#!/usr/bin/env python3
import ipaddress
import json
import os
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
PORT = int(os.getenv("LISTEN_PORT", "8080"))
SECURITY_GROUP_IDS = [s.strip() for s in os.environ["SECURITY_GROUP_ID"].split(",") if s.strip()]
if not SECURITY_GROUP_IDS:
    raise RuntimeError("SECURITY_GROUP_ID must list at least one security group")
# URL token: the group IDs rejoined without whitespace, so formatting the env
# var with "id1, id2" doesn't force a literal space into the URL.
URL_TOKEN = ",".join(SECURITY_GROUP_IDS)
ZONE = os.getenv("SCW_DEFAULT_ZONE", "fr-par-1")
SCW = os.getenv("SCW_BIN", "/usr/bin/scw")
MAX_BODY = 4096

def parse_port_spec(spec):
    """Parse "22,443,8000-8010" into a set of ports."""
    ports = set()
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start, _, end = token.partition("-")
            start, end = int(start), int(end)
        else:
            start = end = int(token)
        if not (1 <= start <= end <= 65535):
            raise RuntimeError(f"invalid port or range in FORBIDDEN_PORTS: {token!r}")
        ports.update(range(start, end + 1))
    return ports

FORBIDDEN_PORTS = parse_port_spec(os.getenv("FORBIDDEN_PORTS", ""))
CREATED_RULES_LOG = os.getenv("CREATED_RULES_LOG", "created_rules.log")

MAX_DAYS = int(os.getenv("MAX_DAYS", "30"))
RULE_EXPIRY_FILE = os.getenv("RULE_EXPIRY_FILE", "rule_expirations.json")
RULE_EXPIRY_INTERVAL = int(os.getenv("RULE_EXPIRY_INTERVAL", "300"))

# Guards rule lookup+create+expiry-bookkeeping so two concurrent requests (or
# a request and the expiry sweep) can't race on the same rule.
UPDATE_LOCK = threading.Lock()

def log(message):
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"{ts} {message}", flush=True)

def run_scw(*args):
    result = subprocess.run(
        [SCW, *args, "-o", "json"],
        capture_output=True, text=True, timeout=20, check=False
    )
    if result.returncode != 0:
        error = result.stderr.strip() or "scw command failed"
        log(f"SCW_ERROR error={error!r}")
        raise RuntimeError(error)
    return json.loads(result.stdout)

def list_rules(sg_id):
    log(f"RULES_LIST sg={sg_id}")
    data = run_scw(
        "instance", "security-group", "list-rules",
        f"security-group-id={sg_id}",
        f"zone={ZONE}",
    )
    return data["rules"] if isinstance(data, dict) else data

def _rule_port(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

def find_rule(rules, family, port):
    for rule in rules:
        if rule.get("direction") != "inbound" or rule.get("protocol") != "TCP":
            continue
        if _rule_port(rule.get("dest_port_from")) != port or _rule_port(rule.get("dest_port_to")) != port:
            continue
        ip_range = rule.get("ip_range")
        if not ip_range:
            continue
        try:
            if ipaddress.ip_network(ip_range, strict=False).version != family:
                continue
        except ValueError:
            continue
        return rule
    return None

def record_created_rule(sg_id, rule_id, family, port, cidr):
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    line = f"{ts} rule={rule_id} family=IPv{family} port={port} cidr={cidr} sg={sg_id}\n"
    with open(CREATED_RULES_LOG, "a", encoding="utf-8") as f:
        f.write(line)

def create_rule(sg_id, family, port, cidr):
    log(f"RULE_CREATE_START sg={sg_id} family={family} port={port} new={cidr!r}")
    data = run_scw(
        "instance", "security-group", "create-rule",
        f"security-group-id={sg_id}",
        "protocol=TCP", "direction=inbound", "action=accept",
        f"ip-range={cidr}", f"dest-port-from={port}", f"dest-port-to={port}",
        f"zone={ZONE}",
    )
    rule = data.get("rule", data) if isinstance(data, dict) else data
    rule_id = rule.get("id") if isinstance(rule, dict) else None
    log(f"RULE_CREATE_DONE sg={sg_id} family={family} port={port} new={cidr!r} rule={rule_id}")
    record_created_rule(sg_id, rule_id, family, port, cidr)
    return rule_id

def delete_rule(sg_id, rule_id):
    run_scw(
        "instance", "security-group", "delete-rule",
        f"security-group-id={sg_id}",
        f"security-group-rule-id={rule_id}",
        f"zone={ZONE}",
    )

def load_expirations():
    try:
        with open(RULE_EXPIRY_FILE, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_expirations(data):
    tmp = f"{RULE_EXPIRY_FILE}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, RULE_EXPIRY_FILE)

def set_expiry(sg_id, rule_id, family, port, days):
    expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec="seconds")
    data = load_expirations()
    data[rule_id] = {"expires_at": expires_at, "sg": sg_id, "family": family, "port": port}
    save_expirations(data)
    log(f"RULE_EXPIRY_SET sg={sg_id} rule={rule_id} family={family} port={port} expires_at={expires_at}")

def sweep_expired():
    now = datetime.now(timezone.utc)
    with UPDATE_LOCK:
        data = load_expirations()
        remaining = {}
        for rule_id, info in data.items():
            try:
                expires_at = datetime.fromisoformat(info["expires_at"])
                sg_id = info["sg"]
            except (KeyError, ValueError):
                continue
            if expires_at > now:
                remaining[rule_id] = info
                continue
            try:
                delete_rule(sg_id, rule_id)
                log(f"RULE_EXPIRE_DONE sg={sg_id} rule={rule_id} family={info.get('family')} port={info.get('port')}")
            except Exception as exc:
                log(f"RULE_EXPIRE_FAILED sg={sg_id} rule={rule_id} error={exc!r}")
                remaining[rule_id] = info  # retry on the next sweep
        if remaining != data:
            save_expirations(remaining)

def expire_loop():
    while True:
        time.sleep(RULE_EXPIRY_INTERVAL)
        try:
            sweep_expired()
        except Exception as exc:
            log(f"RULE_EXPIRE_SWEEP_FAILED error={exc!r}")

def update_rule(sg_id, rule_id, family, port, old_cidr, new_cidr):
    log(f"RULE_UPDATE_START sg={sg_id} family={family} port={port} rule={rule_id} old={old_cidr!r} new={new_cidr!r}")
    run_scw(
        "instance", "security-group", "update-rule",
        f"security-group-id={sg_id}",
        f"security-group-rule-id={rule_id}",
        f"ip-range={new_cidr}",
        f"zone={ZONE}",
    )
    log(f"RULE_UPDATE_DONE sg={sg_id} family={family} port={port} rule={rule_id} old={old_cidr!r} new={new_cidr!r}")

def ensure_rule(sg_id, rules, family, port, desired_cidr, days):
    # Look up before creating so repeat visits update the same rule instead of piling up new ones.
    rule = find_rule(rules, family, port)
    if rule is None:
        rule_id = create_rule(sg_id, family, port, desired_cidr)
        message = f"[{sg_id}] IPv{family} port {port}: nouvelle règle -> {desired_cidr}"
    else:
        rule_id = rule["id"]
        current_cidr = rule.get("ip_range")
        if current_cidr != desired_cidr:
            update_rule(sg_id, rule_id, family, port, current_cidr, desired_cidr)
            message = f"[{sg_id}] IPv{family} port {port}: {current_cidr} -> {desired_cidr}"
        else:
            log(f"RULE_NO_CHANGE sg={sg_id} family={family} port={port} rule={rule_id}")
            message = None
    if days is not None:
        set_expiry(sg_id, rule_id, family, port, days)
        message = (message or f"[{sg_id}] IPv{family} port {port}: inchangé") + f" (expire dans {days}j)"
    return message

def validate_ip(value, version):
    if not isinstance(value, str) or len(value) > 100:
        raise ValueError("invalid IP")
    ip = ipaddress.ip_address(value.strip())
    if ip.version != version:
        raise ValueError("wrong IP family")
    return ip

def validate_port(value):
    if value is None or value == "":
        raise ValueError("port is required")
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError("invalid port")
    if not (1 <= port <= 65535):
        raise ValueError("port out of range")
    if port in FORBIDDEN_PORTS:
        raise ValueError(f"port forbidden: {port}")
    return port

def validate_days(value):
    if value is None or value == "":
        return None
    try:
        days = int(value)
    except (TypeError, ValueError):
        raise ValueError("invalid days")
    if not (1 <= days <= MAX_DAYS):
        raise ValueError(f"days must be between 1 and {MAX_DAYS}")
    return days

# Styling follows Scaleway's Ultraviolet design system (console light/dark
# theme tokens), inlined as CSS variables since the page has no build step.
def page():
    return r"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Scaleway Doorman</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&family=Space+Grotesk:wght@500;600&display=swap">
<style>
:root{
  --bg:#f9f9fa;--surface:#ffffff;--border:#d9dadd;--border-weak:#e9eaeb;
  --text:#3f4250;--text-strong:#222638;--text-weak:#727683;
  --primary:#8c40ef;--primary-text:#641cb3;--primary-bg:#f1eefc;
  --success-text:#22674e;--success-bg:#daf6ec;--success-border:#2c8564;
  --danger-text:#b3144d;--danger-bg:#ffebf2;--danger-border:#e51963;
  --warning-text:#7c5400;--warning-bg:#fff6e6;--warning-border:#7c5400;
  --info-text:#005da3;--info-bg:#e0f2ff;--info-border:#005da3;
  --shadow:0 0 2px 0 #22263829,0 2px 4px 0 #2226381f;
  --font:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --font-heading:"Space Grotesk","Century Gothic",Futura,sans-serif;
  --font-code:"JetBrains Mono",JetBrains,Consolas,Monaco,"Andale Mono",monospace;
}
@media (prefers-color-scheme:dark){:root{
  --bg:#151a2d;--surface:#1b2033;--border:#484b5a;--border-weak:#353948;
  --text:#b8bac0;--text-strong:#ffffff;--text-weak:#7e8291;
  --primary:#8d40ee;--primary-text:#bf96f8;--primary-bg:#2d1c51;
  --success-text:#3cb589;--success-bg:#0e2b21;--success-border:#3cb589;
  --danger-text:#ff72a5;--danger-bg:#4e0921;--danger-border:#ff72a5;
  --warning-text:#ffbf3d;--warning-bg:#3a2a07;--warning-border:#ffbf3d;
  --info-text:#71c2ff;--info-bg:#0b2a45;--info-border:#71c2ff;
  --shadow:0 0 2px 0 #0c0f1a99,0 2px 4px 0 #0c0f1a66;
}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:400 1rem/1.5rem var(--font);-webkit-font-smoothing:antialiased}
main{max-width:640px;margin:0 auto;padding:48px 16px}
header{display:flex;align-items:center;gap:16px;margin-bottom:32px}
.logo{flex:none;width:48px;height:48px;border-radius:.5rem;display:grid;place-items:center;
  background:linear-gradient(151deg,#792dd4 0%,#3d1862 45%,#151a2d 100%);color:#fff}
h1{margin:0;font:500 1.5625rem/2rem var(--font-heading);color:var(--text-strong)}
.subtitle{margin:0;color:var(--text-weak);font-size:.875rem;line-height:1.25rem}
.card{background:var(--surface);border:1px solid var(--border-weak);border-radius:.5rem;box-shadow:var(--shadow);overflow:hidden}
.card h2{margin:0;padding:16px 24px;font:600 1rem/1.5rem var(--font);color:var(--text-strong);border-bottom:1px solid var(--border-weak)}
dl{margin:0;padding:8px 24px}
.row{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:12px 0;border-bottom:1px solid var(--border-weak)}
.row:last-child{border-bottom:0}
dt{color:var(--text-weak);font-size:.875rem}
dd{margin:0;min-width:0;text-align:right;color:var(--text-strong);font:500 .875rem/1.25rem var(--font-code);overflow-wrap:anywhere}
.chips{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:4px}
.chip{display:inline-block;padding:0 8px;border-radius:.25rem;background:var(--primary-bg);color:var(--primary-text);font:500 .75rem/1.5rem var(--font-code)}
.muted{color:var(--text-weak);font-family:var(--font);font-weight:400}
.alert{display:flex;gap:12px;margin-top:24px;padding:16px;border-radius:.5rem;border:1px solid var(--a-border);background:var(--a-bg);color:var(--text)}
.alert .icon{flex:none;width:20px;height:20px;color:var(--a-text);margin-top:2px}
.alert strong{display:block;color:var(--a-text);font-weight:600}
.alert ul{margin:8px 0 0;padding:0;list-style:none;display:grid;gap:4px}
.alert li{font:400 .8125rem/1.25rem var(--font-code);overflow-wrap:anywhere}
.alert p{margin:4px 0 0;font-size:.875rem}
.alert code{font-family:var(--font-code);background:var(--a-bg);padding:0 4px;border-radius:.25rem}
.info{--a-text:var(--info-text);--a-bg:var(--info-bg);--a-border:var(--info-border)}
.success{--a-text:var(--success-text);--a-bg:var(--success-bg);--a-border:var(--success-border)}
.danger{--a-text:var(--danger-text);--a-bg:var(--danger-bg);--a-border:var(--danger-border)}
.warning{--a-text:var(--warning-text);--a-bg:var(--warning-bg);--a-border:var(--warning-border)}
.neutral{--a-text:var(--text-strong);--a-bg:var(--surface);--a-border:var(--border)}
.spin{animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.spin{animation:none}}
footer{margin-top:24px;text-align:center;color:var(--text-weak);font-size:.75rem;line-height:1rem}
@media (max-width:480px){.row{flex-direction:column;align-items:flex-start;gap:4px}dd{text-align:left}.chips{justify-content:flex-start}}
</style>
</head>
<body>
<main>
  <header>
    <div class="logo" aria-hidden="true">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z"/><path d="M9 12l2 2 4-4"/></svg>
    </div>
    <div>
      <h1>Scaleway Doorman</h1>
      <p class="subtitle">Ouvre l'accès des Security Groups à votre IP actuelle</p>
    </div>
  </header>

  <section class="card" aria-labelledby="summary-title">
    <h2 id="summary-title">Récapitulatif</h2>
    <dl>
      <div class="row"><dt>IPv4</dt><dd id="ipv4"><span class="muted">Détection…</span></dd></div>
      <div class="row"><dt>IPv6</dt><dd id="ipv6"><span class="muted">Détection…</span></dd></div>
      <div class="row"><dt>Port TCP</dt><dd id="port"></dd></div>
      <div class="row"><dt>Durée</dt><dd id="days"></dd></div>
      <div class="row"><dt>Security groups</dt><dd><div class="chips" id="sgs"></div></dd></div>
    </dl>
  </section>

  <div id="status" role="status" aria-live="polite"></div>

  <footer>Scaleway Doorman · les IP sont détectées via ipify</footer>
</main>
<script>
(() => {
  const $ = id => document.getElementById(id);
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  const ICONS = {
    info: '<circle cx="12" cy="12" r="9" opacity=".25"/><path d="M21 12a9 9 0 0 0-9-9"/>',
    success: '<circle cx="12" cy="12" r="9"/><path d="M8 12l3 3 5-6"/>',
    neutral: '<circle cx="12" cy="12" r="9"/><path d="M8 12h8"/>',
    warning: '<path d="M12 3l10 18H2L12 3z"/><path d="M12 10v4M12 17.5v.01"/>',
    danger: '<circle cx="12" cy="12" r="9"/><path d="M15 9l-6 6M9 9l6 6"/>',
  };
  const setText = (id, text, muted) => { const n = $(id); n.replaceChildren(muted ? el("span", "muted", text) : document.createTextNode(text)); };

  function alert(kind, title, lines, extra) {
    const box = el("div", "alert " + kind);
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24"); svg.setAttribute("fill", "none"); svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2"); svg.setAttribute("stroke-linecap", "round"); svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("class", "icon" + (kind === "info" ? " spin" : "")); svg.setAttribute("aria-hidden", "true");
    svg.innerHTML = ICONS[kind];
    const body = el("div");
    body.append(el("strong", null, title));
    if (lines && lines.length) { const ul = el("ul"); lines.forEach(l => ul.append(el("li", null, l))); body.append(ul); }
    if (extra) body.append(extra);
    box.append(svg, body);
    $("status").replaceChildren(box);
  }

  const params = new URLSearchParams(location.search);
  const port = params.get("port"), days = params.get("days");
  const path = location.pathname.replace(/\/+$/, "");
  path.slice(1).split(",").filter(Boolean).forEach(sg => $("sgs").append(el("span", "chip", decodeURIComponent(sg))));
  setText("port", port || "manquant", !port);
  setText("days", days ? days + " jour" + (days === "1" ? "" : "s") : "Permanente", !days);

  if (!port) {
    const hint = el("p"); hint.append("Ajoutez ", el("code", null, "?port=3389"), " à l'URL (et éventuellement ", el("code", null, "&days=2"), ").");
    alert("warning", "Port manquant", null, hint);
    setText("ipv4", "—", true); setText("ipv6", "—", true);
    return;
  }

  (async () => {
    try {
      alert("info", "Détection de vos adresses IP…");
      const [a, b] = await Promise.all([
        fetch("https://api4.ipify.org?format=json", { cache: "no-store" }),
        fetch("https://api6.ipify.org?format=json", { cache: "no-store" }),
      ]);
      if (!a.ok || !b.ok) throw new Error("ipify n'a pas répondu correctement");
      const [{ ip: ipv4 }, { ip: ipv6 }] = await Promise.all([a.json(), b.json()]);
      setText("ipv4", ipv4); setText("ipv6", ipv6);

      alert("info", "Mise à jour des Security Groups…");
      const r = await fetch(path + "/update", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ipv4, ipv6, port, days }), cache: "no-store",
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || "Erreur serveur");
      setText("ipv4", d.ipv4); setText("ipv6", d.ipv6); setText("port", String(d.port));
      const [title, ...lines] = d.message.split("\n");
      alert(d.changed || d.days ? "success" : "neutral", title.replace(/\s*:\s*$/, ""), lines);
    } catch (e) {
      alert("danger", "Erreur", null, el("p", null, e.message));
    }
  })();
})();
</script>
</body>
</html>"""

class Handler(BaseHTTPRequestHandler):
    server_version = "scaleway-doorman/1.1"

    def log_message(self, fmt, *args):
        log(f"HTTP client={self.address_string()} {fmt % args}")

    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/")
        if path == f"/{URL_TOKEN}":
            log(f"UPDATE_PAGE_REQUEST sgs={SECURITY_GROUP_IDS}")
            body = page().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_json(404, {"error": "not found"})

    def do_POST(self):
        expected = f"/{URL_TOKEN}/update"
        if urlparse(self.path).path.rstrip("/") != expected:
            self.send_json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_BODY:
            self.send_json(400, {"error": "invalid request body"})
            return
        try:
            payload = json.loads(self.rfile.read(length))
            ipv4 = validate_ip(payload.get("ipv4"), 4)
            ipv6 = validate_ip(payload.get("ipv6"), 6)
            port = validate_port(payload.get("port"))
            days = validate_days(payload.get("days"))
            desired_v4, desired_v6 = f"{ipv4}/32", f"{ipv6}/128"
            log(f"UPDATE_START sgs={SECURITY_GROUP_IDS} port={port} days={days} ipv4={desired_v4!r} ipv6={desired_v6!r}")
            with UPDATE_LOCK:
                changed = []
                for sg_id in SECURITY_GROUP_IDS:
                    rules = list_rules(sg_id)
                    changed += [c for c in (
                        ensure_rule(sg_id, rules, 4, port, desired_v4, days),
                        ensure_rule(sg_id, rules, 6, port, desired_v6, days),
                    ) if c]
            if changed:
                message = "Mise à jour effectuée :\n" + "\n".join(changed)
                log(f"UPDATE_DONE changed={len(changed)} port={port}")
            else:
                message = "Aucune modification : les deux IP sont déjà à jour."
                log(f"UPDATE_DONE changed=0 port={port}")
            self.send_json(200, {"ok": True, "ipv4": desired_v4, "ipv6": desired_v6, "port": port, "days": days,
                                 "changed": bool(changed), "message": message})
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            log(f"UPDATE_INVALID error={str(exc)!r}")
            self.send_json(400, {"ok": False, "error": str(exc)})
        except Exception as exc:
            log(f"UPDATE_FAILED error={str(exc)!r}")
            self.send_json(502, {"ok": False, "error": "Scaleway update failed"})

if __name__ == "__main__":
    log(f"START host={HOST!r} port={PORT} zone={ZONE!r} security_groups={SECURITY_GROUP_IDS!r}")
    log(f"FORBIDDEN_PORTS={sorted(FORBIDDEN_PORTS)!r} created_rules_log={CREATED_RULES_LOG!r}")
    log(f"MAX_DAYS={MAX_DAYS} rule_expiry_file={RULE_EXPIRY_FILE!r} expiry_interval={RULE_EXPIRY_INTERVAL}s")
    threading.Thread(target=expire_loop, daemon=True).start()
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
