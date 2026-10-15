# Scaleway Doorman

Temporarily open a port on your Scaleway servers to the network you're
currently on, just by visiting a URL.

```
https://your-domain/<SECURITY_GROUP_ID>?port=3389&days=2
```

The page detects your public IPv4/IPv6 and points an inbound TCP rule for
that port at it, in every security group listed in `SECURITY_GROUP_ID`.

- `port` (required): the port to open. Ports in `FORBIDDEN_PORTS` are refused.
- `days` (optional, 1 to `MAX_DAYS`): the rule is deleted automatically after
  that many days. Without it, the rule never expires.

Each new IP gets its own new rule; existing rules are never modified.
Revisiting from the same IP reuses its rule (and resets the `days` countdown).

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SCW_ACCESS_KEY`, `SCW_SECRET_KEY` | yes | | Scaleway API credentials, used by the `scw` CLI |
| `SCW_DEFAULT_PROJECT_ID` | yes | | Scaleway project holding the security groups |
| `SCW_DEFAULT_ORGANIZATION_ID` | no | | Only needed on older organization-based accounts |
| `SCW_DEFAULT_ZONE` | no | `fr-par-1` | Zone of the security groups |
| `SECURITY_GROUP_ID` | yes | | Security group(s) to update, comma-separated. Also the URL path token, so keep the URL private |
| `FORBIDDEN_PORTS` | no | empty | Ports/ranges that can never be opened, e.g. `22,3306,5900-5901`. Empty means any port is allowed |
| `MAX_DAYS` | no | `30` | Maximum value accepted for `?days=` |
| `RULE_EXPIRY_INTERVAL` | no | `300` | Seconds between checks for expired rules |
| `CREATED_RULES_LOG` | no | `/data/created_rules.log` | Log of every rule the app created (to clean up permanent rules) |
| `RULE_EXPIRY_FILE` | no | `/data/rule_expirations.json` | Pending expirations; must be on persistent storage |
| `LISTEN_HOST` | no | `0.0.0.0` | HTTP listen address |
| `LISTEN_PORT` | no | `8080` | HTTP listen port |
| `SCW_BIN` | no | `/usr/local/bin/scw` | Path to the `scw` binary |

All listed security groups share the same zone, credentials and policy. A
group in another zone or project needs a separate deployment.

## Run

```bash
cp .env.example .env   # fill it in
chmod 600 .env
docker compose up -d
```

The image `ghcr.io/tarbib/scaleway-doorman` is built by GitHub Actions
(`latest` on `main`, `X.Y.Z` on `vX.Y.Z` tags). `docker compose up -d` always
pulls it; set `DOORMAN_IMAGE` to pin a version. If the package is private:

```bash
echo "$GITHUB_TOKEN" | docker login ghcr.io -u tarbib --password-stdin
```

Put an HTTPS reverse proxy in front of `127.0.0.1:8080`.

Logs: `docker compose logs -f scaleway-doorman` (secrets are never logged).

## Security

- Anyone with the URL can open any port not in `FORBIDDEN_PORTS` to their own
  IP. Block SSH, databases and admin interfaces there, and consider adding
  authentication at the reverse proxy.
- Prefer `&days=N` so access closes on its own.
- Permanent rules are listed in `created_rules.log`; remove unused ones with
  `scw instance security-group delete-rule security-group-id=<sg> security-group-rule-id=<rule>`.
