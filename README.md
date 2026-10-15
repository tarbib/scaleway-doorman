# Scaleway Doorman

Docker service that gets the browser's public IPv4/IPv6 through ipify and points
one or more Scaleway Security Group rules at it, for a chosen port.

## Usage

`?port=` is required on every visit -- there is no default port:

```
https://your-domain/<SECURITY_GROUP_ID>?port=3389
```

This is the "I'm at a friend's house and need in" flow: open the bookmarked
URL for whichever port you need that day and the matching IPv4/IPv6 rule
gets repointed at your current IP in a couple seconds. Any port works
*except* the ones listed in `FORBIDDEN_PORTS`.

`SECURITY_GROUP_ID` can list several groups, comma-separated -- the same
request then updates all of them (same port, same IP, same `days`). The URL
token is just that same list, so with
`SECURITY_GROUP_ID=sg-aaa,sg-bbb` the link is
`https://your-domain/sg-aaa,sg-bbb?port=3389`. See `.env.example` for details.

This only works because one process has exactly one `SCW_DEFAULT_ZONE`, one
set of Scaleway credentials/project, and one `FORBIDDEN_PORTS`/`MAX_DAYS`
policy -- those are process-wide, not per-group. So the groups listed in
`SECURITY_GROUP_ID` must all live in the same zone and be reachable with the
same credentials, and they all get the same port/IP/days/policy applied on
every request; there's no way to target a subset of the list or give one
group different rules than another. Different region, different Scaleway
project, or different policy is **not** supported within one instance --
that needs a second, fully separate deployment (its own `.env`, its own
`docker-compose` service, its own volume, its own URL/path) rather than a
second entry in `SECURITY_GROUP_ID`.

The first time a given port is used, its IPv4 and IPv6 rules are created
(`protocol=TCP`, `direction=inbound`, `action=accept`) and their ID is
appended to `created_rules.log`. Every time after that, the existing rule
is just updated in place -- so revisiting the same port from a new location
never creates a second rule for it.

Add `&days=N` to make the access temporary:

```
https://your-domain/<SECURITY_GROUP_ID>?port=3389&days=2
```

The rule gets deleted automatically once it expires (checked every
`RULE_EXPIRY_INTERVAL` seconds, default every 5 minutes) -- handy for a
one-off visit you don't want to remember to revoke. `days` must be between
1 and `MAX_DAYS`. Without `days`, the rule has no expiry, same as before.
Revisiting the same URL with a new `days` value resets the countdown from
that moment, even if your IP hasn't changed.

## Logs

```bash
docker compose logs -f scaleway-doorman
```

The application logs startup, page access, detected IPs, current/desired rule
values, every rule update, no-change checks, and errors. Scaleway API secrets
are never logged.

Example:

```text
2026-10-03T18:42:13+00:00 UPDATE_START sg=... port=22 ipv4='82.12.34.99/32' ipv6='2a01:.../128'
2026-10-03T18:42:13+00:00 RULES_LIST sg=...
2026-10-03T18:42:13+00:00 RULE_UPDATE_START family=4 port=22 rule=... old='82.12.34.56/32' new='82.12.34.99/32'
2026-10-03T18:42:14+00:00 RULE_UPDATE_DONE family=4 port=22 rule=... old='82.12.34.56/32' new='82.12.34.99/32'
2026-10-03T18:42:14+00:00 RULE_NO_CHANGE family=6 port=22 rule=...
2026-10-03T18:42:14+00:00 UPDATE_DONE changed=1 port=22
```

A temporary rule also logs its expiry being set and, later, its deletion:

```text
2026-10-03T18:42:13+00:00 RULE_EXPIRY_SET rule=... family=4 port=3389 expires_at=2026-10-05T18:42:13+00:00
2026-10-05T18:45:00+00:00 RULE_EXPIRE_DONE rule=... family=4 port=3389
```

### Cleaning up rules

Every rule this app *creates* (first use of a new port) is also appended to
`created_rules.log`, one line per rule:

```text
2026-10-03T18:42:13+00:00 rule=11111111-... family=IPv4 port=3389 cidr=82.12.34.99/32 sg=...
2026-10-03T18:42:13+00:00 rule=22222222-... family=IPv6 port=3389 cidr=2a01:.../128 sg=...
```

That file is the cleanup list: if you stop needing a port, grab its rule IDs
from there and delete them:

```bash
scw instance security-group delete-rule security-group-id=<SECURITY_GROUP_ID> security-group-rule-id=<rule-id>
```

(Rules the app only *updates*, because they already existed, are never
written here -- only ones it created itself.)

This log is only for rules with no expiry. A rule created with `&days=N`
cleans itself up automatically and never needs manual deletion -- its
pending expiry lives in `rule_expirations.json` until the sweep removes it.

## Environment variables

| Variable            | Required | Description                                              |
|---------------------|----------|------------------------------------------------------------|
| `SECURITY_GROUP_ID`  | yes      | Target Scaleway security group(s), comma-separated for several; also the URL token |
| `FORBIDDEN_PORTS`    | no       | Comma-separated ports/ranges this endpoint may never open, e.g. `22,3306,3389`. Empty means no restriction |
| `MAX_DAYS`           | no       | Upper bound accepted for `?days=`. Defaults to `30`        |
| `CREATED_RULES_LOG`  | no       | Path to the created-rules audit file. Defaults to `created_rules.log` |
| `RULE_EXPIRY_FILE`   | no       | Path to the pending-expiry state file. Defaults to `rule_expirations.json` |
| `RULE_EXPIRY_INTERVAL` | no     | Seconds between expiry sweeps. Defaults to `300`            |
| `SCW_DEFAULT_ZONE`   | no       | Defaults to `fr-par-1`                                     |
| `LISTEN_HOST`        | no       | Defaults to `0.0.0.0`                                       |
| `LISTEN_PORT`        | no       | Defaults to `8080`                                           |
| `SCW_BIN`            | no       | Defaults to `/usr/bin/scw`                                   |

## Run

The image is built by GitHub Actions (`.github/workflows/docker.yml`) and
published to `ghcr.io/tarbib/scaleway-doorman` for
`linux/amd64` and `linux/arm64`:

| Tag          | Published on                          |
|--------------|---------------------------------------|
| `latest`     | every push to `main`                  |
| `X.Y.Z`, `X.Y` | pushing a git tag `vX.Y.Z`          |
| `sha-<short>` | every build                          |

On the server you only need `docker-compose.yml` and `.env`:

```bash
cp .env.example .env
chmod 600 .env
docker compose up -d
```

The compose service has no `build:` and uses `pull_policy: always`, so every
`docker compose up -d` pulls the image from GHCR and never builds locally --
that same command also deploys new versions.
To pin a version, set `DOORMAN_IMAGE=ghcr.io/tarbib/scaleway-doorman:1.2.0`
(in the shell or in a `.env` next to the compose file).

If the package is private, log in once on the server with a GitHub token
that has `read:packages`:

```bash
echo "$GITHUB_TOKEN" | docker login ghcr.io -u tarbib --password-stdin
```

Put an HTTPS reverse proxy in front of `127.0.0.1:8080` (that's what the
compose file binds to). The image bundles a pinned `scw` CLI release,
verified against its published checksum at build time; bump `SCW_VERSION`
in the Dockerfile, or build locally with
`docker build --build-arg SCW_VERSION=x.y.z -t ghcr.io/tarbib/scaleway-doorman:latest .`.

## Security

`SECURITY_GROUP_ID` identifies the target group(s) but is not a secret. Protect
the public endpoint with authentication at your reverse proxy if appropriate.
Do not commit `.env`.

`FORBIDDEN_PORTS` is a denylist, not an allowlist: by default every port
1-65535 can be requested, so anyone with the URL can repoint a rule at
their own IP for any port you haven't explicitly blocked. Put the ports you
never want exposed there (SSH, databases, management interfaces, anything
not meant to be reachable from an arbitrary IP). Use `created_rules.log` to
periodically review and remove ports you no longer use.

Prefer `&days=N` for anything you only need temporarily (a friend's-house
visit, a one-off debug session) -- it closes itself back up without you
having to remember.
