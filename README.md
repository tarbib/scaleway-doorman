# Scaleway Dynamic IP Updater

Docker service that gets the browser's public IPv4/IPv6 through ipify and points
a Scaleway Security Group rule at it, for a chosen port.

## Usage

Visit `https://your-domain/<SECURITY_GROUP_ID>` to update the rule for
`DEFAULT_PORT`, or add a port explicitly:

```
https://your-domain/<SECURITY_GROUP_ID>?port=3389
```

This is the "I'm at a friend's house and need in" flow: open the bookmarked
URL (with whichever allowed port you need that day) and the matching
IPv4/IPv6 rule gets repointed at your current IP in a couple seconds. Only
ports listed in `ALLOWED_PORTS` can be requested.

The first time a given port is used, its IPv4 and IPv6 rules are created
(`protocol=TCP`, `direction=inbound`, `action=accept`) and their ID is
appended to `created_rules.log`. Every time after that, the existing rule
is just updated in place -- so revisiting the same port from a new location
never creates a second rule for it.

## Logs

```bash
docker compose logs -f scaleway-ip-updater
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

## Environment variables

| Variable            | Required | Description                                              |
|---------------------|----------|------------------------------------------------------------|
| `SECURITY_GROUP_ID`  | yes      | Target Scaleway security group, also the URL token        |
| `ALLOWED_PORTS`      | yes      | Comma-separated ports/ranges this endpoint may open, e.g. `22,443,8000-8010` |
| `DEFAULT_PORT`       | no       | Port used when no `?port=` is given. Must be in `ALLOWED_PORTS`. Defaults to the lowest allowed port |
| `CREATED_RULES_LOG`  | no       | Path to the created-rules audit file. Defaults to `created_rules.log` |
| `SCW_DEFAULT_ZONE`   | no       | Defaults to `fr-par-1`                                     |
| `LISTEN_HOST`        | no       | Defaults to `0.0.0.0`                                       |
| `LISTEN_PORT`        | no       | Defaults to `8080`                                           |
| `SCW_BIN`            | no       | Defaults to `/usr/bin/scw`                                   |

## Run

```bash
cp .env.example .env
chmod 600 .env
docker compose build
docker compose up -d
```

Put an HTTPS reverse proxy in front of `127.0.0.1:8080` (that's what the
compose file binds to). The image bundles a pinned `scw` CLI release,
verified against its published checksum at build time; bump it with
`docker compose build --build-arg SCW_VERSION=x.y.z`.

## Security

`SECURITY_GROUP_ID` identifies the target group but is not a secret. Protect the
public endpoint with authentication at your reverse proxy if appropriate.
Do not commit `.env`.

Keep `ALLOWED_PORTS` to the ports you actually need reachable from anywhere --
anyone with the URL can repoint the matching rule at their own IP for any
port on that list, so don't add ports (or ranges) you wouldn't want opened to
a stranger who gets hold of the link. Use `created_rules.log` to periodically
review and remove ports you no longer use.
