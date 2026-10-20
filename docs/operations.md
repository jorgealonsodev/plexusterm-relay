# Operations

Day-to-day running of a deployed relay: health, logs, tokens, upgrades and the problems you are most likely to meet. Deployment itself is in [Deployment](deployment.md).

## Health

| Check | How | Healthy |
| --- | --- | --- |
| Container | Portainer, or `docker ps` | `healthy` — the image runs `plexusterm-relay --healthcheck` every 30 s (exit 0 when `GET /healthz` answers) |
| Relay | `curl https://relay-…/healthz` | `ok` |
| Viewer | `curl https://share-…/build.txt` | the deployed commit |
| Memory | `docker stats` | a few MiB idle; capped at 64 MB by the stack |

## Logs

The relay logs to stderr (`docker logs`, Portainer → Logs). At `RUST_LOG=info` you see:

```text
INFO plexusterm_relay: relay listening addr=0.0.0.0:8080
INFO plexusterm_relay: viewer listening addr=0.0.0.0:8081
INFO plexusterm_relay::share: share created share=2f3b60c2827d
INFO plexusterm_relay::share: share ended share=2f3b60c2827d reason=Stopped bytes_to_viewers=… bytes_to_sharer=…
```

`share=` is a short hash of the share id, never the id itself. Logs never contain IPs, user agents, tokens or terminal content. `RUST_LOG=debug` adds viewer joins and sharer attach/detach (still without ids or IPs). The compose file keeps two 10 MB log files.

End reasons: `Stopped` (sharer ended), `Expired`, `Idle` (30 min without viewers), `Offline` (5 min without the sharer).

## Tokens

Each entry of `RELAY_TOKENS` can create shares; give each device or person its own.

| Task | Steps |
| --- | --- |
| Add | `openssl rand -hex 32`, append it to `RELAY_TOKENS` (comma-separated), redeploy |
| Revoke | remove it from `RELAY_TOKENS`, redeploy |
| Rotate | add the new one, update PlexusTerm, then remove the old one |

A token is checked when a share is created or a sharer reconnects; redeploying ends live shares anyway (below).

## Upgrades

1. Push to `main` (or pick the commit to deploy).
2. Wait for the **image** workflow on GitHub to publish it (about 3 minutes), then Portainer → the stack → **Pull and redeploy** (with `RELAY_IMAGE_TAG=latest`, or set it to the new commit to pin it). The server only downloads the image.
3. Verify `build.txt` and health.

State is in memory only, so **a redeploy or restart ends every live share**: viewers see the share end, and the sharer must start a new one. Deploy when nobody is sharing.

If the wire protocol changes (`PROTOCOL_VERSION`), old PlexusTerm builds are refused with "Update PlexusTerm to open this share"; upgrade the relay and PlexusTerm together.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Portainer: "Unable to retrieve stack file: Could not get the contents of the file 'docker-compose.yml'" | Stack points to a missing branch (e.g. `refs/heads/feat/share-p1`), a wrong compose path, or authentication is on | Reference `refs/heads/main`, compose path `docker-compose.yml`, authentication off (public repository). If the reference cannot be edited, recreate the stack: nothing is lost |
| Stack refuses to start: "required variable RELAY_TOKENS is missing" | Missing environment | Set `RELAY_TOKENS` and `RELAY_PUBLIC_URL` |
| Container exits with code 2 | Bad configuration (token shorter than 16 characters, bad `RELAY_PUBLIC_URL`) | `docker logs` names the variable |
| Viewer page loads, "Can't reach <relay>" | NPM Websockets Support off, wrong forward port, or the relay host not proxied | Relay Proxy Host: Websockets on, port `33154` |
| Viewers drop every ~60 s | Proxy read timeout | `proxy_read_timeout 120s; proxy_send_timeout 120s;` in the relay host |
| NPM 502 Bad Gateway | Forward host is the public IP or `127.0.0.1` from inside the NPM container | Server's private IP or the Docker network gateway |
| Page is blank, console shows integrity or CSP errors | A proxy rewrote the HTML/JS (Cloudflare Rocket Loader, minify, email obfuscation) | Turn those off for the viewer host |
| Share refused with `unauthorized` | Token not in `RELAY_TOKENS` | Check PlexusTerm's token |
| Share refused with `bad_request` on create | Expiry over 12 h by the relay's clock | Keep a margin (PlexusTerm uses 12 h − 60 s) |
| "This share has reached its viewer limit." | 10 viewers | Raise `RELAY_MAX_VIEWERS` if intended |
| Join refused with `rate_limited` | 20 join attempts per minute from one IP | Wait a minute |

## Backup and restore

Nothing to back up: the relay has no state on disk. Keep the tokens (they live in your stack configuration and in PlexusTerm's keychain).
