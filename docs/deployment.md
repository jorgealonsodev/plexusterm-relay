# Deployment

Run the relay and the web viewer as one container behind your existing TLS reverse proxy, with two DNS names. This guide uses Portainer and Nginx Proxy Manager (NPM); plain `docker compose` and plain nginx work the same way.

## Quick path

1. **DNS:** two names pointing at the server, e.g. `relay-plexusterm.example.com` (relay) and `share-plexusterm.example.com` (viewer).
2. **Token:** `openssl rand -hex 32` — keep it; PlexusTerm needs it.
3. **Stack:** Portainer → Stacks → Add stack → Repository:
   - Repository URL `https://github.com/jorgealonsodev/plexusterm-relay`, reference `refs/heads/main`, compose path `docker-compose.yml`, no authentication (public repository).
   - Environment: `RELAY_TOKENS=<token>`, `RELAY_PUBLIC_URL=wss://relay-plexusterm.example.com`, `VIEWER_BUILD_HASH=<commit>`.
4. **Proxy:** two NPM Proxy Hosts (table below), each with a Let's Encrypt certificate.
5. **Check:** `https://share-plexusterm.example.com/build.txt` returns the commit; the container is `healthy`.

## What runs

| Container port | Host port (default) | Serves | Public name |
| --- | --- | --- | --- |
| 8080 | `33154` (`RELAY_HOST_PORT`) | relay WebSocket `/v1/sharer`, `/v1/viewer`, `/healthz` | `wss://relay-…` |
| 8081 | `60689` (`VIEWER_HOST_PORT`) | viewer page `/s/<id>`, `/build.txt`, `/relay.txt`, `/healthz` | `https://share-…` |

The host ports are published on `HOST_BIND_IP` (default `0.0.0.0`) so a proxy running in its own container can reach them. **Keep both closed in the firewall**: only the proxy reaches them; the internet reaches the proxy on 443. Use `HOST_BIND_IP=127.0.0.1` only when the proxy runs directly on the host.

The stack has no volumes, no Docker socket and its own network; the filesystem is read-only, all capabilities are dropped, memory is capped at 64 MB. Idle memory is about 2 MiB.

## Environment

All variables, with how to obtain each one, are in [`env.example`](../env.example).

| Variable | Required | Value |
| --- | --- | --- |
| `RELAY_TOKENS` | yes | tokens allowed to create shares, comma-separated, 16+ characters: `openssl rand -hex 32` |
| `RELAY_PUBLIC_URL` | yes | the relay as browsers reach it: `wss://relay-…`, no path or trailing slash |
| `VIEWER_BUILD_HASH` | no | commit shown in the viewer footer and `/build.txt` (default `dev`) |
| `RELAY_HOST_PORT`, `VIEWER_HOST_PORT`, `HOST_BIND_IP` | no | `33154`, `60689`, `0.0.0.0` |
| `RELAY_TRUST_PROXY` | no | `1`: client IP from the last `X-Forwarded-For` entry, which the proxy adds (earlier entries can be forged by the client) |
| `RELAY_MAX_VIEWERS`, `RELAY_BYTES_PER_SEC`, `RELAY_JOINS_PER_MINUTE`, `RELAY_MAX_SHARES_PER_TOKEN`, `RELAY_VIEWER_QUEUE_BYTES` | no | PRD defaults: 10, 2 MiB/s, 20, 50, 2 MiB |
| `RUST_LOG` | no | `info` |

Without `RELAY_TOKENS` or `RELAY_PUBLIC_URL` the stack refuses to start.

## Reverse proxy

### Nginx Proxy Manager

| | Relay host | Viewer host |
| --- | --- | --- |
| Domain | `relay-plexusterm.example.com` | `share-plexusterm.example.com` (must differ from the relay) |
| Scheme / Forward host / Port | `http` / server's private IP or Docker gateway / `33154` | `http` / same / `60689` |
| Websockets Support | **on** | off |
| Block Common Exploits | on | on |
| Cache Assets | off | off |
| SSL | Let's Encrypt, Force SSL, HTTP/2 | Let's Encrypt, Force SSL, HTTP/2 |
| Advanced | `proxy_read_timeout 120s; proxy_send_timeout 120s; access_log off;` | `access_log off;` |

**Forward host:** NPM runs in a container, so use the server's private address (e.g. `10.0.0.x` on Oracle Cloud, from `ip -4 addr show`) or the gateway of NPM's Docker network (Portainer → Networks → Gateway, often `172.17.0.1` or `172.18.0.1`). The public IP would go out through the cloud firewall, where these ports are closed.

**Why the timeouts:** NPM closes idle proxied connections after 60 s; the relay pings every 20 s, 120 s leaves room.

### Plain nginx

[`deploy/nginx.conf`](../deploy/nginx.conf): two server blocks with WebSocket upgrade, a 120 s read timeout, `X-Forwarded-For $remote_addr`, and no access logs for the relay and `/s/*`.

## DNS (Cloudflare)

**Recommended: DNS only (grey cloud).** NPM issues certificates with the HTTP challenge, the relay sees real client IPs, and Cloudflare never serves the viewer page or sees share URLs. The warning icon on DNS-only records only means the server IP is visible.

If you proxy (orange cloud):

- SSL/TLS mode **Full (strict)**; "Flexible" loops with Force SSL.
- Issue certificates with NPM's DNS challenge, or before turning the proxy on.
- Turn off Rocket Loader, Email Obfuscation and any HTML/JS rewriting for the viewer host: modified scripts fail Subresource Integrity and CSP.
- Cloudflare then terminates TLS: terminal content stays end-to-end encrypted, but Cloudflare serves the viewer code and sees `/s/<id>` URLs (see [Security](security.md#trust)).
- The relay would see Cloudflare's IPs: per-IP join limits and the IP shown to the sharer need `CF-Connecting-IP`, which the relay does not read yet.

CNAME records pointing to a proxied apex still resolve to the origin when the records themselves are DNS only.

## Firewall

| Port | Open to the internet |
| --- | --- |
| 443/tcp | yes — HTTPS and WSS through the proxy |
| 80/tcp | yes — Let's Encrypt HTTP challenge and redirect to HTTPS |
| 81/tcp (NPM admin) | no — VPN or SSH tunnel only |
| `33154`, `60689` | **no** |

On Oracle Cloud, open 80 and 443 both in the VCN security list (or NSG) and in the instance firewall.

## Plain docker compose

```sh
git clone https://github.com/jorgealonsodev/plexusterm-relay && cd plexusterm-relay
cp env.example .env   # fill in RELAY_TOKENS and RELAY_PUBLIC_URL
docker compose up -d --build
```

## Verify

| Check | Expected |
| --- | --- |
| Portainer → container status | `healthy` (health check: `plexusterm-relay --healthcheck`) |
| `https://share-…/build.txt` | the deployed commit |
| `https://share-…/relay.txt` | `wss://relay-…` |
| `https://relay-…/healthz` | `ok` |
| `curl -sI https://share-…/s/x` | `content-security-policy` with `connect-src wss://relay-…`, `referrer-policy: no-referrer`, `cache-control: no-store` |
| End to end | share with `plexusterm-share-demo` (see [Development](development.md#tools)) and open the link on a phone |

The first deployment builds the image on the server (a few minutes on arm64 or amd64).

## Configure PlexusTerm

Settings → Share:

| Field | Value |
| --- | --- |
| Relay URL | `wss://relay-plexusterm.example.com` |
| Viewer origin | `https://share-plexusterm.example.com` |
| Relay token | one of `RELAY_TOKENS` (stored in the system keychain) |
