# plexusterm-relay

Share a live [PlexusTerm](https://github.com/jorgealonsodev/PlexusTerm) tab through a link. This repository holds the self-hosted **relay**, the **web viewer**, and the Rust crates PlexusTerm uses to share. Product requirements: [`docs/PRD-share.md`](docs/PRD-share.md).

```text
 Sharing PlexusTerm ──WebSocket (TLS)──► relay ◄──WebSocket (TLS)── browser or PlexusTerm
   encrypts output per viewer,           forwards opaque           decrypts output,
   decrypts input                        frames by share id        encrypts input
```

The relay never holds keys and never sees terminal content: the key travels in the link's `#fragment`, each viewer runs its own Noise handshake with the sharing side, and every frame is AES-256-GCM bound to its share, viewer, direction and sequence number. State is in memory only.

## Layout

| Path | What |
| --- | --- |
| `crates/protocol` | Wire format and end-to-end crypto (`plexusterm-share-protocol`) |
| `crates/relay` | Relay and static viewer server (`plexusterm-relay` binary) |
| `crates/client` | Sans-IO sharer and viewer engines, and the `plexusterm-share-demo` sharer |
| `viewer/` | Web viewer (TypeScript, xterm.js) |
| `docs/protocol.md` | Wire contract, version 1 |
| `docs/plexusterm-integration.md` | What PlexusTerm must build on the sharing side, and what is ready |
| `deploy/nginx.conf` | Reverse proxy example |

## Try it locally

```sh
cargo build --bins
(cd viewer && pnpm install && pnpm build)

RELAY_TOKENS=local-token-0123456789 RELAY_LISTEN=127.0.0.1:8080 \
VIEWER_LISTEN=127.0.0.1:8081 VIEWER_DIR=viewer/dist RELAY_PUBLIC_URL=ws://127.0.0.1:8080 \
  ./target/debug/plexusterm-relay &

PLEXUSTERM_RELAY_TOKEN=local-token-0123456789 ./target/debug/plexusterm-share-demo \
  --relay ws://127.0.0.1:8080 --viewer-origin http://127.0.0.1:8081 --access both
```

The demo prints a View only and a Can type link, then asks `Allow? [y/N]` on its terminal for each join. Open a link in a browser and press **Join**.

To watch a share from a terminal (the reference for PlexusTerm as a viewer), pass the link through the environment, never as an argument:

```sh
PLEXUSTERM_SHARE_LINK='plexusterm://s/relay.example.com/<id>#<key>' ./target/debug/plexusterm-share-watch
# an https:// link also needs: --relay wss://relay.example.com  (see <viewer-origin>/relay.txt)
```

The web viewer offers **Open in PlexusTerm**, which builds that `plexusterm://` link in the browser.

`plexusterm-share-demo` runs any command in a pseudo-terminal: `-- htop`, `-- claude`. Options: `--access view|type|both`, `--expires MINUTES` (1–720), `--approve ask|auto`, `--size COLSxROWS`. Exit codes: 0 share ended, 2 bad arguments, 3 the command could not start, 4 the relay refused the share.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `RELAY_TOKENS` | required | Comma-separated tokens (16+ characters) that may create shares |
| `RELAY_LISTEN` | `0.0.0.0:8080` | Relay address |
| `RELAY_TRUST_PROXY` | `false` | Take the client IP from `X-Forwarded-For` (only behind the proxy) |
| `RELAY_MAX_VIEWERS` | `10` | Viewers per share |
| `RELAY_BYTES_PER_SEC` | `2097152` | Bytes per second per share, both directions |
| `RELAY_JOINS_PER_MINUTE` | `20` | Join attempts per minute per IP |
| `RELAY_MAX_SHARES_PER_TOKEN` | `50` | Concurrent shares per token |
| `RELAY_VIEWER_QUEUE_BYTES` | `2097152` | A viewer queue over this is disconnected (it reconnects with a fresh snapshot) |
| `VIEWER_LISTEN` | unset | Serve the web viewer on this address (separate origin) |
| `VIEWER_DIR` | `/app/viewer` | Built viewer (`viewer/dist`) |
| `RELAY_PUBLIC_URL` | required with `VIEWER_LISTEN` | Relay URL as browsers see it (`wss://relay.example.com`); the viewer's CSP allows only this |
| `RUST_LOG` | `info` | Log level. Logs carry share id hashes and byte counts, never share ids, IPs or content |

Exit codes: 0 clean shutdown, 2 bad configuration, 3 cannot listen. `plexusterm-relay --healthcheck` exits 0 when the local relay answers.

## Deploy

1. Fill in the variables of [`env.example`](env.example), which says how to generate or obtain each one (a token: `openssl rand -hex 32`). With plain docker compose: `cp env.example .env`, edit it, `docker compose up -d --build`.
2. In Portainer, add a stack from this repository (or paste `docker-compose.yml`) and set the same variables as stack environment variables; `RELAY_TOKENS` and `RELAY_PUBLIC_URL` are required. The stack is separate from any PlexusTerm Host stack: no volumes, no Docker socket, read-only filesystem, no capabilities.
3. Point two names at the reverse proxy, one for the relay and one for the viewer. The container publishes the relay on host port `33154` and the viewer on `60689` (`RELAY_HOST_PORT`, `VIEWER_HOST_PORT`); keep both closed in the firewall, only the proxy reaches them.
   - **Nginx Proxy Manager:** two Proxy Hosts, Forward Hostname = the server's IP, scheme `http`. Relay: port `33154`, **Websockets Support** on, SSL with Let's Encrypt and Force SSL, Advanced: `proxy_read_timeout 120s; proxy_send_timeout 120s; access_log off;`. Viewer: port `60689`, SSL with Let's Encrypt and Force SSL, Advanced: `access_log off;`.
   - **Plain nginx:** [`deploy/nginx.conf`](deploy/nginx.conf) (WebSocket upgrade, read timeout over 60 s, no access logs for `/s/*`).
4. In PlexusTerm, enter the relay URL, the viewer origin and the token.

Multi-arch image: `docker buildx build --platform linux/amd64,linux/arm64 --build-arg VIEWER_BUILD_HASH=$(git rev-parse --short=12 HEAD) -t plexusterm-relay .`. The build hash appears in the viewer footer and at `/build.txt`.

## Tests

```sh
cargo test --workspace            # protocol, relay, engines, end-to-end against the real relay
cargo build --bins && (cd viewer && pnpm test)   # TypeScript vs Rust vectors, browser client e2e
```

`viewer/test/vectors.json` is generated by `crates/protocol/tests/vectors.rs`; `cargo test` fails when it is stale (`UPDATE_VECTORS=1 cargo test -p plexusterm-share-protocol --test vectors` rewrites it).

Minimum Rust version: 1.92 (the Docker build toolchain).
