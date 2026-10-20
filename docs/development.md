# Development

Build, test and change the relay, the engines and the web viewer.

## Quick path

```sh
cargo build --bins                       # relay, demo sharer, watch viewer
cargo test --workspace                   # protocol, relay, engines, end to end
(cd viewer && pnpm install && pnpm test) # TypeScript vs Rust vectors, browser client e2e (needs the bins)
```

Requirements: Rust ≥ 1.92 (workspace `rust-version`, the Docker toolchain), Node 22 and pnpm 10.

## Run locally

```sh
(cd viewer && pnpm build)
RELAY_TOKENS=local-token-0123456789 RELAY_LISTEN=127.0.0.1:8080 \
VIEWER_LISTEN=127.0.0.1:8081 VIEWER_DIR=viewer/dist RELAY_PUBLIC_URL=ws://127.0.0.1:8080 \
  ./target/debug/plexusterm-relay
```

With a `ws://` relay the page hides **Open in PlexusTerm** (deep links need `wss://`).

## Tools

| Binary | What it does |
| --- | --- |
| `plexusterm-relay` | the relay; `--healthcheck` probes a running one |
| `plexusterm-share-demo` | shares a command in a PTY: `PLEXUSTERM_RELAY_TOKEN=… plexusterm-share-demo --relay wss://… --viewer-origin https://… [--access view\|type\|both] [--expires MIN] [--approve ask\|auto] [-- COMMAND]`. Exit: 0 ended, 2 bad args, 3 command failed, 4 refused |
| `plexusterm-share-watch` | watches a share: `PLEXUSTERM_SHARE_LINK='plexusterm://…' plexusterm-share-watch [--relay wss://…]`. Exit: 0 ended, 2 bad link, 4 refused |

Secrets never go on the command line (`/proc/<pid>/cmdline` is readable by other users): the demo reads the token from `PLEXUSTERM_RELAY_TOKEN`, the watcher reads the link from `PLEXUSTERM_SHARE_LINK` or stdin. To pass a token from a file without showing it:

```sh
PLEXUSTERM_RELAY_TOKEN="$(cat ~/.secrets/plexusterm/relay/token)" ./target/debug/plexusterm-share-demo …
```

## Tests

| Suite | Covers |
| --- | --- |
| `crates/protocol` unit tests | derivation, proofs, Noise, frames and replay guard, codecs, links |
| `crates/protocol/tests/vectors.rs` | generates `viewer/test/vectors.json`; fails when it is stale |
| `crates/relay/tests/relay.rs` | every relay rule through real WebSockets: auth, limits, expiry, kick/rotate, sharer resume, timers, backpressure |
| `crates/client/tests/e2e.rs` | engines against the real relay: no plaintext in relayed frames, replay dropped, revocation, reconnection and resume |
| `crates/client/tests/history.rs`, `engine_api.rs`, `viewer_version.rs`, `watch.rs` | resume floor, async snapshots, expiry, pause, program exit, version check, the watch binary end to end |
| `viewer/test/protocol.test.ts` | TypeScript protocol byte for byte against the Rust vectors |
| `viewer/test/e2e.test.ts` | the browser client against the real relay and demo sharer (skipped without `cargo build --bins`) |

Regenerate vectors after a deliberate wire change:

```sh
UPDATE_VECTORS=1 cargo test -p plexusterm-share-protocol --test vectors
```

## Changing the protocol

1. Change `crates/protocol` and [`protocol.md`](protocol.md) together.
2. Mirror it in `viewer/src/protocol/` and regenerate the vectors.
3. Bump `PROTOCOL_VERSION` for incompatible changes; relay, PlexusTerm and the viewer must move together.

## Conventions

| Area | Rule |
| --- | --- |
| Rust | `cargo fmt`, `cargo clippy --all-targets -- -D warnings`; no `unwrap` on runtime paths; secrets redacted in `Debug`; checked arithmetic on external values |
| Tests | test first for behaviour changes; tests go through the public interface; scratch state outside the worktree |
| Commits | Conventional Commits; tests and docs with the change they cover |
| Process | Feature work is tracked in `odd/tasks/` (specs, tasks, log with evidence); risky commits get a native review |
| Language | Code, comments, docs and UI copy in English; the viewer translates its strings (English, Spanish) |

## Image

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg VIEWER_BUILD_HASH=$(git rev-parse --short=12 HEAD) -t plexusterm-relay .
```

The viewer is built once on the build platform; the relay is compiled per target and shipped on `distroless/cc` as a non-root user.
