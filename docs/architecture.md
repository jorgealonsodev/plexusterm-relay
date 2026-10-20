# Architecture

A sharer and each viewer run their own end-to-end encrypted session; the relay in the middle routes opaque bytes by share id and enforces access and limits. This page explains the parts, how a share flows through them, and the main design decisions. The byte-level contract is in [protocol.md](protocol.md).

## Components

```text
┌────────────────────────┐        ┌──────────────────────────────┐        ┌──────────────────────┐
│ Sharing PlexusTerm     │        │ plexusterm-relay container    │        │ Viewer               │
│  SharerEngine          │  wss   │  :8080 relay  (/v1/sharer,   │  wss   │  browser: web viewer │
│  (or share-demo)       │◄──────►│               /v1/viewer)    │◄──────►│  or PlexusTerm:      │
│  PTY / pane output     │        │  :8081 viewer (static page)  │ https  │  ViewerEngine        │
└────────────────────────┘        └──────────────────────────────┘        └──────────────────────┘
                 TLS is terminated by the reverse proxy in front of the container
```

| Path | Crate / package | Role |
| --- | --- | --- |
| `crates/protocol` | `plexusterm-share-protocol` | Key derivation, proofs, Noise handshake, encrypted frames, frame plaintext, relay messages, links. No IO |
| `crates/relay` | `plexusterm-relay` (binary) | WebSocket relay and the static viewer server |
| `crates/client` | `plexusterm-share-client` | `SharerEngine`, `ViewerEngine` (sans-IO), `plexusterm-share-demo`, `plexusterm-share-watch` |
| `viewer/` | `plexusterm-share-viewer` | Web viewer: TypeScript port of the protocol and `ViewerEngine`, xterm.js page |

## How a share flows

```text
sharer                         relay                              viewer
  │── create(token, links) ───►│  stores verifiers only             │
  │◄─ ready ───────────────────│                                    │
  │   shows https://view/s/<id>#<secret>  ──── link sent by chat ──►│
  │                            │◄─ join(share, link_id, proof) ─────│  click Join, key from #fragment
  │◄─ join(viewer, ip, ua) ────│── accepted ───────────────────────►│
  │◄════ Noise msg 1 ══════════│◄═══════════════════════════════════│
  │   approve? (toast)         │                                    │  "Waiting for the sharer…"
  │═════ Noise msg 2 ═════════►│════════════════════════════════════►│
  │═════ snapshot, live output (AES-GCM per viewer) ═══════════════►│
  │◄════ input (Can type only) ═════════════════════════════════════│
```

1. **Create.** The sharer generates the share id, one secret per link (View only, Can type) and an owner secret. It registers only *verifiers* (hashes) with the relay, authenticated by a relay token.
2. **Link.** `https://<viewer-origin>/s/<share-id>#<secret>`. The secret lives in the `#fragment`, which browsers never send to a server; the page removes it from the address bar on load.
3. **Join.** The viewer proves it holds a link (HMAC over a fresh relay challenge). The relay never learns the secret.
4. **Handshake.** Viewer and sharer run Noise `NNpsk0` with the link's PSK through the relay. Each viewer gets its own forward-secret keys. The sharer decides whether to approve before answering.
5. **Content.** The sharer sends a snapshot (visible screen first, then history) and then live output, encrypted separately per viewer. Can type viewers send input frames; View only input is dropped by the sharer.
6. **End.** Stop sharing, expiry (≤ 12 h, enforced by the relay), 30 min without viewers, or 5 min without the sharer.

## Reconnection and flow control

| Event | Behaviour |
| --- | --- |
| Viewer drops (phone locks, network change) | Reconnects with back-off 1 s → 30 s and a fresh handshake; resumes from its last output number if the sharer's 1 MB buffer still has it, otherwise gets a fresh snapshot. A known viewer is not asked for approval again |
| Sharer drops | Viewers see "Sharing computer is unreachable — reconnecting…" after 10 s; the sharer resumes with an owner proof; after 5 min the share ends |
| Slow viewer | The relay never drops frames: a viewer whose queue exceeds 2 MB is disconnected and reconnects with a fresh snapshot |
| Heavy output | Per-share rate limit (2 MB/s) slows the sender instead of dropping |

## Design decisions

| Decision | Why |
| --- | --- |
| Relay sees only verifiers and ciphertext | A compromised relay cannot read, replay or inject (PRD §6.1) |
| Per-viewer Noise sessions instead of one shared key | Disconnecting one viewer and rotating its link does not affect the others; forward secrecy |
| Raw Noise split keys with explicit 64-bit sequence numbers | Resume and replay checks need the number in the frame |
| Rotate the link before kicking the viewer | The old secret is dead before the viewer learns it was removed |
| Sans-IO engines | PlexusTerm, the demo, the watch tool and the tests drive the same logic with their own IO |
| One Rust reference, TypeScript mirror, shared vectors | Browser and native ends cannot drift: `cargo test` fails if the vectors are stale |
| Snapshot in two parts (`screen`, then `full`) | Viewers paint at once; history follows |
| Resume floor per client | A viewer can never pull history older than the snapshot it was given (it may contain secrets) |
| Viewer page on its own origin, CSP `connect-src` = relay, SRI | Narrows who can serve code that sees the key (PRD §6.1 browser caveat) |
| State in memory only | Nothing to leak at rest, nothing to migrate; a restart ends live shares |

## Repository map

```text
crates/protocol/src/   b64, keys, noise, frame, content, wire, link
crates/relay/src/      config, hub (registry, limits), share (one actor per share), conn, viewer (static server), main
crates/client/src/     sharer, viewer, snapshot, bin/plexusterm-share-demo, bin/plexusterm-share-watch
viewer/src/            protocol/*, engine, client (WebSocket + reconnect), main (page), strings
deploy/                nginx.conf example
docs/                  this documentation
odd/tasks/             feature log with decisions and evidence
```
