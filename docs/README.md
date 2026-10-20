# plexusterm-relay documentation

`plexusterm-relay` lets a [PlexusTerm](https://github.com/jorgealonsodev/PlexusTerm) tab be watched and used from another computer, a phone or another person's browser through a link. It contains the self-hosted relay, the web viewer, and the Rust crates PlexusTerm uses on both ends. Terminal content is end-to-end encrypted: the relay only forwards opaque frames.

## Start here

| I want to… | Read |
| --- | --- |
| Understand how it works | [Architecture](architecture.md) |
| Run it on my server | [Deployment](deployment.md) |
| Keep it running, rotate tokens, upgrade, troubleshoot | [Operations](operations.md) |
| Know what is protected and what is not | [Security](security.md) |
| Build, test or change the code | [Development](development.md) |
| Implement or check the wire format | [Protocol](protocol.md) |

## The project in one page

```text
 Sharing PlexusTerm ──wss──► relay ◄──wss── browser (web viewer) or another PlexusTerm
   encrypts per viewer        forwards opaque frames       decrypts, renders, types
```

- **Relay** (`crates/relay`): one small container. Matches share ids to viewers, checks link proofs, enforces limits and expiry, forwards frames. Holds no keys, persists nothing.
- **Web viewer** (`viewer/`): static page served by the same container on a second port and a separate origin. Opens a share with one click; nothing to install.
- **Engines** (`crates/client`): `SharerEngine` and `ViewerEngine`, sans-IO Rust state machines that do the protocol and the crypto. PlexusTerm embeds them.
- **Protocol** (`crates/protocol`): keys, proofs, Noise handshake, frames and messages — the single reference implementation, mirrored by the viewer's TypeScript and pinned by shared test vectors.
- **Tools**: `plexusterm-share-demo` shares any command from a terminal; `plexusterm-share-watch` watches a share from a terminal.

## Status

| Phase (PRD §7) | State |
| --- | --- |
| P1 — relay and web viewer | Done, deployed and verified end to end |
| P2 — share from PlexusTerm | Engine ready (`SharerEngine`); PlexusTerm host to build |
| P3 — PlexusTerm as viewer | This repository's side done; PlexusTerm pane to build |
| P4 — polish | Not started |

Progress, decisions and verification evidence are logged in [`odd/tasks/share-p1.md`](../odd/tasks/share-p1.md).
