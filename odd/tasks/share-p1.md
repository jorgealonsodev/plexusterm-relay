# share-p1 — Relay and web viewer (PRD-share P1)

Objective: deliver PRD-share phase P1 in this repository. Branch: `feat/share-p1`. Delivery: `ask-on-risk`, chain strategy `stacked-to-main` (one PR per task slice).
Test runners: `cargo test --workspace` (Rust), `npm test` in `viewer/` (vitest). Source PRD: `docs/PRD-share.md`.

## Specs

S1. Phase P1 scope (PRD §7): "Relay container (arm64, amd64), static viewer, handshake and frame encryption, relay token and limits, reconnection and backpressure, compose file for Portainer". Done when: "A test page streams a terminal end to end; the frame-inspection and replay tests pass (section 8)".

S2. Relay (PRD §5.1): "a small service (one container, a few MB of memory) that matches a share id to its viewers and forwards frames. It never holds keys and never sees content. State is in memory only (share id → sharer connection, viewer connections, limits, expiry); nothing is persisted. Built for arm64 and amd64."

S3. Links and auth (PRD §5.2): "Share ids are 128-bit random, never reused; secrets are 256-bit random. The View only and Can type links carry different secrets". "HKDF-SHA-256 derives from each secret a handshake key and `relay_auth`. The relay stores only a hash of `relay_auth` and asks each viewer to prove it (HMAC challenge), so knowing the id alone does not let anyone attach or spend bandwidth."

S4. Handshake (PRD §5.2): "Each joining viewer runs a Noise `NNpsk0` handshake (X25519) with the sharing side, using the handshake key as PSK. This gives **per-viewer session keys** with forward secrecy, one per direction. The sharing side encrypts output separately for each viewer (at most 10)".

S5. Frames (PRD §5.2): "Every frame is AES-256-GCM (Web Crypto in the browser). The additional data binds share id, viewer id, direction and a 64-bit sequence number; receivers drop any frame whose number is not strictly greater than the last one." "The sharing side drops input from View only viewers and any input it cannot authenticate."

S6. Revocation and expiry at the relay (PRD §5.2): "**Disconnect** drops that viewer's session keys and rotates the secret of the link it used: viewers still connected are unaffected (their keys do not depend on the link), the removed viewer cannot rejoin". "The relay receives `expires_at` when the share is created and closes the share id itself at that time, even if the sharing side is gone." PRD §4.1: "every option ends after 12 h at most"; "A share with no viewers for 30 min ends on its own."

S7. Reconnection and flow control (PRD §5.4): "Sharer and viewers send pings every 20 s"; viewer "reconnects with back-off (1 s → 30 s) while the share is live, with a fresh Noise handshake (no bearer resume tokens). It resumes from its last sequence number if the sharing side's 1 MB buffer still holds it, otherwise it receives a fresh snapshot. While reconnecting it shows "Reconnecting…", sends no input, and does not count as a new viewer." Sharer drop: "after 10 s without the sharer, viewers see "Sharing computer is unreachable — reconnecting…" with typing disabled. The sharer re-registers its share id with an owner secret held per share. After 5 min without it, the relay closes the share and viewers see "The sharing computer went offline. The share has ended."" Backpressure: "The relay never drops individual frames: a viewer whose queue exceeds 2 MB is disconnected and reconnects with a fresh snapshot." Versioning: "the sharer, the relay and viewers exchange a protocol version on join".

S8. Relay access and limits (PRD §5.5): "Creating a share needs a relay token, set as an environment variable of the relay container". "Only one sharer connection per share id; later ones are rejected unless they prove the owner secret." "Defaults (configurable): at most 10 viewers per share, 2 MB/s per share, frames up to 64 KB, 20 join attempts per minute per IP, 50 concurrent shares per token. When a limit is exceeded, the relay refuses the connection with a visible error; it never silently drops data."

S9. Web viewer (PRD §5.1, §4.2): "a static page (xterm.js) served from a separate static origin, pinned to a release hash, with Subresource Integrity, `Content-Security-Policy` limiting `connect-src` to the relay, `Referrer-Policy: no-referrer` and `Cache-Control: no-store`. The build hash is shown in the viewer footer". "The link opens a page that asks for one click (**Join**) before connecting, so chat preview bots never join. The page reads the key from the fragment and removes it from the address bar (`history.replaceState`)." Waiting: "Waiting for the sharer to let you in". Denied: "The sharer declined your request". Ended: "The share has ended". Error strings of PRD §4.4 (browser rows), verbatim.

S10. Retention (PRD §6.2): "the relay keeps no frame buffers beyond in-flight memory and logs no share ids at info level; the shipped reverse-proxy configuration disables access logs for `/s/*`; operational logs hold timestamps, share id hashes and byte counts, with IPs kept 24 h at most."

S11. Deployment (PRD §5.5, §6.2, §5.7): "TLS is terminated by the existing reverse proxy, with WebSocket upgrade and a read timeout over 60 s." Compose file for Portainer, "separate stack on the Oracle Ampere Portainer server"; "runs in a separate stack and network, with no access to the Host's volumes, SSH port or Docker socket."

S12. Tests (PRD §8): "A marker string printed in the terminal never appears in relayed frames"; "A captured input frame re-injected by a test relay is dropped"; "A disconnected viewer's link fails to join; other viewers keep working"; reconnection "Viewer back within 5 s after a 30 s network loss, without a new link" (P1 covers it with a shortened deterministic test; the 8 h soak and latency metrics belong to P4).

S13. User request (L2): "crea un documento que indique a pexusterm lo que tiene que hacer" — `docs/plexusterm-integration.md`, the sharing-side contract for `jorgealonsodev/PlexusTerm`. L3: "segun vallas haciendo el desarrollo, actualizalo si es necesario" — updated with every task that changes the contract.

Assumptions (marked, not user requirements):
- A1. Relay in Rust (axum/tokio); shared Rust crate `plexusterm-share-protocol` so PlexusTerm (Tauri/Rust) reuses the exact wire and crypto code. Viewer in TypeScript + Vite + xterm.js.
- A2. Noise suite `Noise_NNpsk0_25519_AESGCM_SHA256`; frames use the raw split keys with explicit 64-bit sequence numbers.
- A3. The relay serves the viewer from a second listener (separate origin behind the proxy) in the same image.
- A4. Expiry cap is enforced as `expires_at <= now + 12 h` at creation and at each extension.
- A5. A demo sharer CLI (PTY) stands in for PlexusTerm in P1 tests and the end-to-end test page.

## Tasks

| ID | Specs | Route | Status | Commit |
| --- | --- | --- | --- | --- |
| T1 | S3 S4 S5 S13 | inline | done | eecf56c |
| T2 | S2 S6 S7 S8 S10 S13 | inline | done | 4b42bda |
| T3 | S1 S5 S7 S12 S13 | inline | done | 1076a93 |
| T4 | S4 S5 S7 S9 | inline | done | 6393c66 |
| T5 | S9 | inline | done | b828610 |
| T6 | S1 S11 S10 S13 | inline | done | 37ff280 |

- T1 protocol crate: wire messages, HKDF derivation, verifier/HMAC proof, Noise NNpsk0, frame seal/open, replay guard, protocol doc + integration doc v0.
- T2 relay: sharer/viewer WebSocket flows, challenge auth, join forwarding, kick/rotate, expiry, idle end, sharer grace, limits, pings, backpressure, logging policy.
- T3 `plexusterm-share-client`: sans-IO SharerEngine/ViewerEngine, demo sharer (PTY) + end-to-end Rust tests: marker inspection, replay, revocation, reconnection/resume.
- T4 viewer client library (TS): Noise, frames, protocol, reconnection; cross-language vectors from Rust.
- T5 viewer UI and static serving: Join page, fragment removal, states, footer hash, SRI build, security headers.
- T6 deployment: multi-arch Dockerfile, compose for Portainer, reverse-proxy example, README.

Route evidence: one coherent design across units, each unit depends on T1's wire contract; no parallel writer reason is claimed yet.

## Log

L1 (2026-10-20): "/mnt/480GB/Proyectos/Personales/20261015_plexusterm/20261015_plexusterm_git/plexusterm-relay/docs/PRD-share.md lleva a cabo este prd con odd"
L1a: scope answer: "P1 en este repo (Recommended)".
L2 (2026-10-20): "crea un documento que indique a pexusterm lo que tiene que hacer"
L3 (2026-10-20): "segun vallas haciendo el desarrollo, actualizalo si es necesario"
L4: Forecast ~4 000 authored lines; delivery strategy needs a chain choice before the second commit.
L5 (2026-10-20): chain strategy answer: "stacked-to-main (Recommended)".
L6: T1 RED: replay test failed with the sequence check disabled ("left: Ok([108, 115, 13])"); GREEN 24 passed; clippy -D warnings and fmt clean. Native review of eecf56c granted (lenses risk, reliability), lineage review-b29c2807e5cbffe6, running.
L7: T2 relay: 8 unit + 19 integration tests green (3 runs stable). RED: join test failed with the HMAC check disabled ("left: String(\"accepted\")"). Decision: sharer sends `rotate` before `kick` so the old secret is dead before the viewer learns it was removed (protocol.md, integration doc updated). IPs are never logged (S10: stricter than 24 h retention).
L8: T3: SharerEngine (reference for PlexusTerm) and ViewerEngine (mirrored by the TS viewer) in crates/client; demo binary plexusterm-share-demo. 12 e2e tests (real relay + sans-IO test relay) cover S12: marker never in relayed frames, replayed input/output frames dropped, kicked viewer refused with bad_key while others keep working, reconnect resumes from buffer without approval (<5 s, shortened deterministic version of the 30 s chaos test), past-buffer reconnect gets a fresh snapshot, sharer resume + Resync. RED: View only drop disabled → downgrade test failed ("left: [Input { viewer: 1, data: [113] }]"). Decision: snapshot gets a `part` byte (screen, then full, back to back) so PRD §5.3 "visible screen first" works; SnapshotSource hook for @xterm/addon-serialize. Smoke: relay + demo binaries; demo exits 0 when the program exits, 4 when the relay refuses the token.
L9: T4: TS protocol (keys, Noise NNpsk0 via Web Crypto + @noble/curves x25519, frames, content), ViewerEngine mirror and ShareClient (pings 20 s, back-off 1 s → 30 s, no input while reconnecting or sharer away). Cross-language vectors generated by crates/protocol/tests/vectors.rs (cargo test fails if viewer/test/vectors.json is stale): TS matches snow byte for byte. vitest 18 passed, including e2e TS viewer ⇄ Rust relay ⇄ Rust demo sharer (cat in a PTY): join, output, typing, reconnect resumes without a new snapshot. RED: replay check disabled → "promise resolved … instead of rejecting". Versions pinned to PlexusTerm's lockfile (xterm 6.0.0, vite 8.3.4, vitest 5.0.4, typescript 6.0.3).
L10: T5: viewer page (Join click before connecting, fragment removed with history.replaceState, PRD §4.2/§4.4 strings verbatim in English plus Spanish, ARIA live status, xterm screen-reader mode, terminal disposed on end) and static serving from the relay on VIEWER_LISTEN with CSP (connect-src = relay origin only; style-src needs 'unsafe-inline' because xterm injects <style>), Referrer-Policy no-referrer, Cache-Control no-store, nosniff; SRI sha384 on the built script and stylesheet (verified with openssl); build hash in footer and /build.txt. Browser check with Playwright (Chromium): link → Join → bash prompt → typed `echo E2E-$((6*7))` → `E2E-42`; no CSP violations; cut fragment → "incomplete" message and fragment removed. Assumption A6: strings not in the PRD ("This viewer is out of date. Reload the page.", "Too many attempts. Try again in a minute.", "The sharer paused viewer input"); kicked viewers see "The share has ended".
L11: T6: multi-stage Dockerfile (viewer built once on the build platform, relay built per target, distroless nonroot), compose.yaml (own network, no volumes or socket, read-only, cap_drop ALL, healthcheck via `plexusterm-relay --healthcheck`), deploy/nginx.conf (two origins, WebSocket upgrade, 120 s read timeout, no access logs for /s/* and relay), README. Evidence: `docker build` OK with rust:1.92 (MSRV set to 1.92, verified by that build), image 41.3 MB, container RSS 1.96 MiB, /healthz ok, viewer page carries RELAY_PUBLIC_URL; `docker compose config` OK and refuses missing RELAY_TOKENS/RELAY_PUBLIC_URL; `nginx -t` OK with temporary certificates; healthcheck exits 0 up / 1 down. arm64 build not run locally (no QEMU run in this session).
L12: Native review of eecf56c (T1): granted, lenses risk + reliability, approved and acknowledged (authority burned). Assessment of eecf56c..37ff280: high, review due (8 607 lines) → per-commit reviews T2…T6 next, each with its own consent. Independent verifier (Risk item 2, security) launched over the whole feature with baseline 12bf43e.
L13: Independent verifier: S1, S3–S12 PASS; S2 PARTIAL (no arm64 build run); S13 FAIL → blocker B1: SharerEngine honored any viewer-supplied `resume_from`/`Resync{Some(n)}` and replayed up to 1 MB of raw history, bypassing the sharer's history choice; the integration doc prescribed it. Correction (one batch): per-client floor = covers_seq of the last snapshot sent; resume/resync below it (or before any snapshot) gets a fresh snapshot. RED: crates/client/tests/history.rs failed (`hunter2` delivered for resume_from=0 and Resync{Some(0)}); GREEN 3/3, existing e2e unchanged. Doc fixed. Advisories recorded, not fixed: ClientId acts as resume credential; other viewers of a rotated link cannot reconnect; resume accepts any valid token (owner proof still required); no total snapshot reassembly cap in viewers; >128 KiB messages get a bare close; no SIGTERM handler (docker stop waits 10 s); no byte cap on the relay→sharer queue; 2 MB/s throttles without visible error; Pause viewer input not in engine (P2).
