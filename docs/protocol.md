# PlexusTerm share protocol — version 1

The wire contract between a **sharer** (PlexusTerm, or the demo sharer), the **relay** and **viewers** (the web viewer, later PlexusTerm). The reference implementation is the Rust crate `plexusterm-share-protocol` (`crates/protocol`); the web viewer's TypeScript implementation is tested against vectors generated from it.

The relay sees only what is marked *relay-visible* below. Everything else is end-to-end encrypted between the sharer and one viewer.

## 1. Encoding

- Fixed-size byte strings (ids, secrets, verifiers, proofs, challenges) are **unpadded base64url**.
- Times are Unix seconds (`u64`).
- Integers in binary layouts are big-endian.
- Every WebSocket message is at most **64 KiB**.

## 2. Links and keys

```text
https://<viewer-origin>/s/<share-id>#<secret>
```

| Value | Size | Origin |
| --- | --- | --- |
| `share_id` | 16 bytes | random per share, never reused |
| `secret` | 32 bytes | random per link (one for View only, one for Can type) |
| `owner_secret` | 32 bytes | random per share, never leaves the sharer |

From each secret (link or owner), HKDF-SHA-256 with salt `plexusterm-share v1` and the `info` labels below derives:

| `info` | Length | Use | Relay-visible |
| --- | --- | --- | --- |
| `link id` | 16 | `link_id`, names the link | yes |
| `handshake psk` | 32 | Noise PSK | no |
| `relay auth` | 32 | `relay_auth` | no |

`verifier = SHA-256(relay_auth)` is the only key material the relay stores.

**Proof.** After the relay's `hello` carries a 32-byte `challenge`:

```text
proof = HMAC-SHA-256(key = verifier,
                     "plexusterm-share v1 proof" ‖ role ‖ share_id ‖ challenge)
role  = 0x01 viewer | 0x02 owner
```

## 3. Connections

Two WebSocket endpoints on the relay origin:

| Path | Party |
| --- | --- |
| `/v1/sharer` | one per live share |
| `/v1/viewer` | one per viewer |

Text messages are JSON control messages tagged by `"t"`. Binary messages are opaque viewer↔sharer payloads (section 5). On `/v1/sharer` each binary message starts with the 4-byte viewer id it comes from or goes to; on `/v1/viewer` there is no prefix.

Every connection starts with the relay sending:

```json
{"t":"hello","proto":1,"challenge":"<32 bytes>"}
```

Either side may send `{"t":"ping"}` (answered with `{"t":"pong"}`) and must do so every **20 s**; the relay closes a connection silent for 60 s.

### 3.1 Sharer → relay

| `t` | Fields | Meaning |
| --- | --- | --- |
| `create` | `proto`, `token`, `share_id`, `owner_verifier`, `links: [{link_id, verifier}]`, `expires_at` | register a share |
| `resume` | `proto`, `token`, `share_id`, `owner_proof` | re-attach after a drop |
| `deny` | `viewer` | refuse a pending viewer |
| `kick` | `viewer` | Disconnect a viewer |
| `rotate` | `link_id`, `new: {link_id, verifier}` | replace a link; the old secret stops working. Send it before the `kick` it goes with |
| `set_expiry` | `expires_at` | extend or shorten |
| `end` | — | Stop sharing |

### 3.2 Relay → sharer

| `t` | Fields | Meaning |
| --- | --- | --- |
| `ready` | `expires_at`, `viewers: [ViewerInfo]` | share live (after `create` or `resume`) |
| `join` | `viewer`, `link_id`, `ip`, `ua` | a viewer proved `link_id`; its Noise message 1 follows |
| `left` | `viewer`, `reason`: `closed` \| `kicked` \| `denied` \| `slow` | viewer gone |
| `expiry` | `expires_at` | expiry changed |
| `ended` | `reason`: `stopped` \| `expired` \| `offline` \| `idle` | share closed |
| `error` | `code`, `message` | refusal; the relay closes the connection |

### 3.3 Viewer → relay

| `t` | Fields |
| --- | --- |
| `join` | `proto`, `share_id`, `link_id`, `proof` |

### 3.4 Relay → viewer

| `t` | Fields | Meaning |
| --- | --- | --- |
| `accepted` | `viewer`, `expires_at` | proof valid; send Noise message 1 |
| `sharer_away` | — | no sharer for 10 s; typing disabled |
| `sharer_back` | — | sharer re-attached; viewer sends `Resync` |
| `expiry` | `expires_at` | new end time |
| `denied` | — | the sharer declined |
| `kicked` | — | the sharer disconnected this viewer |
| `ended` | `reason` | share closed |
| `error` | `code`, `message` | refusal; the relay closes the connection |

### 3.5 Error codes

| `code` | When |
| --- | --- |
| `not_found` | share unknown, expired or stopped (one answer for all three) |
| `bad_key` | proof matches no link of the share |
| `full` | viewer limit reached |
| `rate_limited` | too many join attempts from this IP |
| `version` | unsupported `proto` |
| `too_large` | message over 64 KiB |
| `unauthorized` | relay token missing or wrong |
| `conflict` | share id taken and owner proof wrong |
| `too_many_shares` | concurrent shares per token reached |
| `bad_request` | malformed or out-of-order message, expiry out of range |

## 4. Viewer join sequence

```text
viewer                         relay                           sharer
  │◄──── hello{challenge} ───────│                                │
  │───── join{share,link,proof}─►│ check proof against verifier   │
  │◄──── accepted{viewer} ───────│───── join{viewer,link,ip,ua} ─►│
  │═════ Noise msg 1 ═══════════►│═════ [viewer] msg 1 ══════════►│ PSK of link_id
  │                              │                                │ ask sharer: Allow/Deny
  │◄════ Noise msg 2 ════════════│◄════ [viewer] msg 2 ═══════════│ (or deny{viewer})
  │◄════ frames ═════════════════│◄════ [viewer] frames ══════════│
```

The access a viewer gets follows from the PSK it completed the handshake with, not from the `link_id` the relay reported: a relay that lies about `link_id` makes the handshake fail.

## 5. Viewer↔sharer payloads

First byte: `0x01` Noise handshake message, `0x02` encrypted frame.

### 5.1 Handshake

`Noise_NNpsk0_25519_AESGCM_SHA256`, viewer = initiator, PSK = the link's handshake key, prologue = `plexusterm-share v1` ‖ `share_id`.

| Message | Payload (JSON, encrypted by Noise) |
| --- | --- |
| 1 (viewer → sharer) | `{"client":"<16 bytes>","resume_from":<u64, optional>}` |
| 2 (sharer → viewer) | `{"access":"view"\|"type","cols":<u16>,"rows":<u16>}` |

`client` is random per browser tab and survives reconnects, so the sharer does not count a reconnecting viewer as new. Message 2 is sent only after the sharer approves the join.

After message 2 both sides take the raw Noise `Split()` output `(k1, k2)`: `k1` encrypts viewer → sharer, `k2` sharer → viewer.

### 5.2 Frames

```text
0x02 ‖ seq (u64) ‖ AES-256-GCM(key, nonce = 0x00000000 ‖ seq, aad, plaintext)
aad = "PTS1" ‖ share_id (16) ‖ viewer_id (u32) ‖ direction (0 = to viewer, 1 = to sharer) ‖ seq (u64)
```

`seq` starts at 1 per key. A receiver drops a frame whose `seq` is not strictly greater than the last one it accepted, and only an authenticated frame advances that number. Plaintext is at most 32 KiB.

### 5.3 Plaintext

| Type | Layout | Direction |
| --- | --- | --- |
| `0x10` Output | `seq u64 ‖ bytes` | to viewer |
| `0x11` Snapshot | `covers_seq u64 ‖ cols u16 ‖ rows u16 ‖ part u8 ‖ index u16 ‖ count u16 ‖ compressed u8 ‖ bytes` | to viewer |
| `0x12` Status | JSON `{"access"?, "input_paused"?, "program_exited"?}` | to viewer |
| `0x13` Size | `cols u16 ‖ rows u16` | to viewer |
| `0x20` Input | bytes: one complete key event or one bracketed paste | to sharer |
| `0x21` Resync | `present u8 ‖ last_seq u64` | to sharer |

Output `seq` numbers are the share's output sequence, the same for every viewer. A snapshot's `covers_seq` is the last output number it contains; live output continues at `covers_seq + 1`.

A snapshot has one or two **parts**, each split into chunks `index` of `count` that concatenate in order; a chunk with `compressed = 1` is raw DEFLATE on its own.

| `part` | Content | Viewer |
| --- | --- | --- |
| `0` screen | visible screen only; the `full` part with the same `covers_seq` follows | resets and paints it as soon as it is complete |
| `1` full | chosen history and screen | resets and writes it, then applies live output after `covers_seq` |

Sending the screen first lets the viewer paint at once while the history is still on its way (PRD §5.3). The sharer sends the `full` part right after the `screen` part, before any later output. A sharer may send only a `full` part. Snapshot bytes are the terminal snapshot format versioned by PlexusTerm (`@xterm/addon-serialize` output); the relay and the protocol treat them as opaque.

A viewer applies `Output` frames in `seq` order: it skips any `seq` it already applied and, while a snapshot is incomplete, holds live output until the snapshot is written.

## 6. Relay rules

- State is in memory only. Nothing is persisted.
- `expires_at` must be in the future and at most 12 h from the moment it is set; the relay closes the share at that time even without a sharer.
- A share with no viewers for 30 min ends (`idle`).
- Without a sharer connection: viewers get `sharer_away` after 10 s; after 5 min the share ends (`offline`). `resume` with a valid owner proof re-attaches and viewers get `sharer_back`.
- Only one sharer connection per share id.
- Default limits: 10 viewers per share, 2 MB/s per share, 64 KiB per message, 20 join attempts per minute per IP, 50 concurrent shares per token. Over a limit the relay refuses with an `error`; it never drops a frame. A viewer whose outgoing queue exceeds 2 MB is disconnected (`left` with `slow`) and reconnects with a fresh snapshot.
