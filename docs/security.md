# Security

Terminal content is end-to-end encrypted between the sharing computer and each viewer; the relay can route, delay or drop frames but cannot read, replay or inject them. Sharing a terminal with **Can type** still gives the viewer a shell on your computer, so access is opt-in, approved, revocable and time-limited.

## What is protected

| Asset | Protection |
| --- | --- |
| Terminal output and typed input | AES-256-GCM per viewer and direction; keys from a per-viewer Noise `NNpsk0` handshake (X25519) with forward secrecy |
| The link secret | Only in the URL `#fragment` (never sent to a server); the page removes it from the address bar on load; the relay stores only `SHA-256` verifiers |
| Who may join | HMAC proof over a fresh relay challenge; the sharer approves each join (Can type always, View only by default) |
| Typing | Only through a Can type link; the sharer drops View only, forged, replayed and reordered input; downgrading to View only applies at once, also to pending joins |
| History | A joiner gets the history the sharer chose; a reconnecting viewer can resume only from output it was already given |
| Removed viewers | Disconnect rotates the link (old secret dead) and then kicks; the client is banned for the share |
| Duration | Expiry at most 12 h, enforced by the relay even without the sharer; 30 min without viewers ends the share |
| The relay | Relay tokens to create shares; per-IP join limits; message, viewer, rate and queue limits; no state on disk |

## Trust

| Party | Can | Cannot |
| --- | --- | --- |
| Someone with a leaked link | Ask to join | Join without approval; join after Disconnect rotated the link, or after expiry |
| The relay or reverse proxy (compromised) | See timing and sizes of frames, drop or delay them, refuse service | Read content, replay or inject frames, join (it lacks the PSK) |
| **The viewer page's server** | Serve modified JavaScript that reads the key from the page | — this is the browser caveat (PRD §6.1) |
| A hostile Can type viewer | Type anything you could; use your cached `sudo`, `ssh-agent`, `gh auth` | Keep access after Disconnect or expiry |

**Browser caveat.** A browser viewer runs code fetched from the viewer origin. The page is served from its own origin with Subresource Integrity, a CSP that only allows connections to the relay, `Referrer-Policy: no-referrer` and `Cache-Control: no-store`, and shows its build hash — which narrows the trust but does not remove it. PlexusTerm as a viewer (`plexusterm://` links) is the fully end-to-end path. If the viewer host is proxied by a CDN (e.g. Cloudflare orange cloud), the CDN joins this trust.

Out of scope: a compromised operating system on the sharing or viewing device.

## Operator checklist

- [ ] TLS on both names; the relay's host ports closed in the firewall.
- [ ] One relay token per device or person; tokens only in the stack configuration and PlexusTerm's keychain.
- [ ] Access logs off for the relay and for `/s/*` on the viewer (share ids are in that path).
- [ ] No HTML/JS rewriting on the viewer host.
- [ ] The relay stack shares no network, volume or socket with other stacks.

## Sharer checklist

- [ ] Prefer **View only**; give **Can type** only to people you would hand your keyboard.
- [ ] Choose the smallest useful history: earlier output may contain secrets.
- [ ] Keep `sudo -k` at share start enabled.
- [ ] Check every join request before allowing it.

## Known limitations

| Limitation | Notes |
| --- | --- |
| Behind a CDN proxy the relay sees the CDN's IPs | Per-IP join limits and the IP shown to the sharer then refer to the CDN; `CF-Connecting-IP` is not read yet. DNS-only records avoid this |
| A known client reconnecting through the same link skips approval | Holding a client id requires the link's PSK; still, it acts as a resume credential |
| After a link rotation, other viewers of that link cannot reconnect with the old link | They stay connected until they drop |
| Password-prompt detection (PlexusTerm) is best effort | Not a security boundary |
| No SIGTERM handler | `docker stop` waits 10 s, then kills; live shares end either way |
| The relay→sharer queue has no byte cap | A stalled sharer socket is bounded by the per-share rate limit and the 60 s idle timeout |

Report security issues privately to the repository owner rather than in a public issue.
