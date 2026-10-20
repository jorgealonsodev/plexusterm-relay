// Deep link that opens a share in PlexusTerm (PRD-share §4.2.4); mirrors
// crates/protocol/src/link.rs. The secret stays in the fragment.

const HOST = /^[A-Za-z0-9.\-:[\]]+$/;

/** `plexusterm://s/<relay-host>/<share-id>#<secret>`, or `null` when the
 * relay is not a plain `wss://host[:port]` URL. */
export function deepLink(relayUrl: string, shareId: string, secret: string): string | null {
  if (!relayUrl.startsWith("wss://")) return null;
  const host = relayUrl.slice("wss://".length).replace(/\/+$/, "");
  if (!HOST.test(host)) return null;
  return `plexusterm://s/${host}/${shareId}#${secret}`;
}
