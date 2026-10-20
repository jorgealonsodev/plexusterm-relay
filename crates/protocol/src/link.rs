//! Share links: `https://<viewer-origin>/s/<share-id>#<secret>`, and deep
//! links that open a share in PlexusTerm:
//! `plexusterm://s/<relay-host>/<share-id>#<secret>`.
//!
//! Browsers never send the fragment to a server, so the secret stays with
//! whoever holds the link.

use crate::ProtocolError;
use crate::keys::{Secret, ShareId};

pub fn share_url(viewer_origin: &str, share_id: &ShareId, secret: &Secret) -> String {
    format!(
        "{}/s/{}#{}",
        viewer_origin.trim_end_matches('/'),
        share_id.to_b64(),
        secret.to_b64()
    )
}

/// A parsed link. `secret` is `None` when the fragment was cut off, which
/// the viewer reports as an incomplete link rather than a wrong one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLink {
    pub origin: String,
    pub share_id: ShareId,
    pub secret: Option<Secret>,
}

pub fn parse_share_url(url: &str) -> Result<ParsedLink, ProtocolError> {
    let (before, fragment) = match url.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (url, None),
    };
    let (origin, id) = before.rsplit_once("/s/").ok_or(ProtocolError::Malformed)?;
    if !(origin.starts_with("https://") || origin.starts_with("http://")) {
        return Err(ProtocolError::Malformed);
    }
    let share_id = ShareId::from_b64(id.trim_end_matches('/'))?;
    let secret = match fragment {
        None | Some("") => None,
        Some(f) => Some(Secret::from_b64(f)?),
    };
    Ok(ParsedLink {
        origin: origin.to_owned(),
        share_id,
        secret,
    })
}

/// `plexusterm://s/<relay-host>/<share-id>#<secret>`: opens a share in
/// PlexusTerm instead of the browser (PRD §4.2.4). `relay-host` is the
/// `host[:port]` of the relay's `wss://` URL; the secret stays in the
/// fragment, as in a share link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeepLink {
    pub relay_host: String,
    pub share_id: ShareId,
    /// `None` when the fragment was cut off.
    pub secret: Option<Secret>,
}

impl DeepLink {
    /// The relay to connect to (always TLS).
    pub fn relay_url(&self) -> String {
        format!("wss://{}", self.relay_host)
    }
}

/// Builds the deep link for a share on the relay at `relay_url`
/// (`wss://host[:port]`).
pub fn deep_link(
    relay_url: &str,
    share_id: &ShareId,
    secret: &Secret,
) -> Result<String, ProtocolError> {
    let host = relay_url
        .strip_prefix("wss://")
        .map(|h| h.trim_end_matches('/'))
        .filter(|h| valid_host(h))
        .ok_or(ProtocolError::Malformed)?;
    Ok(format!(
        "{DEEP_LINK_PREFIX}{host}/{}#{}",
        share_id.to_b64(),
        secret.to_b64()
    ))
}

pub fn parse_deep_link(link: &str) -> Result<DeepLink, ProtocolError> {
    let rest = link
        .strip_prefix(DEEP_LINK_PREFIX)
        .ok_or(ProtocolError::Malformed)?;
    let (path, fragment) = match rest.split_once('#') {
        Some((p, f)) => (p, Some(f)),
        None => (rest, None),
    };
    let (host, id) = path.split_once('/').ok_or(ProtocolError::Malformed)?;
    if !valid_host(host) {
        return Err(ProtocolError::Malformed);
    }
    let share_id = ShareId::from_b64(id)?;
    let secret = match fragment {
        None | Some("") => None,
        Some(f) => Some(Secret::from_b64(f)?),
    };
    Ok(DeepLink {
        relay_host: host.to_owned(),
        share_id,
        secret,
    })
}

const DEEP_LINK_PREFIX: &str = "plexusterm://s/";

/// `host[:port]`: letters, digits, dots, dashes, an optional port and IPv6
/// brackets. Rejects paths, spaces and anything a confirmation prompt
/// could misrepresent.
fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_link_round_trips_with_the_relay_host() {
        let id = ShareId([3; 16]);
        let secret = Secret([4; 32]);
        let link = deep_link("wss://relay.example.com:8443/", &id, &secret).unwrap();
        assert_eq!(
            link,
            "plexusterm://s/relay.example.com:8443/AwMDAwMDAwMDAwMDAwMDAw#BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ"
        );
        let parsed = parse_deep_link(&link).unwrap();
        assert_eq!(parsed.relay_host, "relay.example.com:8443");
        assert_eq!(parsed.relay_url(), "wss://relay.example.com:8443");
        assert_eq!(parsed.share_id, id);
        assert_eq!(parsed.secret, Some(secret));
    }

    #[test]
    fn deep_link_needs_a_tls_relay_and_a_plain_host() {
        let (id, secret) = (ShareId([3; 16]), Secret([4; 32]));
        assert_eq!(
            deep_link("ws://relay.example.com", &id, &secret),
            Err(ProtocolError::Malformed)
        );
        assert_eq!(
            deep_link("wss://relay.example.com/path", &id, &secret),
            Err(ProtocolError::Malformed)
        );
        let cut =
            parse_deep_link("plexusterm://s/relay.example.com/AwMDAwMDAwMDAwMDAwMDAw").unwrap();
        assert_eq!(cut.secret, None);
        for bad in [
            "https://relay.example.com/s/AwMDAwMDAwMDAwMDAwMDAw#x",
            "plexusterm://s//AwMDAwMDAwMDAwMDAwMDAw",
            "plexusterm://s/evil.example/x/AwMDAwMDAwMDAwMDAwMDAw",
            "plexusterm://s/a b/AwMDAwMDAwMDAwMDAwMDAw",
            "plexusterm://s/relay.example.com/short",
        ] {
            assert_eq!(parse_deep_link(bad), Err(ProtocolError::Malformed), "{bad}");
        }
    }

    #[test]
    fn builds_and_parses_a_link() {
        let id = ShareId([3; 16]);
        let secret = Secret([4; 32]);
        let url = share_url("https://view.example.org/", &id, &secret);
        assert_eq!(
            url,
            "https://view.example.org/s/AwMDAwMDAwMDAwMDAwMDAw#BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ"
        );
        let parsed = parse_share_url(&url).unwrap();
        assert_eq!(parsed.origin, "https://view.example.org");
        assert_eq!(parsed.share_id, id);
        assert_eq!(parsed.secret, Some(secret));
    }

    #[test]
    fn missing_fragment_is_incomplete_not_malformed() {
        let parsed = parse_share_url("https://v.example/s/AwMDAwMDAwMDAwMDAwMDAw").unwrap();
        assert_eq!(parsed.secret, None);
        let cut = parse_share_url("https://v.example/s/AwMDAwMDAwMDAwMDAwMDAw#").unwrap();
        assert_eq!(cut.secret, None);
        assert_eq!(
            parse_share_url("https://v.example/s/AwMDAwMDAwMDAwMDAwMDAw#BAQE"),
            Err(ProtocolError::Malformed)
        );
        assert_eq!(
            parse_share_url("ftp://x/s/a"),
            Err(ProtocolError::Malformed)
        );
    }
}
