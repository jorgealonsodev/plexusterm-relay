//! Share links: `https://<viewer-origin>/s/<share-id>#<secret>`.
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

#[cfg(test)]
mod tests {
    use super::*;

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
