//! Messages between each party and the relay.
//!
//! Control messages are JSON in WebSocket text messages, tagged by `"t"`.
//! Everything else is a WebSocket binary message carrying an opaque
//! viewer↔sharer payload (a Noise message or an encrypted frame). On the
//! sharer's connection binary messages carry a 4-byte big-endian viewer id
//! prefix ([`encode_routed`]); on a viewer's connection they carry the payload
//! alone.

use serde::{Deserialize, Serialize};

use crate::ProtocolError;
use crate::keys::{Challenge, LinkId, Proof, ShareId, Verifier};

/// A link the relay should accept joins for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkRegistration {
    pub link_id: LinkId,
    pub verifier: Verifier,
}

/// What the relay tells the sharer about a viewer it let through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewerInfo {
    pub viewer: u32,
    pub link_id: LinkId,
    /// Relay-observed client IP.
    pub ip: String,
    /// `User-Agent` header as seen by the relay, truncated.
    pub ua: String,
}

/// Relay → sharer or viewer, first message on every connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub proto: u16,
    pub challenge: Challenge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum SharerToRelay {
    /// Register a new share. `expires_at` is Unix seconds.
    Create {
        proto: u16,
        token: String,
        share_id: ShareId,
        owner_verifier: Verifier,
        links: Vec<LinkRegistration>,
        expires_at: u64,
    },
    /// Re-attach to a live share after a network drop.
    Resume {
        proto: u16,
        token: String,
        share_id: ShareId,
        owner_proof: Proof,
    },
    /// Refuse a pending viewer.
    Deny {
        viewer: u32,
    },
    /// Disconnect a viewer (Disconnect in the viewer list).
    Kick {
        viewer: u32,
    },
    /// Replace a link's verifier; joins with the old secret fail from now on.
    Rotate {
        link_id: LinkId,
        new: LinkRegistration,
    },
    /// Move the share's end time (Unix seconds).
    SetExpiry {
        expires_at: u64,
    },
    /// Stop sharing.
    End,
    Ping,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum RelayToSharer {
    Hello(Hello),
    /// The share is live. `viewers` lists viewers still connected after a
    /// resume.
    Ready {
        expires_at: u64,
        viewers: Vec<ViewerInfo>,
    },
    /// A viewer proved a link and its binary messages follow.
    Join(ViewerInfo),
    Left {
        viewer: u32,
        reason: LeftReason,
    },
    Expiry {
        expires_at: u64,
    },
    Pong,
    Ended {
        reason: EndReason,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ViewerToRelay {
    Join {
        proto: u16,
        share_id: ShareId,
        link_id: LinkId,
        proof: Proof,
    },
    Ping,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum RelayToViewer {
    Hello(Hello),
    /// Proof accepted; the viewer may send its Noise message 1.
    Accepted {
        viewer: u32,
        expires_at: u64,
    },
    /// No sharer connection for 10 s.
    SharerAway,
    SharerBack,
    Expiry {
        expires_at: u64,
    },
    Denied,
    Kicked,
    Pong,
    Ended {
        reason: EndReason,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    /// The sharer stopped sharing.
    Stopped,
    /// `expires_at` passed.
    Expired,
    /// No sharer for 5 minutes.
    Offline,
    /// No viewers for 30 minutes.
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeftReason {
    Closed,
    Kicked,
    Denied,
    /// Its queue went over the limit; it reconnects with a fresh snapshot.
    Slow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Unknown, expired or stopped share; the same answer for all three.
    NotFound,
    /// Proof did not match any link of the share.
    BadKey,
    /// Viewer limit reached.
    Full,
    RateLimited,
    /// Protocol version not supported by the relay.
    Version,
    TooLarge,
    /// Relay token missing or wrong.
    Unauthorized,
    /// Share id already registered and the owner proof did not match.
    Conflict,
    /// Concurrent shares per token reached.
    TooManyShares,
    BadRequest,
}

/// Prefix a sharer-side binary message with its viewer id.
pub fn encode_routed(viewer: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&viewer.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn decode_routed(message: &[u8]) -> Result<(u32, &[u8]), ProtocolError> {
    if message.len() < 4 {
        return Err(ProtocolError::Malformed);
    }
    let (id, payload) = message.split_at(4);
    let mut b = [0u8; 4];
    b.copy_from_slice(id);
    Ok((u32::from_be_bytes(b), payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_messages_have_documented_json() {
        let m = ViewerToRelay::Join {
            proto: 1,
            share_id: ShareId([0; 16]),
            link_id: LinkId([1; 16]),
            proof: Proof([2; 32]),
        };
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(
            json,
            r#"{"t":"join","proto":1,"share_id":"AAAAAAAAAAAAAAAAAAAAAA","link_id":"AQEBAQEBAQEBAQEBAQEBAQ","proof":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"}"#
        );
        assert_eq!(serde_json::from_str::<ViewerToRelay>(&json).unwrap(), m);

        let hello = RelayToViewer::Hello(Hello {
            proto: 1,
            challenge: Challenge([0; 32]),
        });
        assert_eq!(
            serde_json::to_string(&hello).unwrap(),
            r#"{"t":"hello","proto":1,"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#
        );
        let err = RelayToViewer::Error {
            code: ErrorCode::NotFound,
            message: "x".into(),
        };
        assert_eq!(
            serde_json::to_string(&err).unwrap(),
            r#"{"t":"error","code":"not_found","message":"x"}"#
        );
        assert_eq!(
            serde_json::to_string(&SharerToRelay::SetExpiry { expires_at: 5 }).unwrap(),
            r#"{"t":"set_expiry","expires_at":5}"#
        );
    }

    #[test]
    fn unknown_tags_are_rejected() {
        assert!(serde_json::from_str::<SharerToRelay>(r#"{"t":"nope"}"#).is_err());
    }

    #[test]
    fn routed_prefix_round_trips() {
        let m = encode_routed(0x0102_0304, b"abc");
        assert_eq!(&m[..4], &[1, 2, 3, 4]);
        assert_eq!(decode_routed(&m), Ok((0x0102_0304, &b"abc"[..])));
        assert_eq!(decode_routed(&[1, 2]), Err(ProtocolError::Malformed));
    }
}
