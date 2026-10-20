//! Per-viewer `Noise_NNpsk0_25519_AESGCM_SHA256` handshake.
//!
//! The viewer is the initiator and the sharing side the responder. The PSK is
//! the joining link's handshake key, so only holders of that link complete
//! the handshake, and a fresh X25519 pair on each side gives every viewer its
//! own forward-secret keys. The prologue binds the share id.
//!
//! After the two messages both sides take the raw Noise split as one AES-256
//! key per direction and use it in [`crate::frame`] with explicit sequence
//! numbers, which reconnection and replay checks need.

use snow::{Builder, HandshakeState};

use crate::ProtocolError;
use crate::frame::KIND_HANDSHAKE;
use crate::keys::ShareId;

pub const NOISE_PARAMS: &str = "Noise_NNpsk0_25519_AESGCM_SHA256";
const PROLOGUE_LABEL: &[u8] = b"plexusterm-share v1";
const MAX_NOISE_LEN: usize = 65535;

/// One AES-256 key per direction for one viewer session.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKeys {
    pub to_sharer: [u8; 32],
    pub to_viewer: [u8; 32],
}

impl core::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SessionKeys(<redacted>)")
    }
}

fn prologue(share_id: &ShareId) -> Vec<u8> {
    let mut p = PROLOGUE_LABEL.to_vec();
    p.extend_from_slice(&share_id.0);
    p
}

fn builder<'a>(
    prologue: &'a [u8],
    psk: &'a [u8; 32],
    ephemeral: Option<&'a [u8; 32]>,
) -> Result<Builder<'a>, ProtocolError> {
    let params = NOISE_PARAMS.parse().map_err(|_| ProtocolError::Handshake)?;
    let mut b = Builder::new(params)
        .prologue(prologue)
        .map_err(|_| ProtocolError::Handshake)?
        .psk(0, psk)
        .map_err(|_| ProtocolError::Handshake)?;
    if let Some(e) = ephemeral {
        b = b.fixed_ephemeral_key_for_testing_only(e);
    }
    Ok(b)
}

fn strip_kind(message: &[u8]) -> Result<&[u8], ProtocolError> {
    match message.split_first() {
        Some((&KIND_HANDSHAKE, rest)) => Ok(rest),
        _ => Err(ProtocolError::Malformed),
    }
}

fn write(hs: &mut HandshakeState, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let mut buf = vec![0u8; MAX_NOISE_LEN];
    let n = hs
        .write_message(payload, &mut buf)
        .map_err(|_| ProtocolError::TooLarge)?;
    let mut out = Vec::with_capacity(n + 1);
    out.push(KIND_HANDSHAKE);
    out.extend_from_slice(&buf[..n]);
    Ok(out)
}

fn read(hs: &mut HandshakeState, message: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let mut buf = vec![0u8; MAX_NOISE_LEN];
    let n = hs
        .read_message(strip_kind(message)?, &mut buf)
        .map_err(|_| ProtocolError::Auth)?;
    buf.truncate(n);
    Ok(buf)
}

fn split(hs: &mut HandshakeState) -> SessionKeys {
    // Noise Split() yields (initiator→responder, responder→initiator).
    let (to_sharer, to_viewer) = hs.dangerously_get_raw_split();
    SessionKeys {
        to_sharer,
        to_viewer,
    }
}

/// Viewer side, waiting for the sharer's reply.
pub struct ViewerHandshake {
    hs: HandshakeState,
}

impl ViewerHandshake {
    /// Builds message 1 carrying `payload` (encrypted under the PSK).
    pub fn start(
        share_id: &ShareId,
        psk: &[u8; 32],
        payload: &[u8],
    ) -> Result<(Self, Vec<u8>), ProtocolError> {
        Self::start_inner(share_id, psk, payload, None)
    }

    /// Deterministic variant for cross-language test vectors only.
    #[doc(hidden)]
    pub fn start_with_ephemeral(
        share_id: &ShareId,
        psk: &[u8; 32],
        payload: &[u8],
        ephemeral: &[u8; 32],
    ) -> Result<(Self, Vec<u8>), ProtocolError> {
        Self::start_inner(share_id, psk, payload, Some(ephemeral))
    }

    fn start_inner(
        share_id: &ShareId,
        psk: &[u8; 32],
        payload: &[u8],
        ephemeral: Option<&[u8; 32]>,
    ) -> Result<(Self, Vec<u8>), ProtocolError> {
        let prologue = prologue(share_id);
        let mut hs = builder(&prologue, psk, ephemeral)?
            .build_initiator()
            .map_err(|_| ProtocolError::Handshake)?;
        let msg = write(&mut hs, payload)?;
        Ok((Self { hs }, msg))
    }

    /// Reads message 2 and returns the session keys and the sharer's payload.
    pub fn finish(mut self, message: &[u8]) -> Result<(SessionKeys, Vec<u8>), ProtocolError> {
        let payload = read(&mut self.hs, message)?;
        if !self.hs.is_handshake_finished() {
            return Err(ProtocolError::Handshake);
        }
        Ok((split(&mut self.hs), payload))
    }
}

/// Sharer side after a valid message 1, before the join is approved.
pub struct PendingViewer {
    hs: HandshakeState,
}

impl PendingViewer {
    /// Reads message 1. Fails with [`ProtocolError::Auth`] when the viewer
    /// does not hold the link's PSK.
    pub fn accept(
        share_id: &ShareId,
        psk: &[u8; 32],
        message: &[u8],
    ) -> Result<(Self, Vec<u8>), ProtocolError> {
        Self::accept_inner(share_id, psk, message, None)
    }

    #[doc(hidden)]
    pub fn accept_with_ephemeral(
        share_id: &ShareId,
        psk: &[u8; 32],
        message: &[u8],
        ephemeral: &[u8; 32],
    ) -> Result<(Self, Vec<u8>), ProtocolError> {
        Self::accept_inner(share_id, psk, message, Some(ephemeral))
    }

    fn accept_inner(
        share_id: &ShareId,
        psk: &[u8; 32],
        message: &[u8],
        ephemeral: Option<&[u8; 32]>,
    ) -> Result<(Self, Vec<u8>), ProtocolError> {
        let prologue = prologue(share_id);
        let mut hs = builder(&prologue, psk, ephemeral)?
            .build_responder()
            .map_err(|_| ProtocolError::Handshake)?;
        let payload = read(&mut hs, message)?;
        Ok((Self { hs }, payload))
    }

    /// Approves the join: builds message 2 carrying `payload`.
    pub fn respond(mut self, payload: &[u8]) -> Result<(SessionKeys, Vec<u8>), ProtocolError> {
        let msg = write(&mut self.hs, payload)?;
        if !self.hs.is_handshake_finished() {
            return Err(ProtocolError::Handshake);
        }
        Ok((split(&mut self.hs), msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHARE: ShareId = ShareId([5; 16]);

    #[test]
    fn both_sides_derive_the_same_distinct_keys() {
        let psk = [9u8; 32];
        let (viewer, m1) = ViewerHandshake::start(&SHARE, &psk, b"hello").unwrap();
        let (pending, p1) = PendingViewer::accept(&SHARE, &psk, &m1).unwrap();
        assert_eq!(p1, b"hello");
        let (sharer_keys, m2) = pending.respond(b"welcome").unwrap();
        let (viewer_keys, p2) = viewer.finish(&m2).unwrap();
        assert_eq!(p2, b"welcome");
        assert_eq!(sharer_keys, viewer_keys);
        assert_ne!(viewer_keys.to_sharer, viewer_keys.to_viewer);
    }

    #[test]
    fn each_handshake_gets_fresh_keys() {
        let psk = [9u8; 32];
        let run = || {
            let (v, m1) = ViewerHandshake::start(&SHARE, &psk, b"").unwrap();
            let (p, _) = PendingViewer::accept(&SHARE, &psk, &m1).unwrap();
            let (_, m2) = p.respond(b"").unwrap();
            v.finish(&m2).unwrap().0
        };
        assert_ne!(run(), run());
    }

    #[test]
    fn wrong_psk_or_share_is_rejected() {
        let (_, m1) = ViewerHandshake::start(&SHARE, &[9u8; 32], b"hi").unwrap();
        assert_eq!(
            PendingViewer::accept(&SHARE, &[8u8; 32], &m1).err(),
            Some(ProtocolError::Auth)
        );
        assert_eq!(
            PendingViewer::accept(&ShareId([6; 16]), &[9u8; 32], &m1).err(),
            Some(ProtocolError::Auth)
        );
    }

    #[test]
    fn payload_is_not_visible_in_handshake_bytes() {
        let marker = b"MARKER-noise-41";
        let (_, m1) = ViewerHandshake::start(&SHARE, &[9u8; 32], marker).unwrap();
        assert!(!m1.windows(marker.len()).any(|w| w == marker));
        assert_eq!(m1[0], KIND_HANDSHAKE);
    }
}
