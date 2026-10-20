//! Encrypted frames between one viewer and the sharing side.
//!
//! Layout: `[KIND_FRAME][seq: u64 BE][AES-256-GCM ciphertext ‖ tag]`.
//! The nonce is `0x00000000 ‖ seq`, unique because every direction has its own
//! key and `seq` only grows. The additional data binds share id, viewer id,
//! direction and `seq`, so the relay can neither move a frame to another
//! viewer or direction nor replay it.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::ProtocolError;
use crate::keys::ShareId;

/// First byte of a viewer↔sharer payload carrying a Noise handshake message.
pub const KIND_HANDSHAKE: u8 = 0x01;
/// First byte of a viewer↔sharer payload carrying an encrypted frame.
pub const KIND_FRAME: u8 = 0x02;

const HEADER_LEN: usize = 1 + 8;
const AAD_LABEL: &[u8; 4] = b"PTS1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ToViewer = 0,
    ToSharer = 1,
}

/// Binds a frame to one share, one viewer and one direction.
#[derive(Debug, Clone, Copy)]
pub struct Binding {
    pub share_id: ShareId,
    pub viewer_id: u32,
    pub direction: Direction,
}

impl Binding {
    fn aad(&self, seq: u64) -> [u8; 33] {
        let mut aad = [0u8; 33];
        aad[..4].copy_from_slice(AAD_LABEL);
        aad[4..20].copy_from_slice(&self.share_id.0);
        aad[20..24].copy_from_slice(&self.viewer_id.to_be_bytes());
        aad[24] = self.direction as u8;
        aad[25..].copy_from_slice(&seq.to_be_bytes());
        aad
    }
}

fn nonce(seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}

/// Encrypts outgoing frames for one direction. Sequence numbers start at 1.
pub struct Sealer {
    cipher: Aes256Gcm,
    binding: Binding,
    next_seq: u64,
}

impl Sealer {
    pub fn new(key: &[u8; 32], binding: Binding) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
            binding,
            next_seq: 1,
        }
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if plaintext.len() > crate::MAX_PLAINTEXT_LEN {
            return Err(ProtocolError::TooLarge);
        }
        let seq = self.next_seq;
        self.next_seq = seq.checked_add(1).ok_or(ProtocolError::SequenceExhausted)?;
        let aad = self.binding.aad(seq);
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce(seq)),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| ProtocolError::TooLarge)?;
        let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        out.push(KIND_FRAME);
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }
}

/// Decrypts incoming frames for one direction and drops any frame whose
/// sequence number is not strictly greater than the last accepted one.
pub struct Opener {
    cipher: Aes256Gcm,
    binding: Binding,
    last_seq: u64,
}

impl Opener {
    pub fn new(key: &[u8; 32], binding: Binding) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
            binding,
            last_seq: 0,
        }
    }

    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if frame.len() < HEADER_LEN || frame[0] != KIND_FRAME {
            return Err(ProtocolError::Malformed);
        }
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&frame[1..HEADER_LEN]);
        let seq = u64::from_be_bytes(seq_bytes);
        if seq <= self.last_seq {
            return Err(ProtocolError::Replay);
        }
        let aad = self.binding.aad(seq);
        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce(seq)),
                Payload {
                    msg: &frame[HEADER_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| ProtocolError::Auth)?;
        // Only an authenticated frame may advance the window, so a forged
        // high sequence number cannot lock out real frames.
        self.last_seq = seq;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(viewer_id: u32, direction: Direction) -> Binding {
        Binding {
            share_id: ShareId([1; 16]),
            viewer_id,
            direction,
        }
    }

    #[test]
    fn round_trip_in_order() {
        let key = [4u8; 32];
        let mut tx = Sealer::new(&key, binding(3, Direction::ToViewer));
        let mut rx = Opener::new(&key, binding(3, Direction::ToViewer));
        for text in [&b"one"[..], b"", b"three"] {
            let frame = tx.seal(text).unwrap();
            assert_eq!(rx.open(&frame).unwrap(), text);
        }
    }

    #[test]
    fn replayed_and_reordered_frames_are_dropped() {
        let key = [4u8; 32];
        let mut tx = Sealer::new(&key, binding(3, Direction::ToSharer));
        let mut rx = Opener::new(&key, binding(3, Direction::ToSharer));
        let first = tx.seal(b"ls\r").unwrap();
        let second = tx.seal(b"rm\r").unwrap();
        assert_eq!(rx.open(&second).unwrap(), b"rm\r");
        assert_eq!(rx.open(&first), Err(ProtocolError::Replay));
        assert_eq!(rx.open(&second), Err(ProtocolError::Replay));
    }

    #[test]
    fn frames_are_bound_to_viewer_direction_and_share() {
        let key = [4u8; 32];
        let mut tx = Sealer::new(&key, binding(3, Direction::ToViewer));
        let frame = tx.seal(b"secret").unwrap();
        assert_eq!(
            Opener::new(&key, binding(4, Direction::ToViewer)).open(&frame),
            Err(ProtocolError::Auth)
        );
        assert_eq!(
            Opener::new(&key, binding(3, Direction::ToSharer)).open(&frame),
            Err(ProtocolError::Auth)
        );
        let other_share = Binding {
            share_id: ShareId([2; 16]),
            ..binding(3, Direction::ToViewer)
        };
        assert_eq!(
            Opener::new(&key, other_share).open(&frame),
            Err(ProtocolError::Auth)
        );
    }

    #[test]
    fn forged_frame_does_not_advance_the_window() {
        let key = [4u8; 32];
        let mut tx = Sealer::new(&key, binding(3, Direction::ToViewer));
        let mut rx = Opener::new(&key, binding(3, Direction::ToViewer));
        let mut forged = tx.seal(b"x").unwrap();
        forged[1..9].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(rx.open(&forged), Err(ProtocolError::Auth));
        let real = tx.seal(b"y").unwrap();
        assert_eq!(rx.open(&real).unwrap(), b"y");
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        let mut tx = Sealer::new(&[4u8; 32], binding(3, Direction::ToViewer));
        let marker = b"MARKER-7f3a9c";
        let frame = tx.seal(marker).unwrap();
        assert!(!frame.windows(marker.len()).any(|w| w == marker));
    }

    #[test]
    fn oversized_plaintext_is_refused() {
        let mut tx = Sealer::new(&[4u8; 32], binding(3, Direction::ToViewer));
        let big = vec![0u8; crate::MAX_PLAINTEXT_LEN + 1];
        assert_eq!(tx.seal(&big), Err(ProtocolError::TooLarge));
        assert!(tx.seal(&big[..crate::MAX_PLAINTEXT_LEN]).unwrap().len() < crate::MAX_MESSAGE_LEN);
    }
}
