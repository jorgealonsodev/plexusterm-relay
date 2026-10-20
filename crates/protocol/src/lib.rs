//! Wire format and end-to-end crypto for PlexusTerm terminal sharing.
//!
//! The relay links this crate only for [`wire`] and the verifier side of
//! [`keys`]; it never derives handshake keys and never opens a [`frame`].
//! Sharers and viewers use every module. The byte-level contract is written
//! down in `docs/protocol.md`; this crate is its reference implementation.

pub mod b64;
pub mod content;
pub mod error;
pub mod frame;
pub mod keys;
pub mod link;
pub mod noise;
pub mod wire;

pub use error::ProtocolError;

/// Version exchanged on join by sharer, relay and viewer.
pub const PROTOCOL_VERSION: u16 = 1;

/// Largest WebSocket message, in bytes, that any party may send.
pub const MAX_MESSAGE_LEN: usize = 64 * 1024;

/// Largest plaintext a sharer puts in one encrypted frame, leaving room for
/// the frame header, the GCM tag and the relay's routing prefix.
pub const MAX_PLAINTEXT_LEN: usize = 32 * 1024;
