/// Failures a party must tell apart to decide what to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    /// Bytes are not valid base64url, JSON or a known binary layout.
    #[error("malformed message")]
    Malformed,
    /// A frame or handshake failed authentication: wrong key, tampered bytes
    /// or bytes bound to another share, viewer or direction.
    #[error("authentication failed")]
    Auth,
    /// A frame's sequence number is not strictly greater than the last one.
    #[error("replayed or reordered frame")]
    Replay,
    /// The 64-bit sequence space of a key is used up; the session must end.
    #[error("sequence numbers exhausted")]
    SequenceExhausted,
    /// The Noise handshake could not proceed (wrong step or wrong PSK).
    #[error("handshake failed")]
    Handshake,
    /// A plaintext or message is larger than the protocol allows.
    #[error("message too large")]
    TooLarge,
}
