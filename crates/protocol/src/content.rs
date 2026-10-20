//! Plaintext carried inside encrypted frames and handshake payloads.
//!
//! The relay never sees any of this. Frame plaintext is a one-byte type
//! followed by a fixed big-endian header and the data; handshake payloads and
//! status updates are JSON.

use serde::{Deserialize, Serialize};

use crate::ProtocolError;
use crate::b64::b64_bytes;

b64_bytes!(
    /// Random per-browser-tab identifier so a reconnecting viewer is
    /// recognized by the sharer and not counted as a new viewer.
    ClientId,
    16
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    /// View only: the sharer drops every input frame.
    View,
    /// Can type.
    Type,
}

/// Payload of Noise message 1 (viewer → sharer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewerHello {
    pub client: ClientId,
    /// Last output sequence number the viewer rendered, when reconnecting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_from: Option<u64>,
}

/// Payload of Noise message 2 (sharer → viewer): the join is approved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Welcome {
    pub access: Access,
    pub cols: u16,
    pub rows: u16,
}

/// Change of share state pushed by the sharer to a viewer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<Access>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_paused: Option<bool>,
    /// The shared program exited; the share ends right after.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program_exited: Option<bool>,
}

const T_OUTPUT: u8 = 0x10;
const T_SNAPSHOT: u8 = 0x11;
const T_STATUS: u8 = 0x12;
const T_SIZE: u8 = 0x13;
const T_INPUT: u8 = 0x20;
const T_RESYNC: u8 = 0x21;

/// One frame's plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// Live terminal output with its output sequence number.
    Output {
        seq: u64,
        data: Vec<u8>,
    },
    /// One chunk of a snapshot. `covers_seq` is the last output sequence
    /// number already contained in the snapshot; live output continues
    /// from `covers_seq + 1`. Chunks are numbered `index` of `count`; the
    /// first chunk holds the visible screen. `compressed` means raw DEFLATE.
    /// The bytes are the terminal snapshot format versioned by PlexusTerm.
    Snapshot {
        covers_seq: u64,
        cols: u16,
        rows: u16,
        index: u16,
        count: u16,
        compressed: bool,
        data: Vec<u8>,
    },
    Status(Status),
    /// The shared terminal's size changed.
    Size {
        cols: u16,
        rows: u16,
    },
    /// Viewer keystrokes: one complete key event or one bracketed paste.
    Input {
        data: Vec<u8>,
    },
    /// Viewer asks to continue after `last_seq`, or for a fresh snapshot
    /// when `None` (sent after the sharer comes back).
    Resync {
        last_seq: Option<u64>,
    },
}

impl Content {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Content::Output { seq, data } => {
                out.push(T_OUTPUT);
                out.extend_from_slice(&seq.to_be_bytes());
                out.extend_from_slice(data);
            }
            Content::Snapshot {
                covers_seq,
                cols,
                rows,
                index,
                count,
                compressed,
                data,
            } => {
                out.push(T_SNAPSHOT);
                out.extend_from_slice(&covers_seq.to_be_bytes());
                out.extend_from_slice(&cols.to_be_bytes());
                out.extend_from_slice(&rows.to_be_bytes());
                out.extend_from_slice(&index.to_be_bytes());
                out.extend_from_slice(&count.to_be_bytes());
                out.push(u8::from(*compressed));
                out.extend_from_slice(data);
            }
            Content::Status(status) => {
                out.push(T_STATUS);
                // Serializing a struct of plain fields to JSON cannot fail.
                out.extend(serde_json::to_vec(status).unwrap_or_default());
            }
            Content::Size { cols, rows } => {
                out.push(T_SIZE);
                out.extend_from_slice(&cols.to_be_bytes());
                out.extend_from_slice(&rows.to_be_bytes());
            }
            Content::Input { data } => {
                out.push(T_INPUT);
                out.extend_from_slice(data);
            }
            Content::Resync { last_seq } => {
                out.push(T_RESYNC);
                out.push(u8::from(last_seq.is_some()));
                out.extend_from_slice(&last_seq.unwrap_or(0).to_be_bytes());
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let (&kind, body) = bytes.split_first().ok_or(ProtocolError::Malformed)?;
        let mut r = Reader(body);
        let content = match kind {
            T_OUTPUT => Content::Output {
                seq: r.u64()?,
                data: r.rest(),
            },
            T_SNAPSHOT => Content::Snapshot {
                covers_seq: r.u64()?,
                cols: r.u16()?,
                rows: r.u16()?,
                index: r.u16()?,
                count: r.u16()?,
                compressed: match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(ProtocolError::Malformed),
                },
                data: r.rest(),
            },
            T_STATUS => {
                Content::Status(serde_json::from_slice(body).map_err(|_| ProtocolError::Malformed)?)
            }
            T_SIZE => Content::Size {
                cols: r.u16()?,
                rows: r.u16()?,
            },
            T_INPUT => Content::Input { data: r.rest() },
            T_RESYNC => {
                let present = r.u8()?;
                let seq = r.u64()?;
                Content::Resync {
                    last_seq: match present {
                        0 => None,
                        1 => Some(seq),
                        _ => return Err(ProtocolError::Malformed),
                    },
                }
            }
            _ => return Err(ProtocolError::Malformed),
        };
        Ok(content)
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        if self.0.len() < N {
            return Err(ProtocolError::Malformed);
        }
        let (head, tail) = self.0.split_at(N);
        self.0 = tail;
        head.try_into().map_err(|_| ProtocolError::Malformed)
    }
    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_be_bytes(self.take()?))
    }
    fn u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_be_bytes(self.take()?))
    }
    fn rest(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_round_trips() {
        let all = [
            Content::Output {
                seq: 42,
                data: b"\x1b[31mred".to_vec(),
            },
            Content::Snapshot {
                covers_seq: 41,
                cols: 120,
                rows: 40,
                index: 0,
                count: 3,
                compressed: true,
                data: vec![1, 2, 3],
            },
            Content::Status(Status {
                access: Some(Access::View),
                ..Status::default()
            }),
            Content::Size { cols: 80, rows: 24 },
            Content::Input {
                data: b"q".to_vec(),
            },
            Content::Resync { last_seq: Some(7) },
            Content::Resync { last_seq: None },
        ];
        for c in all {
            assert_eq!(Content::decode(&c.encode()), Ok(c));
        }
    }

    #[test]
    fn truncated_or_unknown_is_malformed() {
        assert_eq!(Content::decode(&[]), Err(ProtocolError::Malformed));
        assert_eq!(
            Content::decode(&[T_OUTPUT, 1, 2]),
            Err(ProtocolError::Malformed)
        );
        assert_eq!(Content::decode(&[0x7f]), Err(ProtocolError::Malformed));
    }

    #[test]
    fn handshake_payloads_use_documented_json() {
        let hello = ViewerHello {
            client: ClientId([0; 16]),
            resume_from: None,
        };
        assert_eq!(
            serde_json::to_string(&hello).unwrap(),
            r#"{"client":"AAAAAAAAAAAAAAAAAAAAAA"}"#
        );
        let welcome = Welcome {
            access: Access::Type,
            cols: 80,
            rows: 24,
        };
        assert_eq!(
            serde_json::to_string(&welcome).unwrap(),
            r#"{"access":"type","cols":80,"rows":24}"#
        );
    }
}
