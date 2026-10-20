//! Output log, snapshot chunking and snapshot assembly.

use std::collections::VecDeque;
use std::io::{Read, Write};

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use plexusterm_share_protocol::ProtocolError;
use plexusterm_share_protocol::content::{Content, SnapshotPart};

/// Raw bytes per snapshot chunk before compression. DEFLATE can grow
/// incompressible input slightly, which still fits `MAX_PLAINTEXT_LEN`.
pub const CHUNK_RAW_LEN: usize = 24 * 1024;
/// Largest decompressed chunk a viewer accepts.
const CHUNK_INFLATED_MAX: usize = 4 * CHUNK_RAW_LEN;
/// Largest live output a sharer puts in one frame.
pub const OUTPUT_CHUNK_LEN: usize = 24 * 1024;

/// Share-wide numbered output, keeping the most recent `cap` bytes so a
/// reconnecting viewer can resume without a snapshot (PRD §5.4: 1 MB).
pub struct OutputLog {
    entries: VecDeque<(u64, Vec<u8>)>,
    bytes: usize,
    cap: usize,
    last_seq: u64,
}

impl OutputLog {
    pub fn new(cap: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            bytes: 0,
            cap,
            last_seq: 0,
        }
    }

    /// Numbers and stores `data`, split in frame-sized pieces. Returns the
    /// new entries.
    pub fn push(&mut self, data: &[u8]) -> Vec<(u64, Vec<u8>)> {
        let mut added = Vec::new();
        for piece in data.chunks(OUTPUT_CHUNK_LEN) {
            // u64 sequence numbers cannot run out in practice; stop
            // numbering rather than wrap if they ever did.
            let Some(seq) = self.last_seq.checked_add(1) else {
                break;
            };
            self.last_seq = seq;
            self.bytes = self.bytes.saturating_add(piece.len());
            self.entries.push_back((seq, piece.to_vec()));
            added.push((seq, piece.to_vec()));
        }
        while self.bytes > self.cap {
            match self.entries.pop_front() {
                Some((_, d)) => self.bytes = self.bytes.saturating_sub(d.len()),
                None => break,
            }
        }
        added
    }

    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    /// Entries after `seq`, or `None` when some of them were evicted and a
    /// snapshot is needed instead.
    pub fn since(&self, seq: u64) -> Option<Vec<(u64, Vec<u8>)>> {
        if seq > self.last_seq {
            return None;
        }
        if seq == self.last_seq {
            return Some(Vec::new());
        }
        let first = self.entries.front().map(|(s, _)| *s)?;
        if seq.checked_add(1)? < first {
            return None;
        }
        Some(
            self.entries
                .iter()
                .filter(|(s, _)| *s > seq)
                .cloned()
                .collect(),
        )
    }

    /// Every retained byte in order: the demo sharer's snapshot, since it
    /// has no terminal emulator to serialize.
    pub fn contents(&self) -> Vec<u8> {
        self.entries
            .iter()
            .flat_map(|(_, d)| d.iter().copied())
            .collect()
    }
}

/// Splits one snapshot part into compressed `Snapshot` frames.
pub fn chunk(
    bytes: &[u8],
    covers_seq: u64,
    cols: u16,
    rows: u16,
    part: SnapshotPart,
) -> Vec<Content> {
    let pieces: Vec<&[u8]> = if bytes.is_empty() {
        vec![&[][..]]
    } else {
        bytes.chunks(CHUNK_RAW_LEN).collect()
    };
    let count = u16::try_from(pieces.len()).unwrap_or(u16::MAX);
    pieces
        .into_iter()
        .take(usize::from(count))
        .enumerate()
        .map(|(i, piece)| Content::Snapshot {
            covers_seq,
            cols,
            rows,
            part,
            index: u16::try_from(i).unwrap_or(u16::MAX),
            count,
            compressed: true,
            data: deflate(piece),
        })
        .collect()
}

fn deflate(bytes: &[u8]) -> Vec<u8> {
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
    // Writing to a Vec cannot fail.
    let _ = enc.write_all(bytes);
    enc.finish().unwrap_or_default()
}

fn inflate(bytes: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let mut out = Vec::new();
    DeflateDecoder::new(bytes)
        .take(CHUNK_INFLATED_MAX as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| ProtocolError::Malformed)?;
    if out.len() > CHUNK_INFLATED_MAX {
        return Err(ProtocolError::TooLarge);
    }
    Ok(out)
}

/// Collects the chunks of one snapshot part.
#[derive(Default)]
pub struct Assembly {
    key: Option<(u64, SnapshotPart, u16)>,
    chunks: Vec<Option<Vec<u8>>>,
}

pub struct Completed {
    pub covers_seq: u64,
    pub part: SnapshotPart,
    pub cols: u16,
    pub rows: u16,
    pub bytes: Vec<u8>,
}

impl Assembly {
    /// Adds a chunk; returns the whole part once every chunk arrived.
    pub fn add(&mut self, content: Content) -> Result<Option<Completed>, ProtocolError> {
        let Content::Snapshot {
            covers_seq,
            cols,
            rows,
            part,
            index,
            count,
            compressed,
            data,
        } = content
        else {
            return Ok(None);
        };
        if count == 0 || index >= count {
            return Err(ProtocolError::Malformed);
        }
        let key = (covers_seq, part, count);
        if self.key != Some(key) {
            self.key = Some(key);
            self.chunks = vec![None; usize::from(count)];
        }
        let bytes = if compressed { inflate(&data)? } else { data };
        self.chunks[usize::from(index)] = Some(bytes);
        if self.chunks.iter().any(Option::is_none) {
            return Ok(None);
        }
        let bytes = self.chunks.drain(..).flatten().flatten().collect();
        self.key = None;
        Ok(Some(Completed {
            covers_seq,
            part,
            cols,
            rows,
            bytes,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_numbers_output_and_evicts_past_its_cap() {
        let mut log = OutputLog::new(10);
        assert_eq!(log.push(b"abcd"), vec![(1, b"abcd".to_vec())]);
        log.push(b"efgh");
        assert_eq!(log.since(1), Some(vec![(2, b"efgh".to_vec())]));
        assert_eq!(log.since(2), Some(vec![]));
        log.push(b"ijkl");
        assert_eq!(log.last_seq(), 3);
        assert_eq!(log.contents(), b"efghijkl");
        assert_eq!(log.since(0), None, "seq 1 was evicted");
        assert_eq!(log.since(1).map(|v| v.len()), Some(2));
        assert_eq!(log.since(9), None);
    }

    #[test]
    fn large_output_is_split_into_frame_sized_entries() {
        let mut log = OutputLog::new(1 << 20);
        let added = log.push(&vec![b'x'; OUTPUT_CHUNK_LEN * 2 + 1]);
        assert_eq!(added.iter().map(|(s, _)| *s).collect::<Vec<_>>(), [1, 2, 3]);
        assert_eq!(added[2].1.len(), 1);
    }

    #[test]
    fn chunks_reassemble_in_any_order() {
        let bytes: Vec<u8> = (0..CHUNK_RAW_LEN * 2 + 100)
            .map(|i| (i % 251) as u8)
            .collect();
        let mut chunks = chunk(&bytes, 9, 80, 24, SnapshotPart::Full);
        assert_eq!(chunks.len(), 3);
        for c in &chunks {
            assert!(c.encode().len() <= plexusterm_share_protocol::MAX_PLAINTEXT_LEN);
        }
        chunks.swap(0, 2);
        let mut asm = Assembly::default();
        assert!(asm.add(chunks.remove(0)).unwrap().is_none());
        assert!(asm.add(chunks.remove(0)).unwrap().is_none());
        let done = asm.add(chunks.remove(0)).unwrap().unwrap();
        assert_eq!(done.bytes, bytes);
        assert_eq!(done.covers_seq, 9);
        assert_eq!(done.part, SnapshotPart::Full);
    }

    #[test]
    fn empty_snapshot_is_one_chunk() {
        let mut asm = Assembly::default();
        let only = chunk(b"", 0, 80, 24, SnapshotPart::Full).remove(0);
        assert_eq!(asm.add(only).unwrap().unwrap().bytes, b"");
    }

    #[test]
    fn decompression_bombs_are_refused() {
        let bomb = Content::Snapshot {
            covers_seq: 1,
            cols: 80,
            rows: 24,
            part: SnapshotPart::Full,
            index: 0,
            count: 1,
            compressed: true,
            data: deflate(&vec![0u8; CHUNK_INFLATED_MAX * 4]),
        };
        assert_eq!(
            Assembly::default().add(bomb).err(),
            Some(ProtocolError::TooLarge)
        );
    }
}
