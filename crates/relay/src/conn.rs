//! Outgoing side of one WebSocket connection.
//!
//! Every connection gets a writer task fed by an unbounded channel whose
//! queued bytes are counted, so the share actor can apply the 2 MB viewer
//! queue limit by disconnecting, never by dropping a frame.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use futures_util::SinkExt;
use futures_util::stream::SplitSink;
use tokio::sync::mpsc;

/// WebSocket close codes the relay uses. Codes below 4100 mean "reconnect";
/// final outcomes are always announced by a control message first.
pub mod close {
    pub const NORMAL: u16 = 1000;
    pub const SLOW: u16 = 4003;
    pub const AWAY_BUFFER_FULL: u16 = 4004;
    pub const REPLACED: u16 = 4005;
}

#[derive(Debug)]
pub enum Out {
    Text(String),
    Binary(Vec<u8>),
    Close(u16, &'static str),
}

impl Out {
    fn len(&self) -> usize {
        match self {
            Out::Text(t) => t.len(),
            Out::Binary(b) => b.len(),
            Out::Close(..) => 0,
        }
    }
}

/// The queue would exceed its byte limit; the caller disconnects the peer.
#[derive(Debug, PartialEq, Eq)]
pub struct Overflow;

#[derive(Clone, Debug)]
pub struct ConnTx {
    pub id: u64,
    tx: mpsc::UnboundedSender<Out>,
    queued: Arc<AtomicUsize>,
}

impl ConnTx {
    pub fn new(id: u64) -> (Self, mpsc::UnboundedReceiver<Out>, Arc<AtomicUsize>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let queued = Arc::new(AtomicUsize::new(0));
        (
            Self {
                id,
                tx,
                queued: Arc::clone(&queued),
            },
            rx,
            queued,
        )
    }

    /// Queues a message with no byte limit (control messages, sharer side).
    pub fn send(&self, out: Out) {
        self.queued.fetch_add(out.len(), Ordering::Relaxed);
        // A closed channel means the writer already finished; the reader
        // side reports the disconnect, so there is nothing to do here.
        let _ = self.tx.send(out);
    }

    /// Queues a message unless it would push the queue over `limit` bytes.
    pub fn send_limited(&self, out: Out, limit: usize) -> Result<(), Overflow> {
        let len = out.len();
        let before = self.queued.fetch_add(len, Ordering::Relaxed);
        if before.checked_add(len).is_none_or(|total| total > limit) {
            self.queued.fetch_sub(len, Ordering::Relaxed);
            return Err(Overflow);
        }
        let _ = self.tx.send(out);
        Ok(())
    }

    pub fn text(&self, msg: &impl serde::Serialize) {
        self.send(Out::Text(to_json(msg)));
    }

    pub fn close(&self, code: u16, reason: &'static str) {
        self.send(Out::Close(code, reason));
    }
}

pub fn to_json(msg: &impl serde::Serialize) -> String {
    // Wire enums contain only strings, numbers and fixed byte strings, so
    // serialization cannot fail.
    serde_json::to_string(msg).unwrap_or_default()
}

/// Drains `rx` into the socket until a `Close` or a send error.
pub async fn write_loop(
    mut sink: SplitSink<WebSocket, Message>,
    mut rx: mpsc::UnboundedReceiver<Out>,
    queued: Arc<AtomicUsize>,
) {
    while let Some(out) = rx.recv().await {
        let len = out.len();
        let msg = match out {
            Out::Text(t) => Message::Text(t.into()),
            Out::Binary(b) => Message::Binary(b.into()),
            Out::Close(code, reason) => {
                let _ = sink
                    .send(Message::Close(Some(CloseFrame {
                        code,
                        reason: reason.into(),
                    })))
                    .await;
                break;
            }
        };
        let sent = sink.send(msg).await;
        queued.fetch_sub(len, Ordering::Relaxed);
        if sent.is_err() {
            break;
        }
    }
    let _ = sink.close().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limited_send_refuses_past_the_limit_without_counting_it() {
        let (tx, mut rx, queued) = ConnTx::new(1);
        assert_eq!(tx.send_limited(Out::Binary(vec![0; 6]), 10), Ok(()));
        assert_eq!(tx.send_limited(Out::Binary(vec![0; 5]), 10), Err(Overflow));
        assert_eq!(queued.load(Ordering::Relaxed), 6);
        assert_eq!(tx.send_limited(Out::Binary(vec![0; 4]), 10), Ok(()));
        assert!(matches!(rx.try_recv(), Ok(Out::Binary(b)) if b.len() == 6));
        assert!(matches!(rx.try_recv(), Ok(Out::Binary(b)) if b.len() == 4));
        assert!(rx.try_recv().is_err());
    }
}
