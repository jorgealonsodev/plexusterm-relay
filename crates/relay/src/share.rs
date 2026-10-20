//! One actor task per live share.
//!
//! The actor owns all of a share's state: links, the sharer connection,
//! viewers and every timer. Connection handlers talk to it through
//! [`ShareEvent`]s, so no lock is held while forwarding frames.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use plexusterm_share_protocol::keys::{Challenge, LinkId, Proof, Role, ShareId, Verifier};
use plexusterm_share_protocol::wire::{
    EndReason, ErrorCode, LeftReason, LinkRegistration, RelayToSharer, RelayToViewer,
    SharerToRelay, ViewerInfo, encode_routed,
};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, sleep_until};
use tracing::{debug, info};

use crate::conn::{ConnTx, Out, close};
use crate::hub::{Bucket, Hub, ShareHandle, expiry_deadline};

pub enum ShareEvent {
    /// `resume` with an owner proof answering `challenge`.
    Resume {
        challenge: Challenge,
        proof: Proof,
        conn: ConnTx,
        reply: oneshot::Sender<Result<(), ErrorCode>>,
    },
    SharerControl {
        conn_id: u64,
        msg: SharerToRelay,
    },
    SharerBinary {
        conn_id: u64,
        viewer: u32,
        payload: Vec<u8>,
    },
    SharerGone {
        conn_id: u64,
    },
    ViewerJoin {
        link_id: LinkId,
        challenge: Challenge,
        proof: Proof,
        ip: String,
        ua: String,
        conn: ConnTx,
        reply: oneshot::Sender<Result<(u32, u64), ErrorCode>>,
    },
    ViewerBinary {
        viewer: u32,
        payload: Vec<u8>,
    },
    ViewerGone {
        viewer: u32,
    },
}

pub struct Init {
    pub id: ShareId,
    pub token: usize,
    pub owner_verifier: Verifier,
    pub links: Vec<LinkRegistration>,
    pub expires_at: u64,
    pub deadline: Instant,
    pub sharer: ConnTx,
}

struct Viewer {
    conn: ConnTx,
    info: ViewerInfo,
    /// Messages for the sharer received while it was away.
    pending: Vec<Vec<u8>>,
    pending_bytes: usize,
}

struct Share {
    hub: Arc<Hub>,
    id: ShareId,
    token: usize,
    owner_verifier: Verifier,
    links: Vec<LinkRegistration>,
    expires_at: u64,
    deadline: Instant,
    sharer: Option<ConnTx>,
    sharer_lost: Option<Instant>,
    away_sent: bool,
    viewers: BTreeMap<u32, Viewer>,
    next_viewer: u32,
    no_viewers_since: Option<Instant>,
    bytes_to_viewers: u64,
    bytes_to_sharer: u64,
}

pub fn spawn(hub: Arc<Hub>, init: Init) -> ShareHandle {
    let (events, rx) = mpsc::unbounded_channel();
    let bucket = Arc::new(Mutex::new(Bucket::new(hub.config.limits.bytes_per_sec)));
    init.sharer.text(&RelayToSharer::Ready {
        expires_at: init.expires_at,
        viewers: Vec::new(),
    });
    let share = Share {
        hub,
        id: init.id,
        token: init.token,
        owner_verifier: init.owner_verifier,
        links: init.links,
        expires_at: init.expires_at,
        deadline: init.deadline,
        sharer: Some(init.sharer),
        sharer_lost: None,
        away_sent: false,
        viewers: BTreeMap::new(),
        next_viewer: 1,
        no_viewers_since: Some(Instant::now()),
        bytes_to_viewers: 0,
        bytes_to_sharer: 0,
    };
    info!(share = %share.id.log_tag(), "share created");
    tokio::spawn(share.run(rx));
    ShareHandle { events, bucket }
}

impl Share {
    async fn run(mut self, mut rx: mpsc::UnboundedReceiver<ShareEvent>) {
        let reason = loop {
            let (at, timer) = self.next_timer();
            tokio::select! {
                event = rx.recv() => match event {
                    Some(event) => {
                        if let Some(reason) = self.handle(event) {
                            break reason;
                        }
                    }
                    // Every handle was dropped: nothing can reach the share.
                    None => break EndReason::Offline,
                },
                () = sleep_until(at) => {
                    if let Some(reason) = self.fire(timer) {
                        break reason;
                    }
                }
            }
        };
        self.end(reason);
    }

    fn next_timer(&self) -> (Instant, Timer) {
        let t = &self.hub.config.timings;
        let mut next = (self.deadline, Timer::Expiry);
        let mut consider = |at: Instant, timer: Timer| {
            if at < next.0 {
                next = (at, timer);
            }
        };
        if let Some(lost) = self.sharer_lost {
            if !self.away_sent {
                consider(lost + t.sharer_away, Timer::Away);
            }
            consider(lost + t.sharer_offline, Timer::Offline);
        }
        if let Some(since) = self.no_viewers_since {
            consider(since + t.no_viewers, Timer::NoViewers);
        }
        next
    }

    fn fire(&mut self, timer: Timer) -> Option<EndReason> {
        match timer {
            Timer::Expiry => Some(EndReason::Expired),
            Timer::Offline => Some(EndReason::Offline),
            Timer::NoViewers => Some(EndReason::Idle),
            Timer::Away => {
                self.away_sent = true;
                self.broadcast(&RelayToViewer::SharerAway);
                None
            }
        }
    }

    fn handle(&mut self, event: ShareEvent) -> Option<EndReason> {
        match event {
            ShareEvent::Resume {
                challenge,
                proof,
                conn,
                reply,
            } => {
                let ok = self
                    .owner_verifier
                    .check(Role::Owner, &self.id, &challenge, &proof);
                if !ok {
                    let _ = reply.send(Err(ErrorCode::Conflict));
                    return None;
                }
                let _ = reply.send(Ok(()));
                self.attach_sharer(conn);
                None
            }
            ShareEvent::SharerControl { conn_id, msg } => {
                if !self.is_sharer(conn_id) {
                    return None;
                }
                self.sharer_control(msg)
            }
            ShareEvent::SharerBinary {
                conn_id,
                viewer,
                payload,
            } => {
                if self.is_sharer(conn_id) {
                    self.forward_to_viewer(viewer, payload);
                }
                None
            }
            ShareEvent::SharerGone { conn_id } => {
                if self.is_sharer(conn_id) {
                    self.sharer = None;
                    self.sharer_lost = Some(Instant::now());
                    debug!(share = %self.id.log_tag(), "sharer disconnected");
                }
                None
            }
            ShareEvent::ViewerJoin {
                link_id,
                challenge,
                proof,
                ip,
                ua,
                conn,
                reply,
            } => {
                let _ = reply.send(self.join(link_id, &challenge, &proof, ip, ua, conn));
                None
            }
            ShareEvent::ViewerBinary { viewer, payload } => {
                self.forward_to_sharer(viewer, payload);
                None
            }
            ShareEvent::ViewerGone { viewer } => {
                if self.viewers.remove(&viewer).is_some() {
                    self.after_viewer_left(viewer, Some(LeftReason::Closed));
                }
                None
            }
        }
    }

    fn is_sharer(&self, conn_id: u64) -> bool {
        self.sharer.as_ref().is_some_and(|s| s.id == conn_id)
    }

    fn attach_sharer(&mut self, conn: ConnTx) {
        if let Some(old) = self.sharer.take() {
            old.close(close::REPLACED, "replaced by a resumed sharer");
        }
        conn.text(&RelayToSharer::Ready {
            expires_at: self.expires_at,
            viewers: self.viewers.values().map(|v| v.info.clone()).collect(),
        });
        for (id, viewer) in &mut self.viewers {
            for payload in viewer.pending.drain(..) {
                conn.send(Out::Binary(encode_routed(*id, &payload)));
            }
            viewer.pending_bytes = 0;
        }
        self.sharer = Some(conn);
        self.sharer_lost = None;
        if std::mem::take(&mut self.away_sent) {
            self.broadcast(&RelayToViewer::SharerBack);
        }
        debug!(share = %self.id.log_tag(), "sharer attached");
    }

    fn sharer_control(&mut self, msg: SharerToRelay) -> Option<EndReason> {
        match msg {
            SharerToRelay::Deny { viewer } => {
                self.remove_viewer(viewer, &RelayToViewer::Denied);
            }
            SharerToRelay::Kick { viewer } => {
                self.remove_viewer(viewer, &RelayToViewer::Kicked);
            }
            SharerToRelay::Rotate { link_id, new } => {
                match self.links.iter_mut().find(|l| l.link_id == link_id) {
                    Some(link) => *link = new,
                    None => self.reject_sharer(),
                }
            }
            SharerToRelay::SetExpiry { expires_at } => {
                match expiry_deadline(expires_at, self.hub.config.limits.max_expiry) {
                    Ok(deadline) => {
                        self.expires_at = expires_at;
                        self.deadline = deadline;
                        self.broadcast(&RelayToViewer::Expiry { expires_at });
                        if let Some(s) = &self.sharer {
                            s.text(&RelayToSharer::Expiry { expires_at });
                        }
                    }
                    Err(_) => self.reject_sharer(),
                }
            }
            SharerToRelay::End => return Some(EndReason::Stopped),
            // `ping` is answered by the connection handler; `create` and
            // `resume` are only valid as the first message.
            SharerToRelay::Ping | SharerToRelay::Create { .. } | SharerToRelay::Resume { .. } => {
                self.reject_sharer();
            }
        }
        None
    }

    /// Closes the sharer connection after a malformed or out-of-order
    /// message. The share survives and the sharer may `resume`.
    fn reject_sharer(&mut self) {
        if let Some(s) = self.sharer.take() {
            s.text(&RelayToSharer::Error {
                code: ErrorCode::BadRequest,
                message: "unexpected message".into(),
            });
            s.close(close::NORMAL, "bad request");
            self.sharer_lost = Some(Instant::now());
        }
    }

    fn join(
        &mut self,
        link_id: LinkId,
        challenge: &Challenge,
        proof: &Proof,
        ip: String,
        ua: String,
        conn: ConnTx,
    ) -> Result<(u32, u64), ErrorCode> {
        let link = self
            .links
            .iter()
            .find(|l| l.link_id == link_id)
            .ok_or(ErrorCode::BadKey)?;
        if !link
            .verifier
            .check(Role::Viewer, &self.id, challenge, proof)
        {
            return Err(ErrorCode::BadKey);
        }
        if self.viewers.len() >= self.hub.config.limits.max_viewers {
            return Err(ErrorCode::Full);
        }
        let id = self.next_viewer;
        self.next_viewer = id.checked_add(1).ok_or(ErrorCode::Full)?;
        let info = ViewerInfo {
            viewer: id,
            link_id,
            ip,
            ua,
        };
        if let Some(s) = &self.sharer {
            s.text(&RelayToSharer::Join(info.clone()));
        }
        if self.away_sent {
            conn.text(&RelayToViewer::SharerAway);
        }
        self.viewers.insert(
            id,
            Viewer {
                conn,
                info,
                pending: Vec::new(),
                pending_bytes: 0,
            },
        );
        self.no_viewers_since = None;
        Ok((id, self.expires_at))
    }

    fn forward_to_viewer(&mut self, viewer: u32, payload: Vec<u8>) {
        let limit = self.hub.config.limits.viewer_queue_bytes;
        let Some(v) = self.viewers.get(&viewer) else {
            return;
        };
        let len = payload.len() as u64;
        if v.conn.send_limited(Out::Binary(payload), limit).is_ok() {
            self.bytes_to_viewers = self.bytes_to_viewers.saturating_add(len);
            return;
        }
        // Never drop a frame: disconnect the slow viewer instead. It
        // reconnects and receives a fresh snapshot.
        if let Some(v) = self.viewers.remove(&viewer) {
            v.conn.close(close::SLOW, "viewer too slow");
            self.after_viewer_left(viewer, Some(LeftReason::Slow));
        }
    }

    fn forward_to_sharer(&mut self, viewer: u32, payload: Vec<u8>) {
        let Some(v) = self.viewers.get_mut(&viewer) else {
            return;
        };
        if let Some(s) = &self.sharer {
            self.bytes_to_sharer = self.bytes_to_sharer.saturating_add(payload.len() as u64);
            s.send(Out::Binary(encode_routed(viewer, &payload)));
            return;
        }
        let limit = self.hub.config.limits.away_buffer_bytes;
        match v.pending_bytes.checked_add(payload.len()) {
            Some(total) if total <= limit => {
                v.pending_bytes = total;
                v.pending.push(payload);
            }
            _ => {
                if let Some(v) = self.viewers.remove(&viewer) {
                    v.conn
                        .close(close::AWAY_BUFFER_FULL, "sharing computer unreachable");
                    self.after_viewer_left(viewer, None);
                }
            }
        }
    }

    fn remove_viewer(&mut self, viewer: u32, notice: &RelayToViewer) {
        if let Some(v) = self.viewers.remove(&viewer) {
            v.conn.text(notice);
            v.conn.close(close::NORMAL, "removed by sharer");
            self.after_viewer_left(viewer, None);
        }
    }

    fn after_viewer_left(&mut self, viewer: u32, tell_sharer: Option<LeftReason>) {
        if let (Some(reason), Some(s)) = (tell_sharer, &self.sharer) {
            s.text(&RelayToSharer::Left { viewer, reason });
        }
        if self.viewers.is_empty() {
            self.no_viewers_since = Some(Instant::now());
        }
    }

    fn broadcast(&self, msg: &RelayToViewer) {
        for v in self.viewers.values() {
            v.conn.text(msg);
        }
    }

    fn end(self, reason: EndReason) {
        self.broadcast(&RelayToViewer::Ended { reason });
        for v in self.viewers.values() {
            v.conn.close(close::NORMAL, "share ended");
        }
        if let Some(s) = &self.sharer {
            s.text(&RelayToSharer::Ended { reason });
            s.close(close::NORMAL, "share ended");
        }
        let tombstone_until = self
            .deadline
            .max(Instant::now() + self.hub.config.timings.sharer_offline);
        self.hub.remove(&self.id, self.token, tombstone_until);
        info!(
            share = %self.id.log_tag(),
            reason = ?reason,
            bytes_to_viewers = self.bytes_to_viewers,
            bytes_to_sharer = self.bytes_to_sharer,
            "share ended"
        );
    }
}

#[derive(Debug, Clone, Copy)]
enum Timer {
    Expiry,
    Away,
    Offline,
    NoViewers,
}
