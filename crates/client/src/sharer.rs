//! Sans-IO engine for the sharing side.
//!
//! Feed it what the relay sends and what the terminal prints; it returns
//! [`Action`]s: messages to send to the relay and decisions the host must
//! make (join approvals, input to inject). It is the reference for the
//! sharing side PlexusTerm builds on top of it.

use std::collections::{BTreeMap, HashMap, HashSet};

use plexusterm_share_protocol::content::{
    Access, ClientId, Content, SnapshotPart, Status, ViewerHello, Welcome,
};
use plexusterm_share_protocol::frame::{
    Binding, Direction, KIND_FRAME, KIND_HANDSHAKE, Opener, Sealer,
};
use plexusterm_share_protocol::keys::{Challenge, DerivedKeys, LinkId, Role, Secret, ShareId};
use plexusterm_share_protocol::link::share_url;
use plexusterm_share_protocol::noise::PendingViewer;
use plexusterm_share_protocol::wire::{
    EndReason, ErrorCode, LinkRegistration, RelayToSharer, SharerToRelay, ViewerInfo,
    decode_routed, encode_routed,
};
use plexusterm_share_protocol::{PROTOCOL_VERSION, ProtocolError};

use crate::snapshot::{OutputLog, chunk};

/// Reconnect buffer size (PRD §5.4).
pub const RESUME_BUFFER_BYTES: usize = 1024 * 1024;

pub struct SharerConfig {
    pub token: String,
    pub expires_at: u64,
    /// One link per entry; usually `[View]` or `[View, Type]`.
    pub accesses: Vec<Access>,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Send this text message to the relay.
    Text(String),
    /// Send this binary message to the relay.
    Binary(Vec<u8>),
    /// The share is live; links are ready to show.
    Ready {
        expires_at: u64,
    },
    /// Ask the sharer: Allow → [`SharerEngine::approve`], Deny →
    /// [`SharerEngine::deny`].
    JoinRequest {
        viewer: u32,
        access: Access,
        ip: String,
        ua: String,
    },
    /// A known viewer came back; no approval needed and not a new viewer.
    Rejoined {
        viewer: u32,
    },
    /// Inject these bytes into the terminal, like typed keys.
    Input {
        viewer: u32,
        data: Vec<u8>,
    },
    ViewerLeft {
        viewer: u32,
    },
    /// A frame failed authentication or replay checks and was dropped.
    Dropped {
        viewer: u32,
        error: ProtocolError,
    },
    /// A link was replaced; show the new one.
    LinkRotated {
        access: Access,
        url_secret: Secret,
    },
    /// Asynchronous snapshots only: serialize the terminal and answer with
    /// [`SharerEngine::snapshot_ready`]. Output for this viewer is held
    /// until then.
    SnapshotRequest {
        viewer: u32,
    },
    /// The relay confirmed a new end time (after [`SharerEngine::set_expiry`]).
    ExpiryChanged {
        expires_at: u64,
    },
    /// The relay ended the share.
    Ended {
        reason: EndReason,
    },
    /// The relay refused the share or a message; the connection closes.
    Refused {
        code: ErrorCode,
    },
}

struct Link {
    secret: Secret,
    keys: DerivedKeys,
    access: Access,
}

#[allow(
    clippy::large_enum_variant,
    reason = "the live variant holds two AES-GCM key schedules; at most a few exist and the hot path uses them in place"
)]
enum Slot {
    /// Relay announced the viewer; waiting for Noise message 1.
    Announced(ViewerInfo),
    /// Message 1 valid; waiting for the sharer's decision.
    Pending {
        info: ViewerInfo,
        pending: Box<PendingViewer>,
        hello: ViewerHello,
        access: Access,
    },
    Live(Live),
}

struct Live {
    client: ClientId,
    link_id: LinkId,
    access: Access,
    /// Lowest output number this client may resume from: the `covers_seq`
    /// of the last snapshot it was sent. Below it lies history the sharer
    /// did not choose to share (PRD §4.1: it may contain secrets).
    floor: u64,
    /// An asynchronous snapshot was requested and not delivered yet: live
    /// output is not sent; it follows the snapshot from the buffer.
    awaiting_snapshot: bool,
    sealer: Sealer,
    opener: Opener,
}

#[derive(Clone, Copy)]
struct Grant {
    link_id: LinkId,
    floor: u64,
}

/// No snapshot sent yet: every resume request is refused.
const NO_FLOOR: u64 = u64::MAX;

pub struct SharerEngine {
    share_id: ShareId,
    owner: Secret,
    token: String,
    expires_at: u64,
    links: Vec<Link>,
    attached: bool,
    slots: BTreeMap<u32, Slot>,
    /// Clients approved before, so reconnects skip approval and may resume.
    approved: HashMap<ClientId, Grant>,
    banned: HashSet<ClientId>,
    log: OutputLog,
    cols: u16,
    rows: u16,
    snapshot_source: Option<SnapshotSource>,
    async_snapshots: bool,
    input_paused: bool,
}

/// A serialized terminal (`@xterm/addon-serialize` output in PlexusTerm).
pub struct Snapshot {
    /// Visible screen only, sent first so viewers paint at once. `None`
    /// when the history choice is "Current screen only".
    pub screen: Option<Vec<u8>>,
    /// History and screen.
    pub full: Vec<u8>,
}

/// Called when a viewer needs a snapshot. It must serialize the terminal
/// with exactly the output already passed to [`SharerEngine::output`].
pub type SnapshotSource = Box<dyn FnMut() -> Snapshot + Send>;

impl SharerEngine {
    pub fn new(config: SharerConfig) -> Self {
        let links = config
            .accesses
            .iter()
            .map(|&access| {
                let secret = Secret::random();
                Link {
                    keys: DerivedKeys::derive(&secret),
                    secret,
                    access,
                }
            })
            .collect();
        Self {
            share_id: ShareId::random(),
            owner: Secret::random(),
            token: config.token,
            expires_at: config.expires_at,
            links,
            attached: false,
            slots: BTreeMap::new(),
            approved: HashMap::new(),
            banned: HashSet::new(),
            log: OutputLog::new(RESUME_BUFFER_BYTES),
            cols: config.cols,
            rows: config.rows,
            snapshot_source: None,
            async_snapshots: false,
            input_paused: false,
        }
    }

    /// Without a source the engine replays its 1 MB output buffer as the
    /// snapshot, which is what the demo sharer does.
    pub fn set_snapshot_source(&mut self, source: SnapshotSource) {
        self.snapshot_source = Some(source);
    }

    /// For hosts whose terminal state lives elsewhere (PlexusTerm: xterm in
    /// the webview). When a viewer needs a snapshot the engine returns
    /// [`Action::SnapshotRequest`] and holds that viewer's output; the host
    /// serializes and answers with [`SharerEngine::snapshot_ready`].
    pub fn set_async_snapshots(&mut self, on: bool) {
        self.async_snapshots = on;
    }

    /// Number of the last output passed to [`SharerEngine::output`]. Tag
    /// what the terminal renders with it, so a snapshot can say which
    /// output it covers.
    pub fn last_seq(&self) -> u64 {
        self.log.last_seq()
    }

    /// Delivers an asynchronous snapshot of the terminal as it was after
    /// output number `covers_seq`. The engine sends it, then the output
    /// after `covers_seq` from its buffer. If that output is no longer
    /// buffered, or `covers_seq` is ahead of the output passed so far, it
    /// asks again with [`Action::SnapshotRequest`].
    pub fn snapshot_ready(
        &mut self,
        viewer: u32,
        covers_seq: u64,
        snapshot: Snapshot,
    ) -> Vec<Action> {
        let Some(Slot::Live(mut live)) = self.slots.remove(&viewer) else {
            return Vec::new();
        };
        let actions = if !live.awaiting_snapshot {
            Vec::new()
        } else {
            match (covers_seq <= self.log.last_seq())
                .then(|| self.log.since(covers_seq))
                .flatten()
            {
                None => vec![Action::SnapshotRequest { viewer }],
                Some(after) => {
                    live.awaiting_snapshot = false;
                    let mut actions = self.send_snapshot(viewer, &mut live, covers_seq, snapshot);
                    actions.extend(after.into_iter().flat_map(|(seq, data)| {
                        seal(viewer, &mut live, &Content::Output { seq, data })
                    }));
                    actions
                }
            }
        };
        self.slots.insert(viewer, Slot::Live(live));
        actions
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Extend or shorten the share (Unix seconds, at most 12 h ahead on the
    /// relay's clock). The relay confirms with [`Action::ExpiryChanged`] and
    /// tells the viewers; a refused value ends with [`Action::Refused`].
    pub fn set_expiry(&mut self, expires_at: u64) -> Vec<Action> {
        vec![text(&SharerToRelay::SetExpiry { expires_at })]
    }

    /// The shared program exited: viewers see "The shared program exited",
    /// then the share ends.
    pub fn program_exited(&mut self) -> Vec<Action> {
        let mut actions = self.broadcast(&Content::Status(Status {
            program_exited: Some(true),
            ..Status::default()
        }));
        actions.extend(self.end());
        actions
    }

    /// Pause viewer input: viewers are told, and viewers who join while
    /// paused are told at once. Holding the input itself is the host's job
    /// (it already holds input for the sharer's own typing).
    pub fn pause_input(&mut self, paused: bool) -> Vec<Action> {
        self.input_paused = paused;
        self.broadcast(&Content::Status(Status {
            input_paused: Some(paused),
            ..Status::default()
        }))
    }

    fn broadcast(&mut self, content: &Content) -> Vec<Action> {
        let mut actions = Vec::new();
        for (id, slot) in &mut self.slots {
            if let Slot::Live(live) = slot {
                actions.extend(seal(*id, live, content));
            }
        }
        actions
    }

    pub fn share_id(&self) -> ShareId {
        self.share_id
    }

    /// Links to show, one per access.
    pub fn links(&self, viewer_origin: &str) -> Vec<(Access, String)> {
        self.links
            .iter()
            .map(|l| {
                (
                    l.access,
                    share_url(viewer_origin, &self.share_id, &l.secret),
                )
            })
            .collect()
    }

    pub fn viewer_count(&self) -> usize {
        self.slots
            .values()
            .filter(|s| matches!(s, Slot::Live(_)))
            .count()
    }

    /// Call when a new relay connection opens: the next `hello` will be
    /// answered with `resume` once the share was created.
    pub fn connection_lost(&mut self) {
        // Pending and announced viewers must start over; live sessions
        // keep their keys (they do not depend on the relay connection).
        self.slots.retain(|_, s| matches!(s, Slot::Live(_)));
    }

    pub fn on_text(&mut self, text: &str) -> Vec<Action> {
        let Ok(msg) = serde_json::from_str::<RelayToSharer>(text) else {
            return Vec::new();
        };
        match msg {
            RelayToSharer::Hello(hello) => vec![self.answer_hello(hello.challenge)],
            RelayToSharer::Ready {
                expires_at,
                viewers,
            } => {
                self.attached = true;
                self.expires_at = expires_at;
                let present: HashSet<u32> = viewers.iter().map(|v| v.viewer).collect();
                self.slots.retain(|id, _| present.contains(id));
                let actions = vec![Action::Ready { expires_at }];
                for info in viewers {
                    self.slots
                        .entry(info.viewer)
                        .or_insert(Slot::Announced(info));
                }
                actions
            }
            RelayToSharer::Join(info) => {
                self.slots.insert(info.viewer, Slot::Announced(info));
                Vec::new()
            }
            RelayToSharer::Left { viewer, .. } => {
                self.slots.remove(&viewer);
                vec![Action::ViewerLeft { viewer }]
            }
            RelayToSharer::Expiry { expires_at } => {
                self.expires_at = expires_at;
                vec![Action::ExpiryChanged { expires_at }]
            }
            RelayToSharer::Pong => Vec::new(),
            RelayToSharer::Ended { reason } => vec![Action::Ended { reason }],
            RelayToSharer::Error { code, .. } => vec![Action::Refused { code }],
        }
    }

    fn answer_hello(&self, challenge: Challenge) -> Action {
        let msg = if self.attached {
            SharerToRelay::Resume {
                proto: PROTOCOL_VERSION,
                token: self.token.clone(),
                share_id: self.share_id,
                owner_proof: DerivedKeys::derive(&self.owner).prove(
                    Role::Owner,
                    &self.share_id,
                    &challenge,
                ),
            }
        } else {
            SharerToRelay::Create {
                proto: PROTOCOL_VERSION,
                token: self.token.clone(),
                share_id: self.share_id,
                owner_verifier: DerivedKeys::derive(&self.owner).verifier(),
                links: self
                    .links
                    .iter()
                    .map(|l| LinkRegistration {
                        link_id: l.keys.link_id,
                        verifier: l.keys.verifier(),
                    })
                    .collect(),
                expires_at: self.expires_at,
            }
        };
        text(&msg)
    }

    pub fn on_binary(&mut self, message: &[u8]) -> Vec<Action> {
        let Ok((viewer, payload)) = decode_routed(message) else {
            return Vec::new();
        };
        match (self.slots.remove(&viewer), payload.first()) {
            (Some(Slot::Announced(info)), Some(&KIND_HANDSHAKE)) => self.on_hello(info, payload),
            (Some(Slot::Live(mut live)), Some(&KIND_FRAME)) => {
                let actions = self.on_frame(viewer, &mut live, payload);
                self.slots.insert(viewer, Slot::Live(live));
                actions
            }
            (Some(slot), _) => {
                self.slots.insert(viewer, slot);
                vec![Action::Dropped {
                    viewer,
                    error: ProtocolError::Malformed,
                }]
            }
            (None, _) => Vec::new(),
        }
    }

    fn on_hello(&mut self, info: ViewerInfo, payload: &[u8]) -> Vec<Action> {
        let viewer = info.viewer;
        let Some(link) = self.links.iter().find(|l| l.keys.link_id == info.link_id) else {
            return vec![deny(viewer)];
        };
        let access = link.access;
        let accepted = PendingViewer::accept(&self.share_id, &link.keys.psk, payload)
            .ok()
            .and_then(|(p, body)| Some((p, serde_json::from_slice::<ViewerHello>(&body).ok()?)));
        let Some((pending, hello)) = accepted else {
            return vec![deny(viewer)];
        };
        if self.banned.contains(&hello.client) {
            return vec![deny(viewer)];
        }
        let known = self.approved.get(&hello.client).map(|g| g.link_id) == Some(info.link_id);
        let (ip, ua) = (info.ip.clone(), info.ua.clone());
        self.slots.insert(
            viewer,
            Slot::Pending {
                info,
                pending: Box::new(pending),
                hello,
                access,
            },
        );
        if known {
            let mut actions = vec![Action::Rejoined { viewer }];
            actions.extend(self.approve(viewer));
            actions
        } else {
            vec![Action::JoinRequest {
                viewer,
                access,
                ip,
                ua,
            }]
        }
    }

    /// Allow a pending viewer: completes the handshake and sends it the
    /// snapshot or the output it missed.
    pub fn approve(&mut self, viewer: u32) -> Vec<Action> {
        let Some(Slot::Pending {
            info,
            pending,
            hello,
            access,
        }) = self.slots.remove(&viewer)
        else {
            return Vec::new();
        };
        let welcome = Welcome {
            access,
            cols: self.cols,
            rows: self.rows,
        };
        // Welcome is a small struct of plain fields; JSON cannot fail.
        let body = serde_json::to_vec(&welcome).unwrap_or_default();
        let Ok((keys, msg2)) = pending.respond(&body) else {
            return vec![deny(viewer)];
        };
        // A reconnecting client keeps its floor; a new one has none, so its
        // `resume_from` is ignored and it gets the snapshot.
        let floor = match self.approved.get(&hello.client) {
            Some(g) if g.link_id == info.link_id => g.floor,
            _ => NO_FLOOR,
        };
        self.approved.insert(
            hello.client,
            Grant {
                link_id: info.link_id,
                floor,
            },
        );
        let mut live = Live {
            client: hello.client,
            link_id: info.link_id,
            access,
            floor,
            awaiting_snapshot: false,
            sealer: Sealer::new(&keys.to_viewer, self.binding(viewer, Direction::ToViewer)),
            opener: Opener::new(&keys.to_sharer, self.binding(viewer, Direction::ToSharer)),
        };
        let mut actions = vec![Action::Binary(encode_routed(viewer, &msg2))];
        actions.extend(self.catch_up(viewer, &mut live, hello.resume_from));
        if self.input_paused {
            let paused = Content::Status(Status {
                input_paused: Some(true),
                ..Status::default()
            });
            actions.extend(seal(viewer, &mut live, &paused));
        }
        self.slots.insert(viewer, Slot::Live(live));
        actions
    }

    pub fn deny(&mut self, viewer: u32) -> Vec<Action> {
        self.slots.remove(&viewer);
        vec![deny(viewer)]
    }

    /// Disconnect: rotate the viewer's link first, then kick it, so its old
    /// secret is dead before it learns it was removed. Returns the new link.
    pub fn kick(&mut self, viewer: u32) -> Vec<Action> {
        let Some(Slot::Live(live)) = self.slots.remove(&viewer) else {
            return self.deny(viewer);
        };
        self.banned.insert(live.client);
        let mut rotated = None;
        if let Some(link) = self
            .links
            .iter_mut()
            .find(|l| l.keys.link_id == live.link_id)
        {
            let secret = Secret::random();
            let keys = DerivedKeys::derive(&secret);
            rotated = Some((
                text(&SharerToRelay::Rotate {
                    link_id: link.keys.link_id,
                    new: LinkRegistration {
                        link_id: keys.link_id,
                        verifier: keys.verifier(),
                    },
                }),
                Action::LinkRotated {
                    access: link.access,
                    url_secret: secret,
                },
            ));
            *link = Link {
                secret,
                keys,
                access: link.access,
            };
        }
        let kick = text(&SharerToRelay::Kick { viewer });
        match rotated {
            Some((rotate, shown)) => vec![rotate, kick, shown],
            None => vec![kick],
        }
    }

    /// Can type → View only for every viewer and link (PRD §4.1.5).
    pub fn downgrade_to_view(&mut self) -> Vec<Action> {
        let status = Content::Status(Status {
            access: Some(Access::View),
            ..Status::default()
        });
        let mut actions = Vec::new();
        for (id, slot) in &mut self.slots {
            match slot {
                Slot::Live(live) if live.access == Access::Type => {
                    live.access = Access::View;
                    actions.extend(seal(*id, live, &status));
                }
                // A join request still waiting for an answer is approved as
                // View only.
                Slot::Pending { access, .. } => *access = Access::View,
                _ => {}
            }
        }
        for link in &mut self.links {
            link.access = Access::View;
        }
        actions
    }

    pub fn end(&self) -> Vec<Action> {
        vec![text(&SharerToRelay::End)]
    }

    pub fn ping(&self) -> Action {
        text(&SharerToRelay::Ping)
    }

    /// Terminal output: numbered once, encrypted per live viewer.
    pub fn output(&mut self, data: &[u8]) -> Vec<Action> {
        let added = self.log.push(data);
        let mut actions = Vec::new();
        for (id, slot) in &mut self.slots {
            if let Slot::Live(live) = slot
                && !live.awaiting_snapshot
            {
                for (seq, piece) in &added {
                    actions.extend(seal(
                        *id,
                        live,
                        &Content::Output {
                            seq: *seq,
                            data: piece.clone(),
                        },
                    ));
                }
            }
        }
        actions
    }

    pub fn resize(&mut self, cols: u16, rows: u16) -> Vec<Action> {
        self.cols = cols;
        self.rows = rows;
        let size = Content::Size { cols, rows };
        let mut actions = Vec::new();
        for (id, slot) in &mut self.slots {
            if let Slot::Live(live) = slot {
                actions.extend(seal(*id, live, &size));
            }
        }
        actions
    }

    fn on_frame(&mut self, viewer: u32, live: &mut Live, frame: &[u8]) -> Vec<Action> {
        let plaintext = match live.opener.open(frame) {
            Ok(p) => p,
            Err(error) => return vec![Action::Dropped { viewer, error }],
        };
        match Content::decode(&plaintext) {
            Ok(Content::Input { data }) if live.access == Access::Type => {
                vec![Action::Input { viewer, data }]
            }
            Ok(Content::Input { .. }) => vec![Action::Dropped {
                viewer,
                error: ProtocolError::Auth,
            }],
            Ok(Content::Resync { last_seq }) => self.catch_up(viewer, live, last_seq),
            _ => vec![Action::Dropped {
                viewer,
                error: ProtocolError::Malformed,
            }],
        }
    }

    /// Sends what the viewer missed after `resume_from`, or a snapshot when
    /// that is not possible or not allowed. `resume_from` comes from the
    /// viewer, so it is honored only from the client's floor up.
    fn catch_up(&mut self, viewer: u32, live: &mut Live, resume_from: Option<u64>) -> Vec<Action> {
        let allowed = resume_from.filter(|n| live.floor != NO_FLOOR && *n >= live.floor);
        if let Some(missed) = allowed.and_then(|n| self.log.since(n)) {
            return missed
                .into_iter()
                .flat_map(|(seq, data)| seal(viewer, live, &Content::Output { seq, data }))
                .collect();
        }
        if self.async_snapshots {
            live.awaiting_snapshot = true;
            return vec![Action::SnapshotRequest { viewer }];
        }
        let snapshot = match &mut self.snapshot_source {
            Some(source) => source(),
            None => Snapshot {
                screen: None,
                full: self.log.contents(),
            },
        };
        let covers = self.log.last_seq();
        self.send_snapshot(viewer, live, covers, snapshot)
    }

    /// Sends a snapshot covering output `covers` and records it as the
    /// client's resume floor.
    fn send_snapshot(
        &mut self,
        viewer: u32,
        live: &mut Live,
        covers: u64,
        snapshot: Snapshot,
    ) -> Vec<Action> {
        live.floor = covers;
        if let Some(grant) = self.approved.get_mut(&live.client) {
            grant.floor = covers;
        }
        let (cols, rows) = (self.cols, self.rows);
        let mut frames = Vec::new();
        if let Some(screen) = snapshot.screen {
            frames.extend(chunk(&screen, covers, cols, rows, SnapshotPart::Screen));
        }
        frames.extend(chunk(
            &snapshot.full,
            covers,
            cols,
            rows,
            SnapshotPart::Full,
        ));
        frames.iter().flat_map(|c| seal(viewer, live, c)).collect()
    }

    fn binding(&self, viewer_id: u32, direction: Direction) -> Binding {
        Binding {
            share_id: self.share_id,
            viewer_id,
            direction,
        }
    }
}

fn seal(viewer: u32, live: &mut Live, content: &Content) -> Option<Action> {
    live.sealer
        .seal(&content.encode())
        .ok()
        .map(|frame| Action::Binary(encode_routed(viewer, &frame)))
}

fn text(msg: &SharerToRelay) -> Action {
    // Wire messages hold only strings, numbers and byte strings.
    Action::Text(serde_json::to_string(msg).unwrap_or_default())
}

fn deny(viewer: u32) -> Action {
    text(&SharerToRelay::Deny { viewer })
}
