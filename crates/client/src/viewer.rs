//! Sans-IO engine for a viewer. The web viewer's TypeScript client mirrors
//! this logic; PlexusTerm as viewer (P3) can use it directly.

use plexusterm_share_protocol::PROTOCOL_VERSION;
use plexusterm_share_protocol::content::{
    Access, ClientId, Content, SnapshotPart, ViewerHello, Welcome,
};
use plexusterm_share_protocol::frame::{Binding, Direction, Opener, Sealer};
use plexusterm_share_protocol::keys::{DerivedKeys, Role, Secret, ShareId};
use plexusterm_share_protocol::noise::ViewerHandshake;
use plexusterm_share_protocol::wire::{EndReason, ErrorCode, RelayToViewer, ViewerToRelay};

use crate::snapshot::Assembly;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Proof accepted; waiting for the sharer to let us in.
    Waiting,
    Joined {
        access: Access,
        cols: u16,
        rows: u16,
    },
    /// Clear the terminal before the next write.
    Reset,
    /// Write these bytes to the terminal.
    Write(Vec<u8>),
    Resized {
        cols: u16,
        rows: u16,
    },
    AccessChanged(Access),
    InputPaused(bool),
    SharerAway,
    SharerBack,
    Expiry(u64),
    Denied,
    Kicked,
    Ended(EndReason),
    Refused(ErrorCode),
    /// A frame failed authentication or replay checks and was dropped.
    Dropped,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Text(String),
    Binary(Vec<u8>),
    Event(Event),
}

/// Output with its sequence number, in arrival order.
type Numbered = Vec<(u64, Vec<u8>)>;

#[allow(
    clippy::large_enum_variant,
    reason = "the live variant holds two AES-GCM key schedules; at most a few exist and the hot path uses them in place"
)]
enum State {
    Connecting,
    Joining,
    Handshaking(Box<ViewerHandshake>),
    Live {
        access: Access,
        sealer: Sealer,
        opener: Opener,
    },
    /// Final: denied, kicked, ended or refused. Do not reconnect.
    Done,
}

pub struct ViewerEngine {
    share_id: ShareId,
    keys: DerivedKeys,
    client: ClientId,
    viewer_id: u32,
    state: State,
    /// Last output sequence number written to the terminal.
    last_seq: Option<u64>,
    assembly: Assembly,
    /// Snapshot incomplete: live output waits in `held`.
    holding: bool,
    held: Numbered,
}

impl ViewerEngine {
    pub fn new(share_id: ShareId, secret: &Secret, client: ClientId) -> Self {
        Self {
            share_id,
            keys: DerivedKeys::derive(secret),
            client,
            viewer_id: 0,
            state: State::Connecting,
            last_seq: None,
            assembly: Assembly::default(),
            holding: false,
            held: Vec::new(),
        }
    }

    /// The relay connection dropped. Returns `false` when the outcome is
    /// final and the viewer must not reconnect.
    pub fn connection_lost(&mut self) -> bool {
        if matches!(self.state, State::Done) {
            return false;
        }
        self.state = State::Connecting;
        self.assembly = Assembly::default();
        self.holding = false;
        self.held.clear();
        true
    }

    pub fn is_live(&self) -> bool {
        matches!(self.state, State::Live { .. })
    }

    pub fn last_seq(&self) -> Option<u64> {
        self.last_seq
    }

    pub fn on_text(&mut self, text: &str) -> Vec<Action> {
        let Ok(msg) = serde_json::from_str::<RelayToViewer>(text) else {
            return Vec::new();
        };
        match msg {
            RelayToViewer::Hello(hello) => {
                self.state = State::Joining;
                vec![json(&ViewerToRelay::Join {
                    proto: PROTOCOL_VERSION,
                    share_id: self.share_id,
                    link_id: self.keys.link_id,
                    proof: self
                        .keys
                        .prove(Role::Viewer, &self.share_id, &hello.challenge),
                })]
            }
            RelayToViewer::Accepted { viewer, .. } => {
                self.viewer_id = viewer;
                let hello = ViewerHello {
                    client: self.client,
                    resume_from: self.last_seq,
                };
                // ViewerHello is plain fields; JSON cannot fail.
                let body = serde_json::to_vec(&hello).unwrap_or_default();
                match ViewerHandshake::start(&self.share_id, &self.keys.psk, &body) {
                    Ok((hs, msg1)) => {
                        self.state = State::Handshaking(Box::new(hs));
                        vec![Action::Binary(msg1), Action::Event(Event::Waiting)]
                    }
                    Err(_) => self.finish(Event::Refused(ErrorCode::BadRequest)),
                }
            }
            RelayToViewer::SharerAway => vec![Action::Event(Event::SharerAway)],
            RelayToViewer::SharerBack => {
                let mut actions = vec![Action::Event(Event::SharerBack)];
                let resync = Content::Resync {
                    last_seq: self.last_seq,
                };
                actions.extend(self.seal(&resync));
                actions
            }
            RelayToViewer::Expiry { expires_at } => vec![Action::Event(Event::Expiry(expires_at))],
            RelayToViewer::Denied => self.finish(Event::Denied),
            RelayToViewer::Kicked => self.finish(Event::Kicked),
            RelayToViewer::Ended { reason } => self.finish(Event::Ended(reason)),
            RelayToViewer::Error { code, .. } => self.finish(Event::Refused(code)),
            RelayToViewer::Pong => Vec::new(),
        }
    }

    fn finish(&mut self, event: Event) -> Vec<Action> {
        self.state = State::Done;
        vec![Action::Event(event)]
    }

    pub fn on_binary(&mut self, message: &[u8]) -> Vec<Action> {
        match std::mem::replace(&mut self.state, State::Connecting) {
            State::Handshaking(hs) => self.on_welcome(hs, message),
            State::Live {
                access,
                sealer,
                mut opener,
            } => {
                let opened = opener.open(message);
                self.state = State::Live {
                    access,
                    sealer,
                    opener,
                };
                match opened.ok().and_then(|p| Content::decode(&p).ok()) {
                    Some(content) => self.on_content(content),
                    None => vec![Action::Event(Event::Dropped)],
                }
            }
            other => {
                self.state = other;
                vec![Action::Event(Event::Dropped)]
            }
        }
    }

    fn on_welcome(&mut self, hs: Box<ViewerHandshake>, message: &[u8]) -> Vec<Action> {
        let Ok((keys, body)) = hs.finish(message) else {
            return self.finish(Event::Refused(ErrorCode::BadKey));
        };
        let Ok(welcome) = serde_json::from_slice::<Welcome>(&body) else {
            return self.finish(Event::Refused(ErrorCode::BadRequest));
        };
        let binding = |direction| Binding {
            share_id: self.share_id,
            viewer_id: self.viewer_id,
            direction,
        };
        self.state = State::Live {
            access: welcome.access,
            sealer: Sealer::new(&keys.to_sharer, binding(Direction::ToSharer)),
            opener: Opener::new(&keys.to_viewer, binding(Direction::ToViewer)),
        };
        // A new viewer always gets a snapshot first; hold live output until
        // it is written.
        self.holding = self.last_seq.is_none();
        vec![Action::Event(Event::Joined {
            access: welcome.access,
            cols: welcome.cols,
            rows: welcome.rows,
        })]
    }

    fn on_content(&mut self, content: Content) -> Vec<Action> {
        match content {
            Content::Output { seq, data } => self.on_output(seq, data),
            snapshot @ Content::Snapshot { .. } => match self.assembly.add(snapshot) {
                Ok(Some(done)) => self.on_snapshot(done),
                Ok(None) => {
                    self.holding = true;
                    Vec::new()
                }
                Err(_) => vec![Action::Event(Event::Dropped)],
            },
            Content::Status(status) => {
                let mut actions = Vec::new();
                if let Some(access) = status.access {
                    if let State::Live { access: a, .. } = &mut self.state {
                        *a = access;
                    }
                    actions.push(Action::Event(Event::AccessChanged(access)));
                }
                if let Some(paused) = status.input_paused {
                    actions.push(Action::Event(Event::InputPaused(paused)));
                }
                actions
            }
            Content::Size { cols, rows } => vec![Action::Event(Event::Resized { cols, rows })],
            Content::Input { .. } | Content::Resync { .. } => vec![Action::Event(Event::Dropped)],
        }
    }

    fn on_output(&mut self, seq: u64, data: Vec<u8>) -> Vec<Action> {
        if self.holding {
            self.held.push((seq, data));
            return Vec::new();
        }
        if self.last_seq.is_some_and(|last| seq <= last) {
            return Vec::new();
        }
        self.last_seq = Some(seq);
        vec![Action::Event(Event::Write(data))]
    }

    fn on_snapshot(&mut self, done: crate::snapshot::Completed) -> Vec<Action> {
        let mut actions = vec![
            Action::Event(Event::Reset),
            Action::Event(Event::Resized {
                cols: done.cols,
                rows: done.rows,
            }),
            Action::Event(Event::Write(done.bytes)),
        ];
        self.last_seq = Some(done.covers_seq);
        // A screen part is followed by its full part before any later
        // output, so keep holding until the full part is written.
        self.holding = done.part == SnapshotPart::Screen;
        if !self.holding {
            let mut held = std::mem::take(&mut self.held);
            held.sort_by_key(|(seq, _)| *seq);
            for (seq, data) in held {
                actions.extend(self.on_output(seq, data));
            }
        }
        actions
    }

    /// Encrypts one key event or paste; `None` when typing is not allowed.
    pub fn input(&mut self, data: &[u8]) -> Option<Action> {
        match &self.state {
            State::Live {
                access: Access::Type,
                ..
            } => self.seal(&Content::Input {
                data: data.to_vec(),
            }),
            _ => None,
        }
    }

    pub fn ping(&self) -> Action {
        json(&ViewerToRelay::Ping)
    }

    fn seal(&mut self, content: &Content) -> Option<Action> {
        match &mut self.state {
            State::Live { sealer, .. } => sealer.seal(&content.encode()).ok().map(Action::Binary),
            _ => None,
        }
    }
}

fn json(msg: &ViewerToRelay) -> Action {
    Action::Text(serde_json::to_string(msg).unwrap_or_default())
}
