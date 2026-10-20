//! End-to-end: sharer engine ⇄ real relay ⇄ viewer engines (PRD §8 tests).

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use plexusterm_relay::{Config, Limits, Timings, serve};
use plexusterm_share_client::sharer::{self, SharerConfig, SharerEngine};
use plexusterm_share_client::viewer::{self, Event, ViewerEngine};
use plexusterm_share_protocol::content::{Access, ClientId};
use plexusterm_share_protocol::keys::Secret;
use plexusterm_share_protocol::link::parse_share_url;
use plexusterm_share_protocol::wire::ErrorCode;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

const TOKEN: &str = "e2e-token-0123456789";
const WAIT: Duration = Duration::from_secs(5);
const MARKER: &[u8] = b"MARKER-5d1e-visible-only-end-to-end";

async fn relay() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = Config {
        listen: addr,
        tokens: vec![TOKEN.into()],
        trust_proxy: false,
        limits: Limits::default(),
        timings: Timings {
            sharer_away: Duration::from_millis(200),
            ..Timings::default()
        },
    };
    tokio::spawn(serve(listener, config));
    addr
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Everything the relay delivered to a party, for frame inspection.
#[derive(Default)]
struct Capture(Vec<Vec<u8>>);

impl Capture {
    fn contains(&self, needle: &[u8]) -> bool {
        self.0
            .iter()
            .any(|m| m.windows(needle.len()).any(|w| w == needle))
    }
}

struct Sharer {
    engine: SharerEngine,
    ws: Ws,
    received: Capture,
}

impl Sharer {
    async fn start(addr: SocketAddr, accesses: Vec<Access>) -> Self {
        let engine = SharerEngine::new(SharerConfig {
            token: TOKEN.into(),
            expires_at: now() + 3600,
            accesses,
            cols: 80,
            rows: 24,
        });
        let mut s = Self::attach(addr, engine).await;
        s.until(|a| matches!(a, sharer::Action::Ready { .. })).await;
        s
    }

    async fn attach(addr: SocketAddr, engine: SharerEngine) -> Self {
        let (ws, _) = connect_async(format!("ws://{addr}/v1/sharer"))
            .await
            .unwrap();
        Self {
            engine,
            ws,
            received: Capture::default(),
        }
    }

    fn link(&self, access: Access) -> (plexusterm_share_protocol::keys::ShareId, Secret) {
        let (_, url) = self
            .engine
            .links("https://view.test")
            .into_iter()
            .find(|(a, _)| *a == access)
            .unwrap();
        let parsed = parse_share_url(&url).unwrap();
        (parsed.share_id, parsed.secret.unwrap())
    }

    /// Sends what must go to the relay, returns the rest.
    async fn apply(&mut self, actions: Vec<sharer::Action>) -> Vec<sharer::Action> {
        let mut rest = Vec::new();
        for a in actions {
            match a {
                sharer::Action::Text(t) => self.ws.send(Message::Text(t.into())).await.unwrap(),
                sharer::Action::Binary(b) => {
                    self.ws.send(Message::Binary(b.into())).await.unwrap();
                }
                other => rest.push(other),
            }
        }
        rest
    }

    async fn until(&mut self, pred: impl Fn(&sharer::Action) -> bool) -> sharer::Action {
        loop {
            let msg = tokio::time::timeout(WAIT, self.ws.next())
                .await
                .expect("sharer timed out")
                .expect("sharer connection closed")
                .unwrap();
            let actions = match msg {
                Message::Text(t) => self.engine.on_text(&t),
                Message::Binary(b) => {
                    self.received.0.push(b.to_vec());
                    self.engine.on_binary(&b)
                }
                _ => continue,
            };
            if let Some(a) = self.apply(actions).await.into_iter().find(&pred) {
                return a;
            }
        }
    }

    /// Handles one relay message (e.g. a viewer's `Resync`).
    async fn pump(&mut self) {
        let msg = tokio::time::timeout(WAIT, self.ws.next())
            .await
            .expect("sharer timed out")
            .expect("sharer connection closed")
            .unwrap();
        let actions = match msg {
            Message::Text(t) => self.engine.on_text(&t),
            Message::Binary(b) => self.engine.on_binary(&b),
            _ => return,
        };
        assert!(self.apply(actions).await.is_empty());
    }

    async fn output(&mut self, data: &[u8]) {
        let actions = self.engine.output(data);
        assert!(self.apply(actions).await.is_empty());
    }
}

struct Viewer {
    engine: ViewerEngine,
    ws: Ws,
    received: Capture,
    sent: Capture,
    screen: Vec<u8>,
    resets: usize,
}

impl Viewer {
    async fn connect(
        addr: SocketAddr,
        link: &(plexusterm_share_protocol::keys::ShareId, Secret),
    ) -> Self {
        let engine = ViewerEngine::new(link.0, &link.1, ClientId::random());
        Self::with_engine(addr, engine).await
    }

    async fn with_engine(addr: SocketAddr, engine: ViewerEngine) -> Self {
        let (ws, _) = connect_async(format!("ws://{addr}/v1/viewer"))
            .await
            .unwrap();
        Self {
            engine,
            ws,
            received: Capture::default(),
            sent: Capture::default(),
            screen: Vec::new(),
            resets: 0,
        }
    }

    async fn reconnect(mut self, addr: SocketAddr) -> Self {
        assert!(self.engine.connection_lost());
        let (ws, _) = connect_async(format!("ws://{addr}/v1/viewer"))
            .await
            .unwrap();
        self.ws = ws;
        self
    }

    async fn send(&mut self, action: viewer::Action) -> Option<Event> {
        match action {
            viewer::Action::Text(t) => self.ws.send(Message::Text(t.into())).await.unwrap(),
            viewer::Action::Binary(b) => {
                self.sent.0.push(b.clone());
                self.ws.send(Message::Binary(b.into())).await.unwrap();
            }
            viewer::Action::Event(Event::Reset) => {
                self.screen.clear();
                self.resets += 1;
            }
            viewer::Action::Event(Event::Write(data)) => self.screen.extend(data),
            viewer::Action::Event(e) => return Some(e),
        }
        None
    }

    async fn until(&mut self, pred: impl Fn(&Event) -> bool) -> Event {
        loop {
            let msg = tokio::time::timeout(WAIT, self.ws.next())
                .await
                .expect("viewer timed out")
                .expect("viewer connection closed")
                .unwrap();
            let actions = match msg {
                Message::Text(t) => self.engine.on_text(&t),
                Message::Binary(b) => {
                    self.received.0.push(b.to_vec());
                    self.engine.on_binary(&b)
                }
                _ => continue,
            };
            let mut found = None;
            for a in actions {
                if let Some(e) = self.send(a).await
                    && found.is_none()
                    && pred(&e)
                {
                    found = Some(e);
                }
            }
            if let Some(e) = found {
                return e;
            }
        }
    }

    /// Reads until the terminal contains `needle`.
    async fn until_screen(&mut self, needle: &[u8]) {
        while !self.screen.windows(needle.len()).any(|w| w == needle) {
            let msg = tokio::time::timeout(WAIT, self.ws.next())
                .await
                .expect("viewer timed out waiting for output")
                .expect("viewer connection closed")
                .unwrap();
            let actions = match msg {
                Message::Text(t) => self.engine.on_text(&t),
                Message::Binary(b) => {
                    self.received.0.push(b.to_vec());
                    self.engine.on_binary(&b)
                }
                _ => continue,
            };
            for a in actions {
                self.send(a).await;
            }
        }
    }

    async fn type_keys(&mut self, data: &[u8]) {
        let action = self.engine.input(data).expect("typing allowed");
        self.send(action).await;
    }
}

/// Viewer joins and the sharer approves it.
async fn join_approved(addr: SocketAddr, sharer: &mut Sharer, access: Access) -> (Viewer, u32) {
    let mut viewer = Viewer::connect(addr, &sharer.link(access)).await;
    viewer.until(|e| *e == Event::Waiting).await;
    let sharer::Action::JoinRequest {
        viewer: id,
        access: asked,
        ip,
        ..
    } = sharer
        .until(|a| matches!(a, sharer::Action::JoinRequest { .. }))
        .await
    else {
        unreachable!()
    };
    assert_eq!(asked, access);
    assert_eq!(ip, "127.0.0.1");
    let actions = sharer.engine.approve(id);
    sharer.apply(actions).await;
    let joined = viewer.until(|e| matches!(e, Event::Joined { .. })).await;
    assert_eq!(
        joined,
        Event::Joined {
            access,
            cols: 80,
            rows: 24
        }
    );
    (viewer, id)
}

#[tokio::test]
async fn marker_never_appears_in_relayed_frames() {
    let addr = relay().await;
    let mut sharer = Sharer::start(addr, vec![Access::Type]).await;
    sharer.output(b"before join ").await;
    sharer.output(MARKER).await;
    let (mut viewer, _) = join_approved(addr, &mut sharer, Access::Type).await;
    viewer.until_screen(MARKER).await;

    sharer.output(b" live ").await;
    sharer.output(MARKER).await;
    sharer.output(b" END").await;
    viewer.until_screen(b" END").await;

    viewer.type_keys(MARKER).await;
    let input = sharer
        .until(|a| matches!(a, sharer::Action::Input { .. }))
        .await;
    assert!(matches!(input, sharer::Action::Input { data, .. } if data == MARKER));

    assert!(
        !viewer.received.contains(MARKER),
        "relay delivered plaintext to viewer"
    );
    assert!(!viewer.sent.contains(MARKER), "viewer sent plaintext");
    assert!(
        !sharer.received.contains(MARKER),
        "relay delivered plaintext to sharer"
    );
    assert!(!viewer.received.0.is_empty() && !sharer.received.0.is_empty());
}

#[tokio::test]
async fn new_viewer_sees_snapshot_then_live_output_without_gaps() {
    let addr = relay().await;
    let mut sharer = Sharer::start(addr, vec![Access::View]).await;
    for i in 0..50 {
        sharer.output(format!("line {i}\r\n").as_bytes()).await;
    }
    let (mut viewer, _) = join_approved(addr, &mut sharer, Access::View).await;
    for i in 50..60 {
        sharer.output(format!("line {i}\r\n").as_bytes()).await;
    }
    viewer.until_screen(b"line 59\r\n").await;
    let expected: Vec<u8> = (0..60)
        .flat_map(|i| format!("line {i}\r\n").into_bytes())
        .collect();
    assert_eq!(viewer.screen, expected);
    assert_eq!(viewer.resets, 1);
}

#[tokio::test]
async fn view_only_viewer_cannot_type() {
    let addr = relay().await;
    let mut sharer = Sharer::start(addr, vec![Access::View]).await;
    let (mut viewer, _) = join_approved(addr, &mut sharer, Access::View).await;
    assert!(viewer.engine.input(b"rm -rf ~\r").is_none());
}

#[tokio::test]
async fn denied_viewer_is_told() {
    let addr = relay().await;
    let mut sharer = Sharer::start(addr, vec![Access::View]).await;
    let mut viewer = Viewer::connect(addr, &sharer.link(Access::View)).await;
    viewer.until(|e| *e == Event::Waiting).await;
    let sharer::Action::JoinRequest { viewer: id, .. } = sharer
        .until(|a| matches!(a, sharer::Action::JoinRequest { .. }))
        .await
    else {
        unreachable!()
    };
    let actions = sharer.engine.deny(id);
    sharer.apply(actions).await;
    assert_eq!(viewer.until(|_| true).await, Event::Denied);
    assert!(!viewer.engine.connection_lost(), "denied is final");
}

#[tokio::test]
async fn disconnected_viewer_cannot_rejoin_and_others_keep_working() {
    let addr = relay().await;
    let mut sharer = Sharer::start(addr, vec![Access::Type]).await;
    let old_link = sharer.link(Access::Type);
    let (mut removed, removed_id) = join_approved(addr, &mut sharer, Access::Type).await;
    let (mut other, _) = join_approved(addr, &mut sharer, Access::Type).await;

    let actions = sharer.engine.kick(removed_id);
    let rest = sharer.apply(actions).await;
    assert!(matches!(
        rest[..],
        [sharer::Action::LinkRotated {
            access: Access::Type,
            ..
        }]
    ));
    assert_eq!(removed.until(|e| *e == Event::Kicked).await, Event::Kicked);

    let mut again = Viewer::connect(addr, &old_link).await;
    assert_eq!(
        again.until(|_| true).await,
        Event::Refused(ErrorCode::BadKey)
    );

    sharer.output(b"still here").await;
    other.until_screen(b"still here").await;
    other.type_keys(b"x").await;
    sharer
        .until(|a| matches!(a, sharer::Action::Input { data, .. } if data == b"x"))
        .await;

    let new_link = sharer.link(Access::Type);
    assert_ne!(new_link.1, old_link.1);
    let mut newcomer = Viewer::connect(addr, &new_link).await;
    newcomer.until(|e| *e == Event::Waiting).await;
    sharer
        .until(|a| matches!(a, sharer::Action::JoinRequest { .. }))
        .await;
}

#[tokio::test]
async fn reconnecting_viewer_resumes_without_approval_or_snapshot() {
    let addr = relay().await;
    let mut sharer = Sharer::start(addr, vec![Access::Type]).await;
    let (mut viewer, _) = join_approved(addr, &mut sharer, Access::Type).await;
    sharer.output(b"first ").await;
    viewer.until_screen(b"first ").await;

    viewer.ws.close(None).await.unwrap();
    sharer
        .until(|a| matches!(a, sharer::Action::ViewerLeft { .. }))
        .await;
    sharer.output(b"missed while away").await;

    let started = std::time::Instant::now();
    let mut viewer = viewer.reconnect(addr).await;
    viewer.until(|e| *e == Event::Waiting).await;
    let rejoined = sharer
        .until(|a| {
            matches!(
                a,
                sharer::Action::Rejoined { .. } | sharer::Action::JoinRequest { .. }
            )
        })
        .await;
    assert!(
        matches!(rejoined, sharer::Action::Rejoined { .. }),
        "{rejoined:?}"
    );
    viewer.until(|e| matches!(e, Event::Joined { .. })).await;
    viewer.until_screen(b"missed while away").await;
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(viewer.resets, 1, "resumed from the buffer, no new snapshot");
    assert_eq!(viewer.screen, b"first missed while away");
    assert_eq!(sharer.engine.viewer_count(), 1);
}

#[tokio::test]
async fn reconnecting_past_the_buffer_gets_a_fresh_snapshot() {
    let addr = relay().await;
    let mut sharer = Sharer::start(addr, vec![Access::View]).await;
    let (mut viewer, _) = join_approved(addr, &mut sharer, Access::View).await;
    sharer.output(b"hi").await;
    viewer.until_screen(b"hi").await;
    viewer.ws.close(None).await.unwrap();
    sharer
        .until(|a| matches!(a, sharer::Action::ViewerLeft { .. }))
        .await;
    let filler = vec![b'.'; 64 * 1024];
    for _ in 0..20 {
        sharer.output(&filler).await;
    }
    sharer.output(b"TAIL").await;

    let mut viewer = viewer.reconnect(addr).await;
    viewer.until(|e| *e == Event::Waiting).await;
    sharer
        .until(|a| matches!(a, sharer::Action::Rejoined { .. }))
        .await;
    viewer.until_screen(b"TAIL").await;
    assert_eq!(viewer.resets, 2, "a fresh snapshot replaced the screen");
    assert!(viewer.screen.len() <= 1024 * 1024 + 4);
}

#[tokio::test]
async fn sharer_reconnects_and_viewers_resync() {
    let addr = relay().await;
    let mut first = Sharer::start(addr, vec![Access::View]).await;
    let (mut viewer, _) = join_approved(addr, &mut first, Access::View).await;
    let Sharer { mut engine, ws, .. } = first;
    drop(ws);
    viewer.until(|e| *e == Event::SharerAway).await;

    engine.connection_lost();
    let mut output = engine.output(b"during the gap");
    output.retain(|a| !matches!(a, sharer::Action::Binary(_)));
    assert!(output.is_empty());
    let mut sharer = Sharer::attach(addr, engine).await;
    sharer
        .until(|a| matches!(a, sharer::Action::Ready { .. }))
        .await;
    viewer.until(|e| *e == Event::SharerBack).await;
    sharer.pump().await;
    viewer.until_screen(b"during the gap").await;
    sharer.output(b" and after").await;
    viewer.until_screen(b" and after").await;
}

#[tokio::test]
async fn wrong_secret_for_a_live_share_is_refused() {
    let addr = relay().await;
    let sharer = Sharer::start(addr, vec![Access::View]).await;
    let (id, _) = sharer.link(Access::View);
    let mut viewer = Viewer::connect(addr, &(id, Secret::random())).await;
    assert_eq!(
        viewer.until(|_| true).await,
        Event::Refused(ErrorCode::BadKey)
    );
}

mod sans_io {
    //! Engines wired by hand, the test acting as the relay.

    use plexusterm_share_client::sharer::{self, SharerConfig, SharerEngine, Snapshot};
    use plexusterm_share_client::viewer::{self, Event, ViewerEngine};
    use plexusterm_share_protocol::ProtocolError;
    use plexusterm_share_protocol::content::{Access, ClientId};
    use plexusterm_share_protocol::keys::DerivedKeys;
    use plexusterm_share_protocol::link::parse_share_url;
    use plexusterm_share_protocol::wire::{decode_routed, encode_routed};

    const HELLO: &str =
        r#"{"t":"hello","proto":1,"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;

    fn engine(access: Access) -> SharerEngine {
        let mut sharer = SharerEngine::new(SharerConfig {
            token: super::TOKEN.into(),
            expires_at: super::now() + 3600,
            accesses: vec![access],
            cols: 80,
            rows: 24,
        });
        assert!(matches!(
            sharer.on_text(HELLO)[..],
            [sharer::Action::Text(_)]
        ));
        sharer.on_text(&format!(
            r#"{{"t":"ready","expires_at":{},"viewers":[]}}"#,
            super::now() + 3600
        ));
        sharer
    }

    /// Runs the join up to approval; returns the viewer-bound payloads the
    /// approval produced (Noise message 2, then snapshot frames).
    fn pair(sharer: &mut SharerEngine) -> (ViewerEngine, Vec<Vec<u8>>) {
        let (_, url) = sharer.links("https://view.test").remove(0);
        let link = parse_share_url(&url).unwrap();
        let secret = link.secret.unwrap();
        let mut viewer = ViewerEngine::new(link.share_id, &secret, ClientId::random());
        viewer.on_text(HELLO);
        let accepted = viewer.on_text(r#"{"t":"accepted","viewer":1,"expires_at":1}"#);
        let viewer::Action::Binary(msg1) = &accepted[0] else {
            panic!("expected Noise message 1")
        };
        let link_id = DerivedKeys::derive(&secret).link_id.to_b64();
        sharer.on_text(&format!(
            r#"{{"t":"join","viewer":1,"link_id":"{link_id}","ip":"203.0.113.9","ua":"test"}}"#
        ));
        assert!(matches!(
            sharer.on_binary(&encode_routed(1, msg1))[..],
            [sharer::Action::JoinRequest { viewer: 1, .. }]
        ));
        (viewer, to_viewer(sharer.approve(1)))
    }

    fn to_viewer(actions: Vec<sharer::Action>) -> Vec<Vec<u8>> {
        actions
            .into_iter()
            .filter_map(|a| match a {
                sharer::Action::Binary(b) => {
                    let (id, payload) = decode_routed(&b).unwrap();
                    assert_eq!(id, 1);
                    Some(payload.to_vec())
                }
                _ => None,
            })
            .collect()
    }

    /// Applies payloads to a viewer and renders its terminal writes.
    fn render(viewer: &mut ViewerEngine, payloads: &[Vec<u8>], screen: &mut Vec<u8>) -> usize {
        let mut resets = 0;
        for p in payloads {
            for a in viewer.on_binary(p) {
                match a {
                    viewer::Action::Event(Event::Reset) => {
                        screen.clear();
                        resets += 1;
                    }
                    viewer::Action::Event(Event::Write(d)) => screen.extend(d),
                    _ => {}
                }
            }
        }
        resets
    }

    /// A test relay that replays captured frames: both directions drop them.
    #[test]
    fn replayed_frames_injected_by_a_test_relay_are_dropped() {
        let mut sharer = engine(Access::Type);
        let (mut viewer, frames) = pair(&mut sharer);
        render(&mut viewer, &frames, &mut Vec::new());
        assert!(viewer.is_live());

        let viewer::Action::Binary(input) = viewer.input(b"ls\r").unwrap() else {
            panic!("expected an input frame")
        };
        assert_eq!(
            sharer.on_binary(&encode_routed(1, &input)),
            vec![sharer::Action::Input {
                viewer: 1,
                data: b"ls\r".to_vec()
            }]
        );
        assert_eq!(
            sharer.on_binary(&encode_routed(1, &input)),
            vec![sharer::Action::Dropped {
                viewer: 1,
                error: ProtocolError::Replay
            }],
            "re-injected input frame must be dropped"
        );
        assert_eq!(
            viewer.on_binary(frames.last().unwrap()),
            vec![viewer::Action::Event(Event::Dropped)],
            "re-injected output frame must be dropped"
        );
    }

    /// Can type → View only takes effect at once: input already in flight
    /// is dropped by the sharer.
    #[test]
    fn downgrade_to_view_only_drops_input_at_once() {
        let mut sharer = engine(Access::Type);
        let (mut viewer, frames) = pair(&mut sharer);
        render(&mut viewer, &frames, &mut Vec::new());
        let viewer::Action::Binary(in_flight) = viewer.input(b"q").unwrap() else {
            panic!()
        };
        let status = to_viewer(sharer.downgrade_to_view());
        assert_eq!(
            sharer.on_binary(&encode_routed(1, &in_flight)),
            vec![sharer::Action::Dropped {
                viewer: 1,
                error: ProtocolError::Auth
            }]
        );
        assert_eq!(
            viewer.on_binary(&status[0]),
            vec![viewer::Action::Event(Event::AccessChanged(Access::View))]
        );
        assert!(viewer.input(b"q").is_none());
    }

    /// A join request still waiting for an answer when the sharer switches
    /// to View only is approved as View only.
    #[test]
    fn downgrade_applies_to_viewers_waiting_for_approval() {
        let mut sharer = engine(Access::Type);
        let (_, url) = sharer.links("https://view.test").remove(0);
        let link = parse_share_url(&url).unwrap();
        let secret = link.secret.unwrap();
        let mut viewer = ViewerEngine::new(link.share_id, &secret, ClientId::random());
        viewer.on_text(HELLO);
        let accepted = viewer.on_text(r#"{"t":"accepted","viewer":1,"expires_at":1}"#);
        let viewer::Action::Binary(msg1) = &accepted[0] else {
            panic!("expected Noise message 1")
        };
        let link_id = DerivedKeys::derive(&secret).link_id.to_b64();
        sharer.on_text(&format!(
            r#"{{"t":"join","viewer":1,"link_id":"{link_id}","ip":"203.0.113.9","ua":"t"}}"#
        ));
        assert!(matches!(
            sharer.on_binary(&encode_routed(1, msg1))[..],
            [sharer::Action::JoinRequest {
                access: Access::Type,
                ..
            }]
        ));

        sharer.downgrade_to_view();
        let frames = to_viewer(sharer.approve(1));
        let joined = viewer.on_binary(&frames[0]);
        assert_eq!(
            joined,
            vec![viewer::Action::Event(Event::Joined {
                access: Access::View,
                cols: 80,
                rows: 24
            })]
        );
        assert!(viewer.input(b"q").is_none());
    }

    /// The screen part paints first, the full part replaces it, and live
    /// output continues after `covers_seq`.
    #[test]
    fn screen_then_full_snapshot_then_live_output() {
        let mut sharer = engine(Access::View);
        sharer.output(b"old history\r\nprompt$ ");
        sharer.set_snapshot_source(Box::new(|| Snapshot {
            screen: Some(b"prompt$ ".to_vec()),
            full: b"old history\r\nprompt$ ".to_vec(),
        }));
        let (mut viewer, frames) = pair(&mut sharer);
        // Noise message 2, one screen chunk, one full chunk.
        assert_eq!(frames.len(), 3);
        let live = to_viewer(sharer.output(b"ls"));

        let mut screen = Vec::new();
        let resets = render(&mut viewer, &frames[..2], &mut screen);
        assert_eq!((resets, screen.as_slice()), (1, &b"prompt$ "[..]));
        let resets = render(&mut viewer, &frames[2..], &mut screen);
        assert_eq!(
            (resets, screen.as_slice()),
            (1, &b"old history\r\nprompt$ "[..])
        );
        render(&mut viewer, &live, &mut screen);
        assert_eq!(screen, b"old history\r\nprompt$ ls");
    }
}
