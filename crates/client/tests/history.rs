//! A viewer only ever gets output it was entitled to: the snapshot the
//! sharer chose, then live output. `resume_from` and `Resync` cannot reach
//! below what this client was already sent (history may hold secrets).

use plexusterm_share_client::sharer::{Action, SharerConfig, SharerEngine, Snapshot};
use plexusterm_share_protocol::content::{Access, ClientId, Content, ViewerHello};
use plexusterm_share_protocol::frame::{Binding, Direction, Opener, Sealer};
use plexusterm_share_protocol::keys::{Challenge, DerivedKeys};
use plexusterm_share_protocol::link::parse_share_url;
use plexusterm_share_protocol::noise::ViewerHandshake;
use plexusterm_share_protocol::wire::{decode_routed, encode_routed};

const SECRET_LINE: &[u8] = b"OLD-HISTORY-password=hunter2\r\n";

struct Joined {
    engine: SharerEngine,
    sealer: Sealer,
    opener: Opener,
    seen: Vec<u8>,
}

fn render(opener: &mut Opener, actions: Vec<Action>, seen: &mut Vec<u8>) {
    for a in actions {
        if let Action::Binary(b) = a {
            let payload = decode_routed(&b).unwrap().1;
            match Content::decode(&opener.open(payload).unwrap()).unwrap() {
                Content::Output { data, .. } => seen.extend(data),
                Content::Snapshot { data, .. } if data.is_empty() => {}
                Content::Snapshot { .. } => seen.extend(b"<snapshot>"),
                _ => {}
            }
        }
    }
}

/// Sharer chose "Current screen only"; a first-time viewer joins claiming
/// `resume_from`.
fn join(resume_from: Option<u64>) -> Joined {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut engine = SharerEngine::new(SharerConfig {
        token: "t".repeat(20),
        expires_at: now + 3600,
        accesses: vec![Access::View],
        cols: 80,
        rows: 24,
    });
    engine.set_snapshot_source(Box::new(|| Snapshot {
        screen: None,
        full: b"SCREEN-ONLY".to_vec(),
    }));
    let ch = Challenge::random();
    engine.on_text(&format!(
        r#"{{"t":"hello","proto":1,"challenge":"{}"}}"#,
        ch.to_b64()
    ));
    engine.on_text(r#"{"t":"ready","expires_at":1,"viewers":[]}"#);
    engine.output(SECRET_LINE);
    engine.output(b"screen line\r\n");

    let link = parse_share_url(&engine.links("https://v.example")[0].1).unwrap();
    let keys = DerivedKeys::derive(&link.secret.unwrap());
    engine.on_text(&format!(
        r#"{{"t":"join","viewer":1,"link_id":"{}","ip":"203.0.113.1","ua":"x"}}"#,
        keys.link_id.to_b64()
    ));
    let hello = serde_json::to_vec(&ViewerHello {
        client: ClientId([7; 16]),
        resume_from,
    })
    .unwrap();
    let (hs, m1) = ViewerHandshake::start(&link.share_id, &keys.psk, &hello).unwrap();
    let asked = engine.on_binary(&encode_routed(1, &m1));
    assert!(
        matches!(asked[..], [Action::JoinRequest { .. }]),
        "{asked:?}"
    );

    let mut actions = engine.approve(1).into_iter();
    let Some(Action::Binary(m2)) = actions.next() else {
        panic!("expected Noise message 2")
    };
    let (sk, _) = hs.finish(decode_routed(&m2).unwrap().1).unwrap();
    let binding = |direction| Binding {
        share_id: link.share_id,
        viewer_id: 1,
        direction,
    };
    let mut opener = Opener::new(&sk.to_viewer, binding(Direction::ToViewer));
    let mut seen = Vec::new();
    render(&mut opener, actions.collect(), &mut seen);
    Joined {
        engine,
        sealer: Sealer::new(&sk.to_sharer, binding(Direction::ToSharer)),
        opener,
        seen,
    }
}

#[test]
fn first_time_viewer_cannot_resume_into_history() {
    assert_eq!(join(None).seen, b"<snapshot>");
    assert_eq!(join(Some(0)).seen, b"<snapshot>");
}

#[test]
fn live_viewer_cannot_resync_below_its_snapshot() {
    let mut j = join(None);
    let live = j.engine.output(b"live\r\n");
    render(&mut j.opener, live, &mut j.seen);
    let resync = j
        .sealer
        .seal(&Content::Resync { last_seq: Some(0) }.encode())
        .unwrap();
    let actions = j.engine.on_binary(&encode_routed(1, &resync));
    render(&mut j.opener, actions, &mut j.seen);
    let seen = String::from_utf8_lossy(&j.seen);
    assert!(!seen.contains("hunter2"), "history leaked: {seen:?}");
    // Refused: the viewer gets a fresh snapshot instead.
    assert_eq!(seen, "<snapshot>live\r\n<snapshot>");
}

#[test]
fn live_viewer_can_resync_from_what_it_was_sent() {
    let mut j = join(None);
    // The viewer saw the snapshot (covering seq 2); these two never reached
    // it (dropped connection), so it asks to continue after seq 2.
    j.engine.output(b"one\r\n");
    j.engine.output(b"two\r\n");
    let resync = j
        .sealer
        .seal(&Content::Resync { last_seq: Some(2) }.encode())
        .unwrap();
    let actions = j.engine.on_binary(&encode_routed(1, &resync));
    render(&mut j.opener, actions, &mut j.seen);
    assert_eq!(String::from_utf8_lossy(&j.seen), "<snapshot>one\r\ntwo\r\n");
}
