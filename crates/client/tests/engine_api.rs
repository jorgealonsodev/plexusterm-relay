//! SharerEngine host API: asynchronous snapshots, expiry changes, program
//! exit and pausing viewer input. Engines are wired by hand; the test acts
//! as the relay.

use plexusterm_share_client::sharer::{Action, SharerConfig, SharerEngine, Snapshot};
use plexusterm_share_client::viewer::{self, Event, ViewerEngine};
use plexusterm_share_protocol::content::{Access, ClientId};
use plexusterm_share_protocol::keys::DerivedKeys;
use plexusterm_share_protocol::link::parse_share_url;
use plexusterm_share_protocol::wire::{SharerToRelay, decode_routed, encode_routed};

const HELLO: &str =
    r#"{"t":"hello","proto":1,"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sharer() -> SharerEngine {
    let mut sharer = SharerEngine::new(SharerConfig {
        token: "t".repeat(20),
        expires_at: now() + 3600,
        accesses: vec![Access::Type],
        cols: 80,
        rows: 24,
    });
    sharer.on_text(HELLO);
    sharer.on_text(&format!(
        r#"{{"t":"ready","expires_at":{},"viewers":[]}}"#,
        now() + 3600
    ));
    sharer
}

/// A viewer engine plus what its terminal shows.
struct Viewer {
    id: u32,
    engine: ViewerEngine,
    screen: Vec<u8>,
    events: Vec<Event>,
}

impl Viewer {
    /// Feeds the sharer's actions addressed to this viewer; returns the
    /// actions that were not frames for it.
    fn feed(&mut self, actions: Vec<Action>) -> Vec<Action> {
        let mut rest = Vec::new();
        for a in actions {
            match a {
                Action::Binary(b) if decode_routed(&b).unwrap().0 == self.id => {
                    let payload = decode_routed(&b).unwrap().1;
                    for v in self.engine.on_binary(payload) {
                        match v {
                            viewer::Action::Event(Event::Reset) => self.screen.clear(),
                            viewer::Action::Event(Event::Write(d)) => self.screen.extend(d),
                            viewer::Action::Event(e) => self.events.push(e),
                            _ => {}
                        }
                    }
                }
                other => rest.push(other),
            }
        }
        rest
    }
}

/// Joins viewer `id` and runs the sharer's approval; returns the viewer and
/// the approval actions not addressed to it as frames.
fn join(sharer: &mut SharerEngine, id: u32) -> (Viewer, Vec<Action>) {
    let (_, url) = sharer.links("https://view.test").remove(0);
    let link = parse_share_url(&url).unwrap();
    let secret = link.secret.unwrap();
    let mut engine = ViewerEngine::new(link.share_id, &secret, ClientId::random());
    engine.on_text(HELLO);
    let accepted = engine.on_text(&format!(
        r#"{{"t":"accepted","viewer":{id},"expires_at":1}}"#
    ));
    let viewer::Action::Binary(msg1) = &accepted[0] else {
        panic!("expected Noise message 1")
    };
    let link_id = DerivedKeys::derive(&secret).link_id.to_b64();
    sharer.on_text(&format!(
        r#"{{"t":"join","viewer":{id},"link_id":"{link_id}","ip":"203.0.113.9","ua":"t"}}"#
    ));
    assert!(matches!(
        sharer.on_binary(&encode_routed(id, msg1))[..],
        [Action::JoinRequest { .. }]
    ));
    let mut viewer = Viewer {
        id,
        engine,
        screen: Vec::new(),
        events: Vec::new(),
    };
    let approval = sharer.approve(id);
    let rest = viewer.feed(approval);
    assert!(viewer.engine.is_live());
    (viewer, rest)
}

fn relay_text(actions: &[Action]) -> Vec<SharerToRelay> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Text(t) => serde_json::from_str(t).ok(),
            _ => None,
        })
        .collect()
}

#[test]
fn async_snapshot_is_requested_and_output_meanwhile_follows_it() {
    let mut sharer = sharer();
    sharer.set_async_snapshots(true);
    sharer.output(b"old ");
    assert_eq!(sharer.last_seq(), 1);

    let (mut viewer, rest) = join(&mut sharer, 1);
    assert_eq!(rest, vec![Action::SnapshotRequest { viewer: 1 }]);
    assert!(viewer.screen.is_empty(), "nothing before the snapshot");

    // Output while the host serializes: held for this viewer, not lost.
    let held = sharer.output(b"new");
    assert!(viewer.feed(held).is_empty());
    assert!(viewer.screen.is_empty());

    // The host serialized the terminal as it was after seq 1.
    let ready = sharer.snapshot_ready(
        1,
        1,
        Snapshot {
            screen: None,
            full: b"SNAP ".to_vec(),
        },
    );
    assert!(viewer.feed(ready).is_empty());
    assert_eq!(viewer.screen, b"SNAP new");

    let live = sharer.output(b"!");
    viewer.feed(live);
    assert_eq!(viewer.screen, b"SNAP new!");
}

#[test]
fn async_snapshot_older_than_the_buffer_is_requested_again() {
    let mut sharer = sharer();
    sharer.set_async_snapshots(true);
    let (_viewer, rest) = join(&mut sharer, 1);
    assert_eq!(rest, vec![Action::SnapshotRequest { viewer: 1 }]);
    for _ in 0..50 {
        sharer.output(&vec![b'x'; 24 * 1024]);
    }
    let again = sharer.snapshot_ready(
        1,
        0,
        Snapshot {
            screen: None,
            full: Vec::new(),
        },
    );
    assert_eq!(again, vec![Action::SnapshotRequest { viewer: 1 }]);
    let future = sharer.snapshot_ready(
        1,
        sharer.last_seq() + 1,
        Snapshot {
            screen: None,
            full: Vec::new(),
        },
    );
    assert_eq!(future, vec![Action::SnapshotRequest { viewer: 1 }]);
}

#[test]
fn set_expiry_asks_the_relay_and_reports_the_confirmation() {
    let mut sharer = sharer();
    let later = now() + 7200;
    let actions = sharer.set_expiry(later);
    assert_eq!(
        relay_text(&actions),
        vec![SharerToRelay::SetExpiry { expires_at: later }]
    );
    assert_eq!(
        sharer.on_text(&format!(r#"{{"t":"expiry","expires_at":{later}}}"#)),
        vec![Action::ExpiryChanged { expires_at: later }]
    );
    assert_eq!(sharer.expires_at(), later);
}

#[test]
fn program_exit_tells_every_viewer_then_ends_the_share() {
    let mut sharer = sharer();
    let (mut a, _) = join(&mut sharer, 1);
    let (mut b, _) = join(&mut sharer, 2);
    let actions = sharer.program_exited();
    let (for_a, rest): (Vec<_>, Vec<_>) = actions
        .into_iter()
        .partition(|x| matches!(x, Action::Binary(m) if decode_routed(m).unwrap().0 == 1));
    let (for_b, rest): (Vec<_>, Vec<_>) = rest
        .into_iter()
        .partition(|x| matches!(x, Action::Binary(m) if decode_routed(m).unwrap().0 == 2));
    a.feed(for_a);
    b.feed(for_b);
    assert!(a.events.contains(&Event::ProgramExited));
    assert!(b.events.contains(&Event::ProgramExited));
    assert_eq!(relay_text(&rest), vec![SharerToRelay::End]);
}

#[test]
fn pausing_input_tells_current_and_new_viewers() {
    let mut sharer = sharer();
    let (mut a, _) = join(&mut sharer, 1);
    let paused = sharer.pause_input(true);
    assert!(a.feed(paused).is_empty());
    assert_eq!(a.events.last(), Some(&Event::InputPaused(true)));

    // A viewer approved while input is paused learns it at once.
    let (b, _) = join(&mut sharer, 2);
    assert_eq!(b.events.last(), Some(&Event::InputPaused(true)));

    let resumed = sharer.pause_input(false);
    a.feed(resumed);
    assert_eq!(a.events.last(), Some(&Event::InputPaused(false)));
}
