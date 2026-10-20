//! A PlexusTerm viewer facing a relay of another protocol version says so
//! ("Update PlexusTerm to open this share") instead of trying to join.

use plexusterm_share_client::viewer::{Action, Event, ViewerEngine};
use plexusterm_share_protocol::content::ClientId;
use plexusterm_share_protocol::keys::{Secret, ShareId};
use plexusterm_share_protocol::wire::ErrorCode;

const CHALLENGE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn engine() -> ViewerEngine {
    ViewerEngine::new(ShareId([1; 16]), &Secret([2; 32]), ClientId([3; 16]))
}

#[test]
fn other_protocol_version_is_refused_without_joining() {
    let mut viewer = engine();
    let actions = viewer.on_text(&format!(
        r#"{{"t":"hello","proto":2,"challenge":"{CHALLENGE}"}}"#
    ));
    assert_eq!(
        actions,
        vec![Action::Event(Event::Refused(ErrorCode::Version))]
    );
    assert!(!viewer.connection_lost(), "a version mismatch is final");
}

#[test]
fn current_protocol_version_joins() {
    let mut viewer = engine();
    let actions = viewer.on_text(&format!(
        r#"{{"t":"hello","proto":1,"challenge":"{CHALLENGE}"}}"#
    ));
    assert!(matches!(&actions[..], [Action::Text(t)] if t.contains(r#""t":"join""#)));
}
