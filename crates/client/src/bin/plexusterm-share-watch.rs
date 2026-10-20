//! Reference viewer: opens a share in this terminal, the way PlexusTerm as
//! a viewer (PRD-share P3) does in a pane. View only: keys typed here are
//! not sent.
//!
//! ```text
//! PLEXUSTERM_SHARE_LINK='plexusterm://s/relay.example.com/<id>#<key>' plexusterm-share-watch
//! PLEXUSTERM_SHARE_LINK='https://view.example.com/s/<id>#<key>' plexusterm-share-watch --relay wss://relay.example.com
//! ```
//!
//! The link carries the key, so it is read from `PLEXUSTERM_SHARE_LINK` or,
//! when unset, from the first line of stdin — never from the command line,
//! which other users can read. A `plexusterm://` link names its relay; an
//! `https://` link needs `--relay` (PlexusTerm reads it from
//! `<viewer-origin>/relay.txt`).
//!
//! Status goes to stderr, the shared terminal to stdout. Exit codes: 0 the
//! share ended, 2 bad arguments or link, 4 refused, denied or disconnected.

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use plexusterm_share_client::viewer::{Action, Event, ViewerEngine};
use plexusterm_share_protocol::content::{Access, ClientId};
use plexusterm_share_protocol::keys::{Secret, ShareId};
use plexusterm_share_protocol::link::{parse_deep_link, parse_share_url};
use plexusterm_share_protocol::wire::{EndReason, ErrorCode};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

const USAGE: &str =
    "usage: PLEXUSTERM_SHARE_LINK=<link> plexusterm-share-watch [--relay wss://relay.example.com]";

/// Debug prints the secret as `<redacted>`.
#[derive(Debug)]
struct Target {
    relay: String,
    share_id: ShareId,
    secret: Secret,
}

/// Messages of PRD-share §4.4 and §5.4 for each final outcome.
fn final_message(event: &Event) -> Option<(&'static str, u8)> {
    Some(match event {
        Event::Ended(EndReason::Offline) => {
            ("The sharing computer went offline. The share has ended.", 0)
        }
        Event::Ended(_) => ("The share has ended", 0),
        Event::Denied => ("The sharer declined your request", 4),
        Event::Kicked => ("The share has ended", 4),
        Event::Refused(ErrorCode::NotFound) => (
            "This share has ended or the link is wrong. Ask for a new link.",
            4,
        ),
        Event::Refused(ErrorCode::BadKey) => {
            ("This link's key is not valid. It may have been revoked.", 4)
        }
        Event::Refused(ErrorCode::Full) => ("This share has reached its viewer limit.", 4),
        Event::Refused(ErrorCode::Version) => ("Update PlexusTerm to open this share", 4),
        Event::Refused(_) => ("The relay refused to open this share.", 4),
        _ => return None,
    })
}

fn parse_target(link: &str, relay_flag: Option<String>) -> Result<Target, String> {
    let link = link.trim();
    let incomplete = "This link is incomplete — the part after # is missing. Copy the whole link.";
    if link.starts_with("plexusterm://") {
        let deep = parse_deep_link(link).map_err(|_| "Not a share link.".to_owned())?;
        let secret = deep.secret.ok_or(incomplete)?;
        return Ok(Target {
            relay: relay_flag.unwrap_or_else(|| deep.relay_url()),
            share_id: deep.share_id,
            secret,
        });
    }
    let parsed = parse_share_url(link).map_err(|_| "Not a share link.".to_owned())?;
    let secret = parsed.secret.ok_or(incomplete)?;
    let relay = relay_flag
        .ok_or("An https:// link needs --relay wss://… (see <viewer-origin>/relay.txt).")?;
    Ok(Target {
        relay,
        share_id: parsed.share_id,
        secret,
    })
}

fn read_link() -> Option<String> {
    if let Some(l) = std::env::var("PLEXUSTERM_SHARE_LINK")
        .ok()
        .filter(|l| !l.trim().is_empty())
    {
        return Some(l);
    }
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).ok()?;
    Some(line).filter(|l| !l.trim().is_empty())
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut relay_flag = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--relay" => relay_flag = args.next().map(|r| r.trim_end_matches('/').to_owned()),
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(link) = read_link() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let target = match parse_target(&link, relay_flag) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    drop(link);

    let mut engine = ViewerEngine::new(target.share_id, &target.secret, ClientId::random());
    let mut out = std::io::stdout();
    let mut backoff = Duration::from_secs(1);
    let host = target
        .relay
        .split("://")
        .nth(1)
        .unwrap_or(&target.relay)
        .to_owned();

    loop {
        let ws = match connect_async(format!("{}/v1/viewer", target.relay)).await {
            Ok((ws, _)) => ws,
            Err(_) => {
                eprintln!("Can't reach {host}. Check your connection.");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
        };
        let (mut sink, mut stream) = ws.split();
        let mut ping = tokio::time::interval(Duration::from_secs(20));
        ping.tick().await;
        loop {
            let actions = tokio::select! {
                msg = stream.next() => match msg {
                    Some(Ok(Message::Text(t))) => engine.on_text(&t),
                    Some(Ok(Message::Binary(b))) => engine.on_binary(&b),
                    Some(Ok(_)) => continue,
                    _ => break,
                },
                _ = ping.tick() => vec![engine.ping()],
            };
            for action in actions {
                match action {
                    Action::Text(t) => {
                        let _ = sink.send(Message::Text(t.into())).await;
                    }
                    Action::Binary(b) => {
                        let _ = sink.send(Message::Binary(b.into())).await;
                    }
                    // RIS: clear the screen and scrollback before a snapshot.
                    Action::Event(Event::Reset) => {
                        let _ = out.write_all(b"\x1bc");
                    }
                    Action::Event(Event::Write(data)) => {
                        let _ = out.write_all(&data);
                        let _ = out.flush();
                    }
                    Action::Event(event) => {
                        if let Some((message, code)) = final_message(&event) {
                            let _ = out.flush();
                            eprintln!("\r\n{message}");
                            return ExitCode::from(code);
                        }
                        match event {
                            Event::Waiting => eprintln!("Waiting for the sharer to let you in"),
                            Event::Joined { access, cols, rows } => {
                                backoff = Duration::from_secs(1);
                                let label = match access {
                                    Access::View => "view only",
                                    Access::Type => {
                                        "can type (typing is not sent from this viewer)"
                                    }
                                };
                                eprintln!("Joined: {label}, {cols}×{rows}");
                            }
                            Event::SharerAway => {
                                eprintln!("\r\nSharing computer is unreachable — reconnecting…");
                            }
                            Event::AccessChanged(Access::View) => {
                                eprintln!("\r\nThe sharer changed this share to view only");
                            }
                            Event::ProgramExited => eprintln!("\r\nThe shared program exited"),
                            _ => {}
                        }
                    }
                }
            }
        }
        if !engine.connection_lost() {
            return ExitCode::SUCCESS;
        }
        eprintln!("\r\nReconnecting…");
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "AwMDAwMDAwMDAwMDAwMDAw";
    const KEY: &str = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ";

    #[test]
    fn deep_link_names_its_relay() {
        let t = parse_target(
            &format!("plexusterm://s/relay.example.com/{ID}#{KEY}\n"),
            None,
        )
        .unwrap();
        assert_eq!(t.relay, "wss://relay.example.com");
        assert_eq!(t.share_id, ShareId([3; 16]));
    }

    #[test]
    fn https_link_needs_a_relay_and_a_complete_fragment() {
        let link = format!("https://view.example.com/s/{ID}#{KEY}");
        assert!(parse_target(&link, None).unwrap_err().contains("--relay"));
        let t = parse_target(&link, Some("wss://relay.example.com".into())).unwrap();
        assert_eq!(t.relay, "wss://relay.example.com");
        let cut = format!("https://view.example.com/s/{ID}#");
        assert!(
            parse_target(&cut, Some("wss://r".into()))
                .unwrap_err()
                .contains("incomplete")
        );
    }
}
