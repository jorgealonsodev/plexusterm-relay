//! Demo sharer: runs a command in a pseudo-terminal and shares it through a
//! relay, standing in for PlexusTerm until the sharing side is built there.
//!
//! ```text
//! PLEXUSTERM_RELAY_TOKEN=… plexusterm-share-demo \
//!     --relay wss://relay.example --viewer-origin https://view.example \
//!     [--access view|type|both] [--expires MINUTES] [--approve ask|auto] \
//!     [--size COLSxROWS] [-- COMMAND ARGS…]
//! ```
//!
//! Links go to stdout; status and join requests to stderr. With
//! `--approve ask` (default) each join is answered with `y` or `n` on stdin.
//! Exit codes: 0 share ended, 2 bad arguments, 3 cannot start the command,
//! 4 the relay refused the share.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::process::ExitCode;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use plexusterm_share_client::sharer::{Action, SharerConfig, SharerEngine};
use plexusterm_share_protocol::content::Access;
use plexusterm_share_protocol::wire::EndReason;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

struct Args {
    relay: String,
    viewer_origin: String,
    accesses: Vec<Access>,
    expires_minutes: u64,
    auto_approve: bool,
    cols: u16,
    rows: u16,
    command: Vec<String>,
}

const USAGE: &str = "usage: PLEXUSTERM_RELAY_TOKEN=… plexusterm-share-demo --relay URL --viewer-origin URL \
[--access view|type|both] [--expires MINUTES] [--approve ask|auto] [--size COLSxROWS] [-- COMMAND…]";

fn parse_args(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut args = Args {
        relay: String::new(),
        viewer_origin: String::new(),
        accesses: vec![Access::View],
        expires_minutes: 60,
        auto_approve: false,
        cols: 120,
        rows: 32,
        command: Vec::new(),
    };
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--relay" => args.relay = value()?.trim_end_matches('/').to_owned(),
            "--viewer-origin" => args.viewer_origin = value()?,
            "--access" => {
                args.accesses = match value()?.as_str() {
                    "view" => vec![Access::View],
                    "type" => vec![Access::Type],
                    "both" => vec![Access::View, Access::Type],
                    _ => return Err("--access must be view, type or both".into()),
                }
            }
            "--expires" => {
                args.expires_minutes = value()?
                    .parse()
                    .ok()
                    .filter(|m| (1..=720).contains(m))
                    .ok_or("--expires must be 1 to 720 minutes")?;
            }
            "--approve" => {
                args.auto_approve = match value()?.as_str() {
                    "ask" => false,
                    "auto" => true,
                    _ => return Err("--approve must be ask or auto".into()),
                }
            }
            "--size" => {
                let v = value()?;
                let (c, r) = v.split_once('x').ok_or("--size must be COLSxROWS")?;
                args.cols = c.parse().map_err(|_| "--size must be COLSxROWS")?;
                args.rows = r.parse().map_err(|_| "--size must be COLSxROWS")?;
            }
            "--" => {
                args.command = it.by_ref().collect();
            }
            "-h" | "--help" => return Err(USAGE.into()),
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    if args.relay.is_empty() || args.viewer_origin.is_empty() {
        return Err(USAGE.into());
    }
    Ok(args)
}

enum PtyEvent {
    Output(Vec<u8>),
    Exited,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let Some(token) = std::env::var("PLEXUSTERM_RELAY_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
    else {
        eprintln!("PLEXUSTERM_RELAY_TOKEN is not set");
        return ExitCode::from(2);
    };

    let (pty_tx, mut pty_rx) = mpsc::unbounded_channel();
    let mut pty_writer = match start_pty(&args, pty_tx) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("cannot start the command: {e}");
            return ExitCode::from(3);
        }
    };

    let expires_at = unix_now().saturating_add(args.expires_minutes.saturating_mul(60));
    let mut engine = SharerEngine::new(SharerConfig {
        token,
        expires_at,
        accesses: args.accesses.clone(),
        cols: args.cols,
        rows: args.rows,
    });
    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    let mut pending: VecDeque<u32> = VecDeque::new();
    let mut backoff = Duration::from_secs(1);
    let mut shown_links = false;

    loop {
        let url = format!("{}/v1/sharer", args.relay);
        let (ws, _) = match connect_async(&url).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "relay unreachable ({e}); retrying in {}s",
                    backoff.as_secs()
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
        };
        backoff = Duration::from_secs(1);
        let (mut sink, mut stream) = ws.split();
        let mut ping = tokio::time::interval(Duration::from_secs(20));
        ping.tick().await;

        let outcome: Option<ExitCode> = loop {
            let actions = tokio::select! {
                msg = stream.next() => match msg {
                    Some(Ok(Message::Text(t))) => engine.on_text(&t),
                    Some(Ok(Message::Binary(b))) => engine.on_binary(&b),
                    Some(Ok(_)) => continue,
                    _ => break None,
                },
                ev = pty_rx.recv() => match ev {
                    Some(PtyEvent::Output(data)) => engine.output(&data),
                    Some(PtyEvent::Exited) | None => {
                        eprintln!("the shared program exited; ending the share");
                        let mut a = engine.end();
                        a.push(Action::Ended { reason: EndReason::Stopped });
                        a
                    }
                },
                line = stdin.next_line(), if !pending.is_empty() => {
                    let Some(viewer) = pending.pop_front() else { continue };
                    match line {
                        Ok(Some(l)) if l.trim().eq_ignore_ascii_case("y") => engine.approve(viewer),
                        _ => engine.deny(viewer),
                    }
                }
                _ = ping.tick() => vec![engine.ping()],
            };
            let mut done = None;
            for action in actions {
                let sent = match action {
                    Action::Text(t) => sink.send(Message::Text(t.into())).await.is_ok(),
                    Action::Binary(b) => sink.send(Message::Binary(b.into())).await.is_ok(),
                    Action::Ready { expires_at } => {
                        if !shown_links {
                            shown_links = true;
                            for (access, link) in engine.links(&args.viewer_origin) {
                                println!("{}: {link}", access_label(access));
                            }
                            eprintln!("sharing until {expires_at} (Unix time)");
                        } else {
                            eprintln!("reconnected to the relay");
                        }
                        true
                    }
                    Action::JoinRequest {
                        viewer,
                        access,
                        ip,
                        ua,
                    } => {
                        if args.auto_approve {
                            for a in engine.approve(viewer) {
                                if let Action::Binary(b) = a {
                                    let _ = sink.send(Message::Binary(b.into())).await;
                                }
                            }
                            eprintln!(
                                "viewer {viewer} joined ({}) from {ip}",
                                access_label(access)
                            );
                        } else {
                            eprintln!(
                                "viewer {viewer} wants to join ({}) from {ip} — {ua}. Allow? [y/N]",
                                access_label(access)
                            );
                            pending.push_back(viewer);
                        }
                        true
                    }
                    Action::Rejoined { viewer } => {
                        eprintln!("viewer {viewer} reconnected");
                        true
                    }
                    Action::Input { data, .. } => pty_writer.write_all(&data).is_ok(),
                    Action::ViewerLeft { viewer } => {
                        eprintln!("viewer {viewer} left");
                        true
                    }
                    Action::Dropped { viewer, error } => {
                        eprintln!("dropped a frame from viewer {viewer}: {error}");
                        true
                    }
                    Action::LinkRotated { .. } => true,
                    // The demo uses the synchronous buffer snapshot.
                    Action::SnapshotRequest { .. } => true,
                    Action::ExpiryChanged { expires_at } => {
                        eprintln!("sharing until {expires_at} (Unix time)");
                        true
                    }
                    Action::Ended { reason } => {
                        eprintln!("share ended: {reason:?}");
                        done = Some(ExitCode::SUCCESS);
                        true
                    }
                    Action::Refused { code } => {
                        eprintln!("the relay refused the share: {code:?}");
                        done = Some(ExitCode::from(4));
                        true
                    }
                };
                if !sent {
                    break;
                }
            }
            if let Some(code) = done {
                let _ = sink.close().await;
                break Some(code);
            }
        };
        if let Some(code) = outcome {
            return code;
        }
        eprintln!("relay connection lost; reconnecting");
        engine.connection_lost();
        pending.clear();
    }
}

fn access_label(access: Access) -> &'static str {
    match access {
        Access::View => "view only",
        Access::Type => "can type",
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn start_pty(
    args: &Args,
    events: mpsc::UnboundedSender<PtyEvent>,
) -> Result<Box<dyn Write + Send>, String> {
    let pty = native_pty_system();
    let pair = pty
        .openpty(PtySize {
            rows: args.rows,
            cols: args.cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| e.to_string())?;
    let mut cmd = match args.command.split_first() {
        Some((program, rest)) => {
            let mut c = CommandBuilder::new(program);
            c.args(rest);
            c
        }
        None => CommandBuilder::new_default_prog(),
    };
    cmd.env("TERM", "xterm-256color");
    let mut child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    let writer = pair.master.take_writer().map_err(|e| e.to_string())?;
    let exit_events = events.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if events.send(PtyEvent::Output(buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
            }
        }
    });
    std::thread::spawn(move || {
        let _ = child.wait();
        let _ = exit_events.send(PtyEvent::Exited);
    });
    // Keep the master alive for the life of the process.
    std::mem::forget(pair.master);
    Ok(writer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Args, String> {
        parse_args(s.split_whitespace().map(str::to_owned))
    }

    #[test]
    fn parses_flags_and_command() {
        let a = parse("--relay wss://r/ --viewer-origin https://v --access both --expires 90 --approve auto --size 80x24 -- htop -d 5").unwrap();
        assert_eq!(a.relay, "wss://r");
        assert_eq!(a.accesses, vec![Access::View, Access::Type]);
        assert_eq!(a.expires_minutes, 90);
        assert!(a.auto_approve);
        assert_eq!((a.cols, a.rows), (80, 24));
        assert_eq!(a.command, ["htop", "-d", "5"]);
    }

    #[test]
    fn rejects_bad_values_and_missing_urls() {
        assert!(parse("--relay wss://r").is_err());
        assert!(parse("--relay wss://r --viewer-origin https://v --expires 721").is_err());
        assert!(parse("--relay wss://r --viewer-origin https://v --access admin").is_err());
        let d = parse("--relay wss://r --viewer-origin https://v").unwrap();
        assert_eq!(d.accesses, vec![Access::View]);
        assert!(!d.auto_approve);
    }
}
