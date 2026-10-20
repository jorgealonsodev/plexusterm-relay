//! The reference viewer binary against a real relay and sharer engine:
//! it renders the shared output and exits when the share ends.

use std::process::Stdio;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use plexusterm_relay::{Config, Limits, Timings, serve};
use plexusterm_share_client::sharer::{Action, SharerConfig, SharerEngine};
use plexusterm_share_protocol::content::Access;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

const TOKEN: &str = "watch-token-0123456789";

enum Cmd {
    Output(&'static [u8]),
    End,
}

#[tokio::test]
async fn watch_renders_the_share_and_exits_when_it_ends() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(
        listener,
        Config {
            listen: addr,
            tokens: vec![TOKEN.into()],
            trust_proxy: false,
            limits: Limits::default(),
            timings: Timings::default(),
        },
    ));

    // Sharer: approves every join and forwards commands.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut engine = SharerEngine::new(SharerConfig {
        token: TOKEN.into(),
        expires_at: now + 600,
        accesses: vec![Access::View],
        cols: 80,
        rows: 24,
    });
    engine.output(b"before-join ");
    let (_, link) = engine.links("http://view.test").remove(0);
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<Cmd>();
    let (joined_tx, mut joined_rx) = mpsc::unbounded_channel::<()>();
    let (ws, _) = connect_async(format!("ws://{addr}/v1/sharer"))
        .await
        .unwrap();
    tokio::spawn(async move {
        let (mut sink, mut stream) = ws.split();
        loop {
            let mut actions = tokio::select! {
                m = stream.next() => match m {
                    Some(Ok(Message::Text(t))) => engine.on_text(&t),
                    Some(Ok(Message::Binary(b))) => engine.on_binary(&b),
                    Some(Ok(_)) => continue,
                    _ => break,
                },
                c = cmd_rx.recv() => match c {
                    Some(Cmd::Output(d)) => engine.output(d),
                    Some(Cmd::End) | None => engine.end(),
                },
            };
            while !actions.is_empty() {
                let mut more = Vec::new();
                for a in actions {
                    match a {
                        Action::Text(t) => sink.send(Message::Text(t.into())).await.unwrap(),
                        Action::Binary(b) => sink.send(Message::Binary(b.into())).await.unwrap(),
                        Action::JoinRequest { viewer, .. } => {
                            more.extend(engine.approve(viewer));
                            let _ = joined_tx.send(());
                        }
                        _ => {}
                    }
                }
                actions = more;
            }
        }
    });

    let mut watch = tokio::process::Command::new(env!("CARGO_BIN_EXE_plexusterm-share-watch"))
        .args(["--relay", &format!("ws://{addr}")])
        .env("PLEXUSTERM_SHARE_LINK", &link)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    tokio::time::timeout(Duration::from_secs(5), joined_rx.recv())
        .await
        .expect("viewer never asked to join");
    cmd_tx.send(Cmd::Output(b"LIVE-MARKER")).unwrap();

    let mut stdout = watch.stdout.take().unwrap();
    let mut seen = Vec::new();
    let mut buf = [0u8; 4096];
    tokio::time::timeout(Duration::from_secs(5), async {
        while !String::from_utf8_lossy(&seen).contains("LIVE-MARKER") {
            let n = stdout.read(&mut buf).await.unwrap();
            assert!(n > 0, "watch closed its output early");
            seen.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .expect("live output never reached the viewer");
    let seen = String::from_utf8_lossy(&seen).into_owned();
    assert!(seen.contains("before-join "), "snapshot missing: {seen:?}");

    cmd_tx.send(Cmd::End).unwrap();
    let status = tokio::time::timeout(Duration::from_secs(5), watch.wait())
        .await
        .expect("watch did not exit when the share ended")
        .unwrap();
    assert!(status.success(), "{status:?}");
    let mut stderr = String::new();
    watch
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .await
        .unwrap();
    assert!(stderr.contains("The share has ended"), "{stderr}");
    assert!(
        !stderr.contains(link.split('#').nth(1).unwrap()),
        "key printed"
    );
}
