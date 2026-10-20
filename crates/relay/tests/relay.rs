//! Relay behavior through its public WebSocket interface.

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use plexusterm_relay::{Config, Limits, Timings, serve};
use plexusterm_share_protocol::keys::{Challenge, DerivedKeys, Role, Secret, ShareId};
use plexusterm_share_protocol::wire::{
    EndReason, ErrorCode, LeftReason, LinkRegistration, RelayToSharer, RelayToViewer,
    SharerToRelay, ViewerToRelay, encode_routed,
};
use serde_json::Value;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

const TOKEN: &str = "test-token-0123456789";
const WAIT: Duration = Duration::from_secs(5);

fn config(limits: Limits, timings: Timings) -> Config {
    Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        tokens: vec![TOKEN.into()],
        trust_proxy: false,
        limits,
        timings,
    }
}

fn fast_timings() -> Timings {
    Timings {
        handshake: Duration::from_secs(2),
        idle_connection: Duration::from_secs(10),
        sharer_away: Duration::from_millis(300),
        sharer_offline: Duration::from_millis(1500),
        no_viewers: Duration::from_secs(30),
    }
}

async fn start(config: Config) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, config));
    addr
}

async fn relay() -> SocketAddr {
    start(config(Limits::default(), fast_timings())).await
}

struct Client {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    challenge: Challenge,
}

impl Client {
    async fn connect(addr: SocketAddr, path: &str) -> Self {
        let (mut ws, _) = connect_async(format!("ws://{addr}{path}")).await.unwrap();
        let hello = next_text(&mut ws).await.expect("hello");
        assert_eq!(hello["t"], "hello");
        assert_eq!(hello["proto"], 1);
        let challenge = Challenge::from_b64(hello["challenge"].as_str().unwrap()).unwrap();
        Self { ws, challenge }
    }

    async fn send(&mut self, msg: &impl serde::Serialize) {
        let text = serde_json::to_string(msg).unwrap();
        self.ws.send(Message::Text(text.into())).await.unwrap();
    }

    async fn send_bin(&mut self, bytes: &[u8]) {
        self.ws
            .send(Message::Binary(bytes.to_vec().into()))
            .await
            .unwrap();
    }

    async fn text(&mut self) -> Value {
        next_text(&mut self.ws)
            .await
            .expect("expected a text message")
    }

    async fn bin(&mut self) -> Vec<u8> {
        loop {
            match tokio::time::timeout(WAIT, self.ws.next()).await {
                Ok(Some(Ok(Message::Binary(b)))) => return b.to_vec(),
                Ok(Some(Ok(Message::Text(t)))) => panic!("expected binary, got {t}"),
                Ok(Some(Ok(_))) => continue,
                other => panic!("expected binary, got {other:?}"),
            }
        }
    }

    /// True when the relay closes the connection without more data.
    async fn closed(&mut self) -> bool {
        loop {
            match tokio::time::timeout(WAIT, self.ws.next()).await {
                Ok(None | Some(Err(_)) | Some(Ok(Message::Close(_)))) => return true,
                Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
                _ => return false,
            }
        }
    }
}

async fn next_text(ws: &mut WebSocketStream<MaybeTlsStream<TcpStream>>) -> Option<Value> {
    loop {
        match tokio::time::timeout(WAIT, ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => return serde_json::from_str(&t).ok(),
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
            _ => return None,
        }
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct TestShare {
    id: ShareId,
    owner: DerivedKeys,
    view: DerivedKeys,
    sharer: Client,
}

fn registration(keys: &DerivedKeys) -> LinkRegistration {
    LinkRegistration {
        link_id: keys.link_id,
        verifier: keys.verifier(),
    }
}

async fn create_with(addr: SocketAddr, expires_at: u64) -> TestShare {
    let id = ShareId::random();
    let owner = DerivedKeys::derive(&Secret::random());
    let view = DerivedKeys::derive(&Secret::random());
    let mut sharer = Client::connect(addr, "/v1/sharer").await;
    sharer
        .send(&SharerToRelay::Create {
            proto: 1,
            token: TOKEN.into(),
            share_id: id,
            owner_verifier: owner.verifier(),
            links: vec![registration(&view)],
            expires_at,
        })
        .await;
    let ready = sharer.text().await;
    assert_eq!(ready["t"], "ready", "{ready}");
    assert_eq!(ready["expires_at"], expires_at);
    TestShare {
        id,
        owner,
        view,
        sharer,
    }
}

async fn create(addr: SocketAddr) -> TestShare {
    create_with(addr, now() + 3600).await
}

async fn join_with(addr: SocketAddr, id: ShareId, keys: &DerivedKeys) -> (Client, Value) {
    let mut viewer = Client::connect(addr, "/v1/viewer").await;
    let proof = keys.prove(Role::Viewer, &id, &viewer.challenge);
    viewer
        .send(&ViewerToRelay::Join {
            proto: 1,
            share_id: id,
            link_id: keys.link_id,
            proof,
        })
        .await;
    let answer = viewer.text().await;
    (viewer, answer)
}

async fn join(addr: SocketAddr, share: &mut TestShare) -> (Client, u32) {
    let (viewer, answer) = join_with(addr, share.id, &share.view).await;
    assert_eq!(answer["t"], "accepted", "{answer}");
    let id = answer["viewer"].as_u64().unwrap() as u32;
    let note = share.sharer.text().await;
    assert_eq!(note["t"], "join");
    assert_eq!(note["viewer"], id);
    assert_eq!(note["link_id"], share.view.link_id.to_b64());
    assert_eq!(note["ip"], "127.0.0.1");
    (viewer, id)
}

fn error_code(v: &Value) -> ErrorCode {
    assert_eq!(v["t"], "error", "{v}");
    serde_json::from_value(v["code"].clone()).unwrap()
}

#[tokio::test]
async fn create_validates_token_version_expiry_and_id() {
    let addr = relay().await;
    let make = |token: &str, proto: u16, share_id: ShareId, expires_at: u64| {
        let keys = DerivedKeys::derive(&Secret::random());
        SharerToRelay::Create {
            proto,
            token: token.into(),
            share_id,
            owner_verifier: keys.verifier(),
            links: vec![registration(&keys)],
            expires_at,
        }
    };
    let cases = [
        (
            make("wrong-token-0123456789", 1, ShareId::random(), now() + 60),
            ErrorCode::Unauthorized,
        ),
        (
            make(TOKEN, 2, ShareId::random(), now() + 60),
            ErrorCode::Version,
        ),
        (
            make(TOKEN, 1, ShareId::random(), now() + 12 * 3600 + 60),
            ErrorCode::BadRequest,
        ),
        (
            make(TOKEN, 1, ShareId::random(), now().saturating_sub(5)),
            ErrorCode::BadRequest,
        ),
    ];
    for (msg, code) in cases {
        let mut c = Client::connect(addr, "/v1/sharer").await;
        c.send(&msg).await;
        assert_eq!(error_code(&c.text().await), code);
        assert!(c.closed().await);
    }
    let share = create(addr).await;
    let mut dup = Client::connect(addr, "/v1/sharer").await;
    dup.send(&make(TOKEN, 1, share.id, now() + 60)).await;
    assert_eq!(error_code(&dup.text().await), ErrorCode::Conflict);
}

#[tokio::test]
async fn concurrent_shares_per_token_are_limited_and_freed_on_end() {
    let limits = Limits {
        max_shares_per_token: 1,
        ..Limits::default()
    };
    let addr = start(config(limits, fast_timings())).await;
    let mut first = create(addr).await;
    let keys = DerivedKeys::derive(&Secret::random());
    let second = SharerToRelay::Create {
        proto: 1,
        token: TOKEN.into(),
        share_id: ShareId::random(),
        owner_verifier: keys.verifier(),
        links: vec![registration(&keys)],
        expires_at: now() + 60,
    };
    let mut c = Client::connect(addr, "/v1/sharer").await;
    c.send(&second).await;
    assert_eq!(error_code(&c.text().await), ErrorCode::TooManyShares);

    first.sharer.send(&SharerToRelay::End).await;
    assert_eq!(first.sharer.text().await["t"], "ended");
    create(addr).await;
}

#[tokio::test]
async fn twelve_hour_expiry_is_accepted() {
    let addr = relay().await;
    create_with(addr, now() + 12 * 3600 - 1).await;
}

#[tokio::test]
async fn frames_are_routed_between_viewer_and_sharer_unchanged() {
    let addr = relay().await;
    let mut share = create(addr).await;
    let (mut viewer, id) = join(addr, &mut share).await;
    viewer.send_bin(b"\x01noise-1").await;
    assert_eq!(share.sharer.bin().await, encode_routed(id, b"\x01noise-1"));
    share
        .sharer
        .send_bin(&encode_routed(id, b"\x02frame"))
        .await;
    assert_eq!(viewer.bin().await, b"\x02frame");
}

#[tokio::test]
async fn joins_need_a_valid_proof_for_a_live_share() {
    let addr = relay().await;
    let mut share = create(addr).await;
    let wrong = DerivedKeys::derive(&Secret::random());
    let (_, answer) = join_with(addr, share.id, &wrong).await;
    assert_eq!(error_code(&answer), ErrorCode::BadKey);
    let (_, answer) = join_with(addr, ShareId::random(), &share.view).await;
    assert_eq!(error_code(&answer), ErrorCode::NotFound);

    // Right link id, proof for another challenge: knowing the id is not enough.
    let mut replayer = Client::connect(addr, "/v1/viewer").await;
    replayer
        .send(&ViewerToRelay::Join {
            proto: 1,
            share_id: share.id,
            link_id: share.view.link_id,
            proof: share
                .view
                .prove(Role::Viewer, &share.id, &Challenge([0; 32])),
        })
        .await;
    assert_eq!(error_code(&replayer.text().await), ErrorCode::BadKey);

    share.sharer.send(&SharerToRelay::End).await;
    assert_eq!(share.sharer.text().await["t"], "ended");
    let (_, answer) = join_with(addr, share.id, &share.view).await;
    assert_eq!(error_code(&answer), ErrorCode::NotFound);
}

#[tokio::test]
async fn viewer_limit_refuses_with_full() {
    let limits = Limits {
        max_viewers: 2,
        ..Limits::default()
    };
    let addr = start(config(limits, fast_timings())).await;
    let mut share = create(addr).await;
    let _a = join(addr, &mut share).await;
    let _b = join(addr, &mut share).await;
    let (_, answer) = join_with(addr, share.id, &share.view).await;
    assert_eq!(error_code(&answer), ErrorCode::Full);
}

#[tokio::test]
async fn join_attempts_are_rate_limited_per_ip() {
    let limits = Limits {
        joins_per_minute: 3,
        ..Limits::default()
    };
    let addr = start(config(limits, fast_timings())).await;
    let share = create(addr).await;
    let wrong = DerivedKeys::derive(&Secret::random());
    for _ in 0..3 {
        let (_, answer) = join_with(addr, share.id, &wrong).await;
        assert_eq!(error_code(&answer), ErrorCode::BadKey);
    }
    let (_, answer) = join_with(addr, share.id, &share.view).await;
    assert_eq!(error_code(&answer), ErrorCode::RateLimited);
}

#[tokio::test]
async fn kick_and_rotate_lock_out_the_viewer_but_not_the_others() {
    let addr = relay().await;
    let mut share = create(addr).await;
    let (mut kicked, kicked_id) = join(addr, &mut share).await;
    let (mut other, other_id) = join(addr, &mut share).await;

    // Rotate first, then kick: once `kicked` arrives the old secret is dead.
    let rotated = DerivedKeys::derive(&Secret::random());
    share
        .sharer
        .send(&SharerToRelay::Rotate {
            link_id: share.view.link_id,
            new: registration(&rotated),
        })
        .await;
    share
        .sharer
        .send(&SharerToRelay::Kick { viewer: kicked_id })
        .await;
    assert_eq!(kicked.text().await["t"], "kicked");
    assert!(kicked.closed().await);

    let (_, answer) = join_with(addr, share.id, &share.view).await;
    assert_eq!(error_code(&answer), ErrorCode::BadKey);

    share
        .sharer
        .send_bin(&encode_routed(other_id, b"\x02still"))
        .await;
    assert_eq!(other.bin().await, b"\x02still");

    let (_, answer) = join_with(addr, share.id, &rotated).await;
    assert_eq!(answer["t"], "accepted");
}

#[tokio::test]
async fn denied_viewer_is_told_and_closed() {
    let addr = relay().await;
    let mut share = create(addr).await;
    let (mut viewer, id) = join(addr, &mut share).await;
    share.sharer.send(&SharerToRelay::Deny { viewer: id }).await;
    assert_eq!(viewer.text().await["t"], "denied");
    assert!(viewer.closed().await);
}

#[tokio::test]
async fn stop_sharing_ends_the_share_for_everyone() {
    let addr = relay().await;
    let mut share = create(addr).await;
    let (mut viewer, _) = join(addr, &mut share).await;
    share.sharer.send(&SharerToRelay::End).await;
    let ended = viewer.text().await;
    assert_eq!(ended["t"], "ended");
    assert_eq!(ended["reason"], "stopped");
    assert!(viewer.closed().await);
    assert_eq!(share.sharer.text().await["reason"], "stopped");
}

#[tokio::test]
async fn relay_ends_the_share_at_expiry_without_the_sharer() {
    let timings = Timings {
        sharer_offline: Duration::from_secs(30),
        ..fast_timings()
    };
    let addr = start(config(Limits::default(), timings)).await;
    let mut share = create_with(addr, now() + 2).await;
    let (mut viewer, _) = join(addr, &mut share).await;
    drop(share.sharer);
    loop {
        let msg = viewer.text().await;
        if msg["t"] == "ended" {
            assert_eq!(msg["reason"], "expired");
            break;
        }
        assert_eq!(msg["t"], "sharer_away");
    }
}

#[tokio::test]
async fn expiry_changes_reach_viewers_and_are_bounded() {
    let addr = relay().await;
    let mut share = create(addr).await;
    let (mut viewer, _) = join(addr, &mut share).await;
    let later = now() + 7200;
    share
        .sharer
        .send(&SharerToRelay::SetExpiry { expires_at: later })
        .await;
    let msg = viewer.text().await;
    assert_eq!(msg["t"], "expiry");
    assert_eq!(msg["expires_at"], later);
    assert_eq!(share.sharer.text().await["expires_at"], later);

    share
        .sharer
        .send(&SharerToRelay::SetExpiry {
            expires_at: now() + 13 * 3600,
        })
        .await;
    assert_eq!(
        error_code(&share.sharer.text().await),
        ErrorCode::BadRequest
    );
}

#[tokio::test]
async fn sharer_can_resume_with_owner_proof_and_viewers_are_told() {
    let addr = relay().await;
    let mut share = create(addr).await;
    let (mut viewer, id) = join(addr, &mut share).await;
    drop(share.sharer);
    assert_eq!(viewer.text().await["t"], "sharer_away");
    viewer.send_bin(b"\x02typed-while-away").await;

    let mut impostor = Client::connect(addr, "/v1/sharer").await;
    let fake = DerivedKeys::derive(&Secret::random());
    impostor
        .send(&SharerToRelay::Resume {
            proto: 1,
            token: TOKEN.into(),
            share_id: share.id,
            owner_proof: fake.prove(Role::Owner, &share.id, &impostor.challenge),
        })
        .await;
    assert_eq!(error_code(&impostor.text().await), ErrorCode::Conflict);

    // A viewer proof is never accepted as an owner proof.
    let mut confused = Client::connect(addr, "/v1/sharer").await;
    confused
        .send(&SharerToRelay::Resume {
            proto: 1,
            token: TOKEN.into(),
            share_id: share.id,
            owner_proof: share
                .owner
                .prove(Role::Viewer, &share.id, &confused.challenge),
        })
        .await;
    assert_eq!(error_code(&confused.text().await), ErrorCode::Conflict);

    let mut back = Client::connect(addr, "/v1/sharer").await;
    back.send(&SharerToRelay::Resume {
        proto: 1,
        token: TOKEN.into(),
        share_id: share.id,
        owner_proof: share.owner.prove(Role::Owner, &share.id, &back.challenge),
    })
    .await;
    let ready = back.text().await;
    assert_eq!(ready["t"], "ready");
    assert_eq!(ready["viewers"][0]["viewer"], id);
    assert_eq!(back.bin().await, encode_routed(id, b"\x02typed-while-away"));
    assert_eq!(viewer.text().await["t"], "sharer_back");
}

#[tokio::test]
async fn share_ends_offline_when_the_sharer_does_not_return() {
    let addr = relay().await;
    let mut share = create(addr).await;
    let (mut viewer, _) = join(addr, &mut share).await;
    drop(share.sharer);
    assert_eq!(viewer.text().await["t"], "sharer_away");
    let ended = viewer.text().await;
    assert_eq!(ended["t"], "ended");
    assert_eq!(ended["reason"], "offline");
}

#[tokio::test]
async fn share_without_viewers_ends_idle() {
    let timings = Timings {
        no_viewers: Duration::from_millis(400),
        ..fast_timings()
    };
    let addr = start(config(Limits::default(), timings)).await;
    let mut share = create(addr).await;
    let (viewer, _) = join(addr, &mut share).await;
    drop(viewer);
    let left = share.sharer.text().await;
    assert_eq!(left["t"], "left");
    assert_eq!(left["reason"], "closed");
    let ended = share.sharer.text().await;
    assert_eq!(ended["t"], "ended");
    assert_eq!(ended["reason"], "idle");
}

#[tokio::test]
async fn slow_viewer_is_disconnected_not_dropped_from() {
    let limits = Limits {
        viewer_queue_bytes: 128 * 1024,
        bytes_per_sec: 1 << 30,
        ..Limits::default()
    };
    let addr = start(config(limits, fast_timings())).await;
    let mut share = create(addr).await;
    let (_stalled, id) = join(addr, &mut share).await;
    let chunk = encode_routed(id, &vec![0x02; 60 * 1024]);
    let mut sent = 0usize;
    let left = loop {
        share.sharer.send_bin(&chunk).await;
        sent += chunk.len();
        assert!(sent < 512 * 1024 * 1024, "viewer was never disconnected");
        if let Ok(Some(Ok(Message::Text(t)))) =
            tokio::time::timeout(Duration::from_millis(1), share.sharer.ws.next()).await
        {
            break serde_json::from_str::<Value>(&t).unwrap();
        }
    };
    assert_eq!(left["t"], "left");
    assert_eq!(
        serde_json::from_value::<LeftReason>(left["reason"].clone()).unwrap(),
        LeftReason::Slow
    );
}

#[tokio::test]
async fn oversized_message_is_refused_visibly() {
    let addr = relay().await;
    let mut share = create(addr).await;
    let (mut viewer, _) = join(addr, &mut share).await;
    viewer.send_bin(&vec![0u8; 64 * 1024 + 1]).await;
    assert_eq!(error_code(&viewer.text().await), ErrorCode::TooLarge);
    assert!(viewer.closed().await);
}

#[tokio::test]
async fn pings_are_answered() {
    let addr = relay().await;
    let mut share = create(addr).await;
    share.sharer.send(&SharerToRelay::Ping).await;
    assert_eq!(share.sharer.text().await, serde_json::json!({"t": "pong"}));
    let (mut viewer, _) = join(addr, &mut share).await;
    viewer.send(&ViewerToRelay::Ping).await;
    assert_eq!(viewer.text().await, serde_json::json!({"t": "pong"}));
}

#[tokio::test]
async fn messages_keep_their_documented_shape() {
    // Guards the JSON the TypeScript viewer parses.
    let ended = serde_json::to_value(RelayToViewer::Ended {
        reason: EndReason::Offline,
    })
    .unwrap();
    assert_eq!(
        ended,
        serde_json::json!({"t": "ended", "reason": "offline"})
    );
    let left = serde_json::to_value(RelayToSharer::Left {
        viewer: 3,
        reason: LeftReason::Slow,
    })
    .unwrap();
    assert_eq!(
        left,
        serde_json::json!({"t": "left", "viewer": 3, "reason": "slow"})
    );
}

#[tokio::test]
async fn accepted_is_the_first_answer_even_while_the_sharer_is_away() {
    let addr = relay().await;
    let mut share = create(addr).await;
    let (mut first, _) = join(addr, &mut share).await;
    drop(share.sharer);
    assert_eq!(first.text().await["t"], "sharer_away");

    let (mut late, answer) = join_with(addr, share.id, &share.view).await;
    assert_eq!(answer["t"], "accepted", "{answer}");
    assert_eq!(late.text().await["t"], "sharer_away");
}

/// Joins with a given `X-Forwarded-For` header; returns the IP the relay
/// reports to the sharer, or the refusal code.
async fn join_forwarded(
    addr: SocketAddr,
    share: &mut TestShare,
    forwarded_for: &str,
) -> Result<String, ErrorCode> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut req = format!("ws://{addr}/v1/viewer")
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("x-forwarded-for", forwarded_for.parse().unwrap());
    let (mut ws, _) = connect_async(req).await.unwrap();
    let hello = next_text(&mut ws).await.unwrap();
    let challenge = Challenge::from_b64(hello["challenge"].as_str().unwrap()).unwrap();
    let mut viewer = Client { ws, challenge };
    viewer
        .send(&ViewerToRelay::Join {
            proto: 1,
            share_id: share.id,
            link_id: share.view.link_id,
            proof: share.view.prove(Role::Viewer, &share.id, &viewer.challenge),
        })
        .await;
    let answer = viewer.text().await;
    if answer["t"] != "accepted" {
        return Err(error_code(&answer));
    }
    // Earlier viewers of this helper have closed: skip their `left`.
    loop {
        let note = share.sharer.text().await;
        if note["t"] == "join" {
            return Ok(note["ip"].as_str().unwrap().to_owned());
        }
    }
}

#[tokio::test]
async fn behind_a_proxy_the_client_ip_is_the_entry_the_proxy_added() {
    let limits = Limits {
        joins_per_minute: 2,
        ..Limits::default()
    };
    let addr = start(Config {
        trust_proxy: true,
        ..config(limits, fast_timings())
    })
    .await;
    let mut share = create(addr).await;

    // Nginx Proxy Manager appends the real address to whatever the client
    // sent: the first entries are the client's own, possibly forged.
    assert_eq!(
        join_forwarded(addr, &mut share, "198.51.100.1, 203.0.113.7").await,
        Ok("203.0.113.7".to_owned())
    );
    // Rotating a forged first entry does not escape the per-IP limit.
    assert_eq!(
        join_forwarded(addr, &mut share, "198.51.100.2, 203.0.113.7").await,
        Ok("203.0.113.7".to_owned())
    );
    assert_eq!(
        join_forwarded(addr, &mut share, "198.51.100.3, 203.0.113.7").await,
        Err(ErrorCode::RateLimited)
    );
    // A single entry (deploy/nginx.conf sets $remote_addr) is used as is.
    assert_eq!(
        join_forwarded(addr, &mut share, "192.0.2.44").await,
        Ok("192.0.2.44".to_owned())
    );
}
