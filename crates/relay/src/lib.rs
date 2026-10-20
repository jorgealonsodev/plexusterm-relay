//! PlexusTerm share relay.
//!
//! Matches share ids to viewers and forwards opaque frames. It holds no
//! keys, sees no content and persists nothing (PRD-share §5.1). The wire
//! contract is `docs/protocol.md`.

pub mod config;
mod conn;
mod hub;
mod share;
pub mod viewer;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use futures_util::StreamExt;
use futures_util::stream::SplitStream;
use plexusterm_share_protocol::PROTOCOL_VERSION;
use plexusterm_share_protocol::keys::Challenge;
use plexusterm_share_protocol::wire::{
    ErrorCode, Hello, RelayToSharer, RelayToViewer, SharerToRelay, ViewerToRelay, decode_routed,
};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tracing::debug;

pub use config::{Config, ConfigError, Limits, Timings};
use conn::{ConnTx, close, write_loop};
use hub::{Hub, NewShare, ShareHandle};
use share::ShareEvent;

const MAX_UA_LEN: usize = 200;

pub fn router(config: Config) -> Router {
    let hub = Hub::new(config);
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/sharer", get(sharer_upgrade))
        .route("/v1/viewer", get(viewer_upgrade))
        .with_state(hub)
}

/// Serves the relay on `listener` until the process is stopped.
pub async fn serve(listener: TcpListener, config: Config) -> std::io::Result<()> {
    let app = router(config).into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn upgrade(ws: WebSocketUpgrade, hub: &Hub) -> WebSocketUpgrade {
    // The socket accepts up to twice the limit so an oversized message can
    // be refused with a visible `too_large` error instead of a bare close.
    let max = hub.config.limits.max_message.saturating_mul(2);
    ws.max_message_size(max).max_frame_size(max)
}

/// Behind the trusted proxy, the client is the **last** `X-Forwarded-For`
/// entry: proxies such as Nginx Proxy Manager append the address they saw
/// to whatever the client sent, so earlier entries can be forged.
fn client_ip(hub: &Hub, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    if hub.config.trust_proxy
        && let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse().ok())
    {
        return ip;
    }
    peer.ip()
}

async fn sharer_upgrade(ws: WebSocketUpgrade, State(hub): State<Arc<Hub>>) -> Response {
    let ws = upgrade(ws, &hub);
    ws.on_upgrade(move |socket| sharer_session(socket, hub))
}

async fn viewer_upgrade(
    ws: WebSocketUpgrade,
    State(hub): State<Arc<Hub>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let ip = client_ip(&hub, peer, &headers);
    let ua: String = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .chars()
        .take(MAX_UA_LEN)
        .collect();
    let ws = upgrade(ws, &hub);
    ws.on_upgrade(move |socket| viewer_session(socket, hub, ip, ua))
}

/// Starts the writer task and sends `hello`.
fn open(hub: &Hub, socket: WebSocket) -> (ConnTx, SplitStream<WebSocket>, Challenge) {
    let (sink, stream) = socket.split();
    let (tx, rx, queued) = ConnTx::new(hub.conn_id());
    tokio::spawn(write_loop(sink, rx, queued));
    let challenge = Challenge::random();
    // Sharer and viewer `hello` messages serialize identically.
    tx.text(&RelayToViewer::Hello(Hello {
        proto: PROTOCOL_VERSION,
        challenge,
    }));
    (tx, stream, challenge)
}

enum Incoming {
    Text(String),
    Binary(Vec<u8>),
    TooLarge,
    Closed,
}

/// Next data message, or `Closed` on close, error or silence past `idle`.
async fn next(stream: &mut SplitStream<WebSocket>, idle: Duration, max: usize) -> Incoming {
    loop {
        let incoming = match timeout(idle, stream.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => Incoming::Text(t.to_string()),
            Ok(Some(Ok(Message::Binary(b)))) => Incoming::Binary(b.to_vec()),
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
            _ => return Incoming::Closed,
        };
        let len = match &incoming {
            Incoming::Text(t) => t.len(),
            Incoming::Binary(b) => b.len(),
            _ => 0,
        };
        return if len > max {
            Incoming::TooLarge
        } else {
            incoming
        };
    }
}

fn refuse<T: serde::Serialize>(tx: &ConnTx, msg: T) {
    tx.text(&msg);
    tx.close(close::NORMAL, "refused");
}

fn sharer_error(code: ErrorCode, message: &str) -> RelayToSharer {
    RelayToSharer::Error {
        code,
        message: message.into(),
    }
}

fn viewer_error(code: ErrorCode, message: &str) -> RelayToViewer {
    RelayToViewer::Error {
        code,
        message: message.into(),
    }
}

async fn wait_bucket(handle: &ShareHandle, n: usize) {
    let wait = match handle.bucket.lock() {
        Ok(mut b) => b.take(n),
        Err(poisoned) => poisoned.into_inner().take(n),
    };
    if !wait.is_zero() {
        tokio::time::sleep(wait).await;
    }
}

async fn sharer_session(socket: WebSocket, hub: Arc<Hub>) {
    let (tx, mut stream, challenge) = open(&hub, socket);
    let timings = hub.config.timings.clone();
    let max = hub.config.limits.max_message;
    let first = match timeout(timings.handshake, next(&mut stream, timings.handshake, max)).await {
        Ok(Incoming::Text(t)) => serde_json::from_str::<SharerToRelay>(&t).ok(),
        _ => None,
    };
    let handle = match first {
        Some(SharerToRelay::Create {
            proto,
            token,
            share_id,
            owner_verifier,
            links,
            expires_at,
        }) => {
            if proto != PROTOCOL_VERSION {
                return refuse(
                    &tx,
                    sharer_error(ErrorCode::Version, "unsupported protocol"),
                );
            }
            let new = NewShare {
                token,
                share_id,
                owner_verifier,
                links,
                expires_at,
            };
            if let Err(code) = hub.create(new, tx.clone()) {
                return refuse(&tx, sharer_error(code, "share refused"));
            }
            match hub.get(&share_id) {
                Some(h) => h,
                None => return,
            }
        }
        Some(SharerToRelay::Resume {
            proto,
            token,
            share_id,
            owner_proof,
        }) => {
            if proto != PROTOCOL_VERSION {
                return refuse(
                    &tx,
                    sharer_error(ErrorCode::Version, "unsupported protocol"),
                );
            }
            if hub.token_index(&token).is_none() {
                return refuse(
                    &tx,
                    sharer_error(ErrorCode::Unauthorized, "bad relay token"),
                );
            }
            let Some(handle) = hub.get(&share_id) else {
                return refuse(&tx, sharer_error(ErrorCode::NotFound, "share not found"));
            };
            let (reply, answer) = oneshot::channel();
            let _ = handle.events.send(ShareEvent::Resume {
                challenge,
                proof: owner_proof,
                conn: tx.clone(),
                reply,
            });
            match answer.await {
                Ok(Ok(())) => handle,
                Ok(Err(code)) => return refuse(&tx, sharer_error(code, "resume refused")),
                Err(_) => {
                    return refuse(&tx, sharer_error(ErrorCode::NotFound, "share not found"));
                }
            }
        }
        _ => {
            return refuse(
                &tx,
                sharer_error(ErrorCode::BadRequest, "expected create or resume"),
            );
        }
    };

    loop {
        match next(&mut stream, timings.idle_connection, max).await {
            Incoming::Text(t) => match serde_json::from_str::<SharerToRelay>(&t) {
                Ok(SharerToRelay::Ping) => tx.text(&RelayToSharer::Pong),
                Ok(msg) => {
                    let _ = handle.events.send(ShareEvent::SharerControl {
                        conn_id: tx.id,
                        msg,
                    });
                }
                Err(_) => {
                    tx.text(&sharer_error(ErrorCode::BadRequest, "malformed message"));
                    break;
                }
            },
            Incoming::Binary(b) => {
                wait_bucket(&handle, b.len()).await;
                match decode_routed(&b) {
                    Ok((viewer, payload)) => {
                        let _ = handle.events.send(ShareEvent::SharerBinary {
                            conn_id: tx.id,
                            viewer,
                            payload: payload.to_vec(),
                        });
                    }
                    Err(_) => {
                        tx.text(&sharer_error(ErrorCode::BadRequest, "malformed message"));
                        break;
                    }
                }
            }
            Incoming::TooLarge => {
                tx.text(&sharer_error(ErrorCode::TooLarge, "message too large"));
                break;
            }
            Incoming::Closed => break,
        }
    }
    let _ = handle
        .events
        .send(ShareEvent::SharerGone { conn_id: tx.id });
    tx.close(close::NORMAL, "closed");
}

async fn viewer_session(socket: WebSocket, hub: Arc<Hub>, ip: IpAddr, ua: String) {
    let (tx, mut stream, challenge) = open(&hub, socket);
    let timings = hub.config.timings.clone();
    let max = hub.config.limits.max_message;
    let first = match timeout(timings.handshake, next(&mut stream, timings.handshake, max)).await {
        Ok(Incoming::Text(t)) => serde_json::from_str::<ViewerToRelay>(&t).ok(),
        _ => None,
    };
    let Some(ViewerToRelay::Join {
        proto,
        share_id,
        link_id,
        proof,
    }) = first
    else {
        return refuse(&tx, viewer_error(ErrorCode::BadRequest, "expected join"));
    };
    if !hub.allow_join(ip) {
        return refuse(
            &tx,
            viewer_error(ErrorCode::RateLimited, "too many join attempts"),
        );
    }
    if proto != PROTOCOL_VERSION {
        return refuse(
            &tx,
            viewer_error(ErrorCode::Version, "unsupported protocol"),
        );
    }
    let Some(handle) = hub.get(&share_id) else {
        return refuse(&tx, viewer_error(ErrorCode::NotFound, "share not found"));
    };
    let (reply, answer) = oneshot::channel();
    let _ = handle.events.send(ShareEvent::ViewerJoin {
        link_id,
        challenge,
        proof,
        ip: ip.to_string(),
        ua,
        conn: tx.clone(),
        reply,
    });
    let viewer = match answer.await {
        // The share actor already queued `accepted` for this viewer.
        Ok(Ok((viewer, _))) => viewer,
        Ok(Err(code)) => return refuse(&tx, viewer_error(code, "join refused")),
        Err(_) => return refuse(&tx, viewer_error(ErrorCode::NotFound, "share not found")),
    };
    debug!(viewer, "viewer joined");

    loop {
        match next(&mut stream, timings.idle_connection, max).await {
            Incoming::Text(t) => match serde_json::from_str::<ViewerToRelay>(&t) {
                Ok(ViewerToRelay::Ping) => tx.text(&RelayToViewer::Pong),
                _ => {
                    tx.text(&viewer_error(ErrorCode::BadRequest, "unexpected message"));
                    break;
                }
            },
            Incoming::Binary(b) => {
                wait_bucket(&handle, b.len()).await;
                let _ = handle
                    .events
                    .send(ShareEvent::ViewerBinary { viewer, payload: b });
            }
            Incoming::TooLarge => {
                tx.text(&viewer_error(ErrorCode::TooLarge, "message too large"));
                break;
            }
            Incoming::Closed => break,
        }
    }
    let _ = handle.events.send(ShareEvent::ViewerGone { viewer });
    tx.close(close::NORMAL, "closed");
}
