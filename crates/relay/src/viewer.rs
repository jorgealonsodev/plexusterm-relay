//! Static web viewer, served on its own listener so it can sit behind a
//! separate origin (PRD-share §5.1).
//!
//! Files are read into memory once at start, so requests never touch the
//! filesystem. Every response carries the viewer's security headers.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

#[derive(Debug, Clone)]
pub struct ViewerConfig {
    pub listen: SocketAddr,
    /// Output of `pnpm build` in `viewer/` (`index.html`, `assets/`, `build.txt`).
    pub dir: PathBuf,
    /// The relay's public WebSocket URL, e.g. `wss://relay.example`. It is
    /// written into the page and is the only `connect-src` the page allows.
    pub relay_url: String,
}

#[derive(Debug)]
pub enum ViewerError {
    BadRelayUrl,
    Read(PathBuf, std::io::Error),
}

impl std::fmt::Display for ViewerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ViewerError::BadRelayUrl => f.write_str(
                "RELAY_PUBLIC_URL must be a ws:// or wss:// URL with no path, query or quotes",
            ),
            ViewerError::Read(path, e) => write!(f, "cannot read {}: {e}", path.display()),
        }
    }
}

impl ViewerConfig {
    /// `None` unless `VIEWER_LISTEN` is set; then `RELAY_PUBLIC_URL` is
    /// required and `VIEWER_DIR` defaults to `/app/viewer`.
    pub fn from_env_with(
        get: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, crate::ConfigError> {
        let Some(listen) = get("VIEWER_LISTEN").filter(|v| !v.is_empty()) else {
            return Ok(None);
        };
        let listen = listen
            .parse()
            .map_err(|_| crate::ConfigError::Invalid("VIEWER_LISTEN"))?;
        let relay_url = get("RELAY_PUBLIC_URL")
            .filter(|u| relay_origin(u).is_some())
            .ok_or(crate::ConfigError::Invalid("RELAY_PUBLIC_URL"))?;
        let dir = get("VIEWER_DIR")
            .unwrap_or_else(|| "/app/viewer".to_owned())
            .into();
        Ok(Some(Self {
            listen,
            dir,
            relay_url,
        }))
    }
}

/// Serves the viewer on `listener` until the process is stopped.
pub async fn serve(listener: tokio::net::TcpListener, app: Router) -> std::io::Result<()> {
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
}

struct Site {
    index: Vec<u8>,
    /// `wss://host[:port]`, served at `/relay.txt` so a PlexusTerm given a
    /// pasted share link knows which relay to join.
    relay: Vec<u8>,
    files: HashMap<String, (Vec<u8>, &'static str)>,
    headers: Vec<(HeaderName, HeaderValue)>,
}

/// Validates `url` and returns it as a CSP source (`wss://host[:port]`).
fn relay_origin(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("wss://")
        .map(|r| ("wss", r))
        .or_else(|| url.strip_prefix("ws://").map(|r| ("ws", r)))?;
    let (scheme, host) = (rest.0, rest.1.trim_end_matches('/'));
    let valid = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'));
    valid.then(|| format!("{scheme}://{host}"))
}

fn content_type(path: &str) -> &'static str {
    match Path::new(path).extension().and_then(|e| e.to_str()) {
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("html") => "text/html; charset=utf-8",
        Some("txt") => "text/plain; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

fn load(
    dir: &Path,
    prefix: &str,
    files: &mut HashMap<String, (Vec<u8>, &'static str)>,
) -> Result<(), ViewerError> {
    let entries = std::fs::read_dir(dir).map_err(|e| ViewerError::Read(dir.to_owned(), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| ViewerError::Read(dir.to_owned(), e))?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let key = format!("{prefix}{name}");
        if path.is_dir() {
            load(&path, &format!("{key}/"), files)?;
        } else {
            let bytes = std::fs::read(&path).map_err(|e| ViewerError::Read(path.clone(), e))?;
            files.insert(key.clone(), (bytes, content_type(&key)));
        }
    }
    Ok(())
}

pub fn router(config: &ViewerConfig) -> Result<Router, ViewerError> {
    let origin = relay_origin(&config.relay_url).ok_or(ViewerError::BadRelayUrl)?;
    let mut files = HashMap::new();
    load(&config.dir, "", &mut files)?;
    let (index, _) = files.remove("index.html").ok_or_else(|| {
        ViewerError::Read(
            config.dir.join("index.html"),
            std::io::ErrorKind::NotFound.into(),
        )
    })?;
    // `origin` passed the character check above, so it cannot break out of
    // the attribute.
    let index = String::from_utf8_lossy(&index)
        .replace("__RELAY_URL__", &origin)
        .into_bytes();
    let csp = format!(
        "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
         connect-src {origin}; img-src 'self' data:; font-src 'self'; base-uri 'none'; \
         form-action 'none'; frame-ancestors 'none'"
    );
    let static_headers = [
        (header::CONTENT_SECURITY_POLICY, csp.as_str()),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::CACHE_CONTROL, "no-store"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin",
        ),
        (
            HeaderName::from_static("cross-origin-resource-policy"),
            "same-origin",
        ),
        (
            HeaderName::from_static("permissions-policy"),
            "camera=(), microphone=(), geolocation=()",
        ),
    ];
    let mut headers = Vec::new();
    for (name, value) in static_headers {
        let value = HeaderValue::from_str(value).map_err(|_| ViewerError::BadRelayUrl)?;
        headers.push((name, value));
    }
    let site = Arc::new(Site {
        index,
        relay: format!("{origin}\n").into_bytes(),
        files,
        headers,
    });
    Ok(Router::new()
        .route("/s/{id}", get(index_page))
        .route("/s/{id}/", get(index_page))
        .route("/assets/{*file}", get(asset))
        .route("/build.txt", get(build))
        .route("/relay.txt", get(relay))
        .route("/healthz", get(|| async { "ok" }))
        .fallback(not_found)
        .with_state(site))
}

fn respond(site: &Site, status: StatusCode, body: Vec<u8>, kind: &'static str) -> Response {
    let mut res = (status, Body::from(body)).into_response();
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(kind));
    for (name, value) in &site.headers {
        h.insert(name.clone(), value.clone());
    }
    res
}

async fn index_page(State(site): State<Arc<Site>>, UrlPath(_id): UrlPath<String>) -> Response {
    respond(
        &site,
        StatusCode::OK,
        site.index.clone(),
        "text/html; charset=utf-8",
    )
}

async fn asset(State(site): State<Arc<Site>>, UrlPath(file): UrlPath<String>) -> Response {
    match site.files.get(&format!("assets/{file}")) {
        Some((body, kind)) => respond(&site, StatusCode::OK, body.clone(), kind),
        None => not_found(State(site)).await,
    }
}

async fn build(State(site): State<Arc<Site>>) -> Response {
    match site.files.get("build.txt") {
        Some((body, kind)) => respond(&site, StatusCode::OK, body.clone(), kind),
        None => not_found(State(site)).await,
    }
}

async fn relay(State(site): State<Arc<Site>>) -> Response {
    respond(
        &site,
        StatusCode::OK,
        site.relay.clone(),
        "text/plain; charset=utf-8",
    )
}

async fn not_found(State(site): State<Arc<Site>>) -> Response {
    respond(
        &site,
        StatusCode::NOT_FOUND,
        b"not found\n".to_vec(),
        "text/plain; charset=utf-8",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::Request;
    use tower::ServiceExt;

    /// A fresh built-viewer directory per call; tests run in parallel.
    fn site_dir() -> PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "plexusterm-viewer-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(dir.join("assets")).unwrap();
        std::fs::write(
            dir.join("index.html"),
            r#"<meta name="plexusterm-relay" content="__RELAY_URL__"><script src="/assets/app.js"></script>"#,
        )
        .unwrap();
        std::fs::write(dir.join("assets/app.js"), "console.log(1)").unwrap();
        std::fs::write(dir.join("build.txt"), "abc123\n").unwrap();
        dir
    }

    fn app(relay_url: &str) -> Router {
        let dir = site_dir();
        let app = router(&ViewerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            dir: dir.clone(),
            relay_url: relay_url.into(),
        })
        .unwrap();
        // Everything is in memory now; the files are no longer needed.
        std::fs::remove_dir_all(dir).unwrap();
        app
    }

    async fn get(app: Router, path: &str) -> Response {
        app.oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn share_page_carries_relay_url_and_security_headers() {
        let res = get(
            app("wss://relay.example:8443/"),
            "/s/AAAAAAAAAAAAAAAAAAAAAA",
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK);
        let h = res.headers();
        let csp = h[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert!(
            csp.contains("connect-src wss://relay.example:8443;"),
            "{csp}"
        );
        assert!(csp.contains("script-src 'self';"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert_eq!(h[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        let body = to_bytes(res.into_body(), 1 << 20).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            body.contains(r#"content="wss://relay.example:8443""#),
            "{body}"
        );
    }

    #[tokio::test]
    async fn relay_url_is_published_for_pasted_share_links() {
        let res = get(app("wss://relay.example:8443/"), "/relay.txt").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        assert_eq!(res.headers()[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(
            to_bytes(res.into_body(), 128).await.unwrap(),
            "wss://relay.example:8443\n"
        );
    }

    #[tokio::test]
    async fn assets_and_build_hash_are_served_with_the_same_headers() {
        let res = get(app("wss://r.example"), "/assets/app.js").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()[header::CONTENT_TYPE],
            "text/javascript; charset=utf-8"
        );
        assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
        let res = get(app("wss://r.example"), "/build.txt").await;
        assert_eq!(to_bytes(res.into_body(), 64).await.unwrap(), "abc123\n");
    }

    #[tokio::test]
    async fn unknown_paths_are_not_found_and_never_read_the_disk() {
        for path in [
            "/",
            "/assets/../index.html",
            "/assets/missing.js",
            "/etc/passwd",
        ] {
            let res = get(app("wss://r.example"), path).await;
            assert_eq!(res.status(), StatusCode::NOT_FOUND, "{path}");
            assert_eq!(res.headers()[header::REFERRER_POLICY], "no-referrer");
        }
    }

    #[test]
    fn viewer_is_optional_and_needs_a_public_relay_url() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        assert!(ViewerConfig::from_env_with(env(&[])).unwrap().is_none());
        assert!(ViewerConfig::from_env_with(env(&[("VIEWER_LISTEN", "0.0.0.0:8081")])).is_err());
        let c = ViewerConfig::from_env_with(env(&[
            ("VIEWER_LISTEN", "0.0.0.0:8081"),
            ("RELAY_PUBLIC_URL", "wss://relay.example"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(c.dir, PathBuf::from("/app/viewer"));
    }

    #[test]
    fn relay_url_must_be_a_plain_websocket_origin() {
        assert_eq!(
            relay_origin("wss://relay.example/").as_deref(),
            Some("wss://relay.example")
        );
        assert_eq!(
            relay_origin("ws://127.0.0.1:8080").as_deref(),
            Some("ws://127.0.0.1:8080")
        );
        for bad in [
            "https://relay.example",
            "wss://",
            "wss://r.example/path",
            "wss://a\"b",
            "wss://a b",
        ] {
            assert_eq!(relay_origin(bad), None, "{bad}");
        }
    }
}
