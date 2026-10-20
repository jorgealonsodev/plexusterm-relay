//! `plexusterm-relay` binary: reads `RELAY_*` and `VIEWER_*` from the
//! environment, serves the relay and, when `VIEWER_LISTEN` is set, the web
//! viewer on a second listener.

use std::process::ExitCode;

use plexusterm_relay::{Config, serve};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

/// `--healthcheck`: GET /healthz on the local relay port, for container
/// health checks in an image without a shell or curl. Exit 0 when healthy.
fn healthcheck() -> ExitCode {
    use std::io::{Read, Write};
    let port = std::env::var("RELAY_LISTEN")
        .ok()
        .and_then(|l| l.rsplit_once(':').map(|(_, p)| p.to_owned()))
        .unwrap_or_else(|| "8080".to_owned());
    let timeout = std::time::Duration::from_secs(3);
    let ok = (|| -> std::io::Result<bool> {
        let addr = format!("127.0.0.1:{port}")
            .parse()
            .map_err(|_| std::io::ErrorKind::InvalidInput)?;
        let mut stream = std::net::TcpStream::connect_timeout(&addr, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response.starts_with("HTTP/1.0 200") || response.starts_with("HTTP/1.1 200"))
    })();
    if matches!(ok, Ok(true)) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Exit codes: 0 clean shutdown, 2 bad configuration, 3 cannot listen.
#[tokio::main]
async fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--healthcheck") {
        return healthcheck();
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let config = match Config::from_env_with(|k| std::env::var(k).ok()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("plexusterm-relay: {e}");
            return ExitCode::from(2);
        }
    };
    let listener = match TcpListener::bind(config.listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("plexusterm-relay: cannot listen on {}: {e}", config.listen);
            return ExitCode::from(3);
        }
    };
    let viewer =
        match plexusterm_relay::viewer::ViewerConfig::from_env_with(|k| std::env::var(k).ok()) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("plexusterm-relay: {e}");
                return ExitCode::from(2);
            }
        };
    if let Some(viewer) = viewer {
        let app = match plexusterm_relay::viewer::router(&viewer) {
            Ok(app) => app,
            Err(e) => {
                eprintln!("plexusterm-relay: viewer: {e}");
                return ExitCode::from(2);
            }
        };
        let listener = match TcpListener::bind(viewer.listen).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("plexusterm-relay: cannot listen on {}: {e}", viewer.listen);
                return ExitCode::from(3);
            }
        };
        tracing::info!(addr = %viewer.listen, "viewer listening");
        tokio::spawn(plexusterm_relay::viewer::serve(listener, app));
    }
    tracing::info!(addr = %config.listen, "relay listening");
    match serve(listener, config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("plexusterm-relay: {e}");
            ExitCode::from(3)
        }
    }
}
