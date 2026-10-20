//! `plexusterm-relay` binary: reads `RELAY_*` and `VIEWER_*` from the
//! environment, serves the relay and, when `VIEWER_LISTEN` is set, the web
//! viewer on a second listener.

use std::process::ExitCode;

use plexusterm_relay::{Config, serve};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

/// Exit codes: 0 clean shutdown, 2 bad configuration, 3 cannot listen.
#[tokio::main]
async fn main() -> ExitCode {
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
