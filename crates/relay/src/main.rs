//! `plexusterm-relay` binary: reads `RELAY_*` from the environment and serves.

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
    tracing::info!(addr = %config.listen, "relay listening");
    match serve(listener, config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("plexusterm-relay: {e}");
            ExitCode::from(3)
        }
    }
}
