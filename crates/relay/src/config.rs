//! Relay configuration, read from environment variables.

use std::net::SocketAddr;
use std::time::Duration;

/// Configurable limits (PRD §5.5 defaults).
#[derive(Debug, Clone)]
pub struct Limits {
    pub max_viewers: usize,
    /// Bytes per second per share, both directions together.
    pub bytes_per_sec: u64,
    pub max_message: usize,
    pub joins_per_minute: usize,
    pub max_shares_per_token: usize,
    /// A viewer whose outgoing queue exceeds this is disconnected.
    pub viewer_queue_bytes: usize,
    /// Bytes a viewer may send while the sharer is away before it is
    /// disconnected (it reconnects once the sharer is back).
    pub away_buffer_bytes: usize,
    pub max_links: usize,
    pub max_expiry: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_viewers: 10,
            bytes_per_sec: 2 * 1024 * 1024,
            max_message: plexusterm_share_protocol::MAX_MESSAGE_LEN,
            joins_per_minute: 20,
            max_shares_per_token: 50,
            viewer_queue_bytes: 2 * 1024 * 1024,
            away_buffer_bytes: 64 * 1024,
            max_links: 4,
            max_expiry: Duration::from_secs(12 * 60 * 60),
        }
    }
}

/// Timers of PRD §4.1 and §5.4. Fixed in production; tests shorten them.
#[derive(Debug, Clone)]
pub struct Timings {
    /// Time a new connection has to answer `hello` with `create`, `resume` or `join`.
    pub handshake: Duration,
    /// A connection silent for this long is closed (pings come every 20 s).
    pub idle_connection: Duration,
    /// No sharer for this long → `sharer_away` to viewers.
    pub sharer_away: Duration,
    /// No sharer for this long → share ends (`offline`).
    pub sharer_offline: Duration,
    /// No viewers for this long → share ends (`idle`).
    pub no_viewers: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(10),
            idle_connection: Duration::from_secs(60),
            sharer_away: Duration::from_secs(10),
            sharer_offline: Duration::from_secs(5 * 60),
            no_viewers: Duration::from_secs(30 * 60),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    /// Relay tokens allowed to create shares. Never logged.
    pub tokens: Vec<String>,
    /// Take the client IP from the last `X-Forwarded-For` entry (set only behind the
    /// shipped reverse proxy).
    pub trust_proxy: bool,
    pub limits: Limits,
    pub timings: Timings,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    MissingTokens,
    Invalid(&'static str),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::MissingTokens => {
                f.write_str("RELAY_TOKENS must list at least one token of 16+ characters")
            }
            ConfigError::Invalid(var) => write!(f, "{var} is not valid"),
        }
    }
}

impl Config {
    /// Reads `RELAY_*` variables through `get`, so tests need no real env.
    pub fn from_env_with(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let tokens: Vec<String> = get("RELAY_TOKENS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_owned)
            .collect();
        if tokens.is_empty() || tokens.iter().any(|t| t.len() < 16) {
            return Err(ConfigError::MissingTokens);
        }
        let listen = get("RELAY_LISTEN")
            .unwrap_or_else(|| "0.0.0.0:8080".to_owned())
            .parse()
            .map_err(|_| ConfigError::Invalid("RELAY_LISTEN"))?;
        let trust_proxy = match get("RELAY_TRUST_PROXY").as_deref() {
            None | Some("") | Some("0") | Some("false") => false,
            Some("1") | Some("true") => true,
            Some(_) => return Err(ConfigError::Invalid("RELAY_TRUST_PROXY")),
        };
        let mut limits = Limits::default();
        let num = |var: &'static str, default: usize| -> Result<usize, ConfigError> {
            match get(var) {
                None => Ok(default),
                Some(v) => match v.trim().parse::<usize>() {
                    Ok(n) if n > 0 => Ok(n),
                    _ => Err(ConfigError::Invalid(var)),
                },
            }
        };
        limits.max_viewers = num("RELAY_MAX_VIEWERS", limits.max_viewers)?;
        limits.bytes_per_sec = num("RELAY_BYTES_PER_SEC", 2 * 1024 * 1024)? as u64;
        limits.joins_per_minute = num("RELAY_JOINS_PER_MINUTE", limits.joins_per_minute)?;
        limits.max_shares_per_token =
            num("RELAY_MAX_SHARES_PER_TOKEN", limits.max_shares_per_token)?;
        limits.viewer_queue_bytes = num("RELAY_VIEWER_QUEUE_BYTES", limits.viewer_queue_bytes)?;
        Ok(Self {
            listen,
            tokens,
            trust_proxy,
            limits,
            timings: Timings::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn defaults_follow_the_prd() {
        let c = Config::from_env_with(env(&[("RELAY_TOKENS", "0123456789abcdef")])).unwrap();
        assert_eq!(c.listen.to_string(), "0.0.0.0:8080");
        assert_eq!(c.limits.max_viewers, 10);
        assert_eq!(c.limits.joins_per_minute, 20);
        assert_eq!(c.limits.max_shares_per_token, 50);
        assert_eq!(c.limits.max_message, 64 * 1024);
        assert_eq!(c.limits.bytes_per_sec, 2 * 1024 * 1024);
        assert!(!c.trust_proxy);
        assert_eq!(c.timings.sharer_offline, Duration::from_secs(300));
    }

    #[test]
    fn tokens_are_required_and_long() {
        assert_eq!(
            Config::from_env_with(env(&[])).err(),
            Some(ConfigError::MissingTokens)
        );
        assert_eq!(
            Config::from_env_with(env(&[("RELAY_TOKENS", "short")])).err(),
            Some(ConfigError::MissingTokens)
        );
        let c = Config::from_env_with(env(&[(
            "RELAY_TOKENS",
            " 0123456789abcdef , fedcba9876543210 ",
        )]))
        .unwrap();
        assert_eq!(c.tokens, ["0123456789abcdef", "fedcba9876543210"]);
    }

    #[test]
    fn limits_can_be_overridden_and_are_validated() {
        let c = Config::from_env_with(env(&[
            ("RELAY_TOKENS", "0123456789abcdef"),
            ("RELAY_MAX_VIEWERS", "3"),
            ("RELAY_TRUST_PROXY", "1"),
        ]))
        .unwrap();
        assert_eq!(c.limits.max_viewers, 3);
        assert!(c.trust_proxy);
        assert_eq!(
            Config::from_env_with(env(&[
                ("RELAY_TOKENS", "0123456789abcdef"),
                ("RELAY_MAX_VIEWERS", "0"),
            ]))
            .err(),
            Some(ConfigError::Invalid("RELAY_MAX_VIEWERS"))
        );
    }
}
