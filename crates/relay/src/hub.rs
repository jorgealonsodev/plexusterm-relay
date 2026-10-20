//! Registry of live shares, relay tokens and per-IP join limits.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use plexusterm_share_protocol::keys::{ShareId, Verifier};
use plexusterm_share_protocol::wire::{ErrorCode, LinkRegistration};
use subtle::ConstantTimeEq;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::config::Config;
use crate::conn::ConnTx;
use crate::share::{self, ShareEvent};

const JOIN_WINDOW: Duration = Duration::from_secs(60);

/// What a connection handler holds to talk to one share's actor.
#[derive(Clone)]
pub struct ShareHandle {
    pub events: mpsc::UnboundedSender<ShareEvent>,
    pub bucket: Arc<Mutex<Bucket>>,
}

pub struct Hub {
    pub config: Config,
    inner: Mutex<Inner>,
    next_conn: AtomicU64,
}

#[derive(Default)]
struct Inner {
    shares: HashMap<ShareId, ShareHandle>,
    /// Ended share ids, kept until their original expiry so an id is never
    /// reused and joins keep getting `not_found`.
    tombstones: HashMap<ShareId, Instant>,
    shares_per_token: HashMap<usize, usize>,
    joins: HashMap<IpAddr, VecDeque<Instant>>,
}

pub struct NewShare {
    pub token: String,
    pub share_id: ShareId,
    pub owner_verifier: Verifier,
    pub links: Vec<LinkRegistration>,
    pub expires_at: u64,
}

impl Hub {
    pub fn new(config: Config) -> Arc<Self> {
        Arc::new(Self {
            config,
            inner: Mutex::new(Inner::default()),
            next_conn: AtomicU64::new(1),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panic while holding this lock would leave plain maps in a
        // consistent state, so recovering the guard is sound.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn conn_id(&self) -> u64 {
        self.next_conn.fetch_add(1, Ordering::Relaxed)
    }

    /// Index of the matching relay token, compared in constant time.
    pub fn token_index(&self, token: &str) -> Option<usize> {
        let mut found = None;
        for (i, t) in self.config.tokens.iter().enumerate() {
            if bool::from(t.as_bytes().ct_eq(token.as_bytes())) {
                found = Some(i);
            }
        }
        found
    }

    /// Counts a join attempt; `false` when the IP is over its limit.
    pub fn allow_join(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut inner = self.lock();
        inner.joins.retain(|_, times| {
            while times
                .front()
                .is_some_and(|t| now.duration_since(*t) >= JOIN_WINDOW)
            {
                times.pop_front();
            }
            !times.is_empty()
        });
        let times = inner.joins.entry(ip).or_default();
        if times.len() >= self.config.limits.joins_per_minute {
            return false;
        }
        times.push_back(now);
        true
    }

    pub fn get(&self, id: &ShareId) -> Option<ShareHandle> {
        self.lock().shares.get(id).cloned()
    }

    /// Validates and registers a share, then starts its actor with `sharer`
    /// attached.
    pub fn create(self: &Arc<Self>, new: NewShare, sharer: ConnTx) -> Result<u64, ErrorCode> {
        let limits = &self.config.limits;
        let token = self
            .token_index(&new.token)
            .ok_or(ErrorCode::Unauthorized)?;
        if new.links.is_empty() || new.links.len() > limits.max_links {
            return Err(ErrorCode::BadRequest);
        }
        let deadline = expiry_deadline(new.expires_at, limits.max_expiry)?;
        let mut inner = self.lock();
        let now = Instant::now();
        inner.tombstones.retain(|_, until| *until > now);
        if inner.shares.contains_key(&new.share_id) || inner.tombstones.contains_key(&new.share_id)
        {
            return Err(ErrorCode::Conflict);
        }
        let count = inner.shares_per_token.entry(token).or_default();
        if *count >= limits.max_shares_per_token {
            return Err(ErrorCode::TooManyShares);
        }
        *count = count.saturating_add(1);
        let handle = share::spawn(
            Arc::clone(self),
            share::Init {
                id: new.share_id,
                token,
                owner_verifier: new.owner_verifier,
                links: new.links,
                expires_at: new.expires_at,
                deadline,
                sharer,
            },
        );
        inner.shares.insert(new.share_id, handle);
        Ok(new.expires_at)
    }

    /// Called by a share actor when it ends.
    pub fn remove(&self, id: &ShareId, token: usize, tombstone_until: Instant) {
        let mut inner = self.lock();
        inner.shares.remove(id);
        inner.tombstones.insert(*id, tombstone_until);
        if let Some(count) = inner.shares_per_token.get_mut(&token) {
            *count = count.saturating_sub(1);
        }
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Turns a Unix `expires_at` into a monotonic deadline, enforcing that it
/// is in the future and at most `max` away (PRD: at most 12 h).
pub fn expiry_deadline(expires_at: u64, max: Duration) -> Result<Instant, ErrorCode> {
    let now = unix_now();
    let remaining = expires_at
        .checked_sub(now)
        .filter(|r| *r > 0)
        .ok_or(ErrorCode::BadRequest)?;
    let remaining = Duration::from_secs(remaining);
    if remaining > max {
        return Err(ErrorCode::BadRequest);
    }
    Ok(Instant::now() + remaining)
}

/// Token bucket for the per-share byte rate. Readers wait instead of
/// dropping, which pushes back on the sender through TCP.
pub struct Bucket {
    rate: f64,
    tokens: f64,
    last: Instant,
}

impl Bucket {
    pub fn new(bytes_per_sec: u64) -> Self {
        let rate = bytes_per_sec as f64;
        Self {
            rate,
            tokens: rate,
            last: Instant::now(),
        }
    }

    /// Takes `n` bytes and returns how long the caller must wait first.
    pub fn take(&mut self, n: usize) -> Duration {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.rate);
        self.tokens -= n as f64;
        if self.tokens >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-self.tokens / self.rate)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Limits, Timings};

    fn hub(joins_per_minute: usize) -> Arc<Hub> {
        Hub::new(Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            tokens: vec!["token-aaaaaaaaaaaa".into(), "token-bbbbbbbbbbbb".into()],
            trust_proxy: false,
            limits: Limits {
                joins_per_minute,
                ..Limits::default()
            },
            timings: Timings::default(),
        })
    }

    #[test]
    fn tokens_match_exactly() {
        let h = hub(20);
        assert_eq!(h.token_index("token-bbbbbbbbbbbb"), Some(1));
        assert_eq!(h.token_index("token-bbbbbbbbbbb"), None);
        assert_eq!(h.token_index(""), None);
    }

    #[test]
    fn join_attempts_are_limited_per_ip() {
        let h = hub(2);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(h.allow_join(a));
        assert!(h.allow_join(a));
        assert!(!h.allow_join(a));
        assert!(h.allow_join(b));
    }

    #[test]
    fn expiry_must_be_future_and_within_max() {
        let max = Duration::from_secs(12 * 3600);
        let now = unix_now();
        assert!(expiry_deadline(now + 3600, max).is_ok());
        assert!(expiry_deadline(now + 12 * 3600, max).is_ok());
        assert_eq!(
            expiry_deadline(now + 12 * 3600 + 5, max).err(),
            Some(ErrorCode::BadRequest)
        );
        assert_eq!(expiry_deadline(now, max).err(), Some(ErrorCode::BadRequest));
        assert_eq!(expiry_deadline(0, max).err(), Some(ErrorCode::BadRequest));
    }

    #[tokio::test(start_paused = true)]
    async fn bucket_asks_to_wait_once_the_burst_is_spent() {
        let mut b = Bucket::new(1000);
        assert_eq!(b.take(1000), Duration::ZERO);
        assert_eq!(b.take(500), Duration::from_millis(500));
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(b.take(400), Duration::ZERO);
    }
}
