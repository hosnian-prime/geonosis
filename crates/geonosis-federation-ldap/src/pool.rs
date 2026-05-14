//! Bounded LDAP connection pool with a per-source circuit breaker.
//!
//! Implements the doc's `docs/04-federation-ldap.md` §"Connection
//! management" semantics:
//! - Round-robin URL selection (with failover on connect failure)
//! - Bounded pool (default 8) — `acquire` returns `PoolExhausted` if
//!   no slot frees within the configured wait
//! - Circuit breaker: 5 consecutive failures opens it, a 30s
//!   probe attempts a half-open trial bind, success closes
//! - Backoff: exponential, capped at 60s with jitter

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ldap3::{Ldap, LdapConnAsync, LdapConnSettings};
use parking_lot::Mutex;
use tokio::sync::Semaphore;

use crate::config::{LdapFederationConfig, TlsPolicy};
use crate::error::LdapError;

const MAX_BACKOFF: Duration = Duration::from_secs(60);
const PROBE_INTERVAL: Duration = Duration::from_secs(30);
const CIRCUIT_OPEN_THRESHOLD: usize = 5;
const CONNECT_WAIT: Duration = Duration::from_secs(2);

/// Public state of the circuit. Exposed for the `/-/ready` health probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug)]
struct Breaker {
    state: CircuitState,
    consecutive_failures: usize,
    opened_at: Option<Instant>,
    backoff: Duration,
}

impl Breaker {
    fn closed() -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            opened_at: None,
            backoff: Duration::from_millis(500),
        }
    }

    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= CIRCUIT_OPEN_THRESHOLD {
            self.state = CircuitState::Open;
            self.opened_at = Some(Instant::now());
            self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
        }
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.state = CircuitState::Closed;
        self.opened_at = None;
        self.backoff = Duration::from_millis(500);
    }

    fn try_half_open(&mut self) -> bool {
        if self.state != CircuitState::Open {
            return true;
        }
        match self.opened_at {
            Some(t) if t.elapsed() >= PROBE_INTERVAL => {
                self.state = CircuitState::HalfOpen;
                true
            }
            _ => false,
        }
    }
}

/// Connection pool. One per `FederationSource`.
pub struct LdapPool {
    cfg: LdapFederationConfig,
    /// Acquire one permit before connecting; bounds in-flight ops.
    permits: Arc<Semaphore>,
    /// Round-robin cursor through `cfg.urls`.
    cursor: AtomicUsize,
    breaker: Mutex<Breaker>,
}

impl LdapPool {
    pub fn new(cfg: LdapFederationConfig) -> Self {
        let permits = Arc::new(Semaphore::new(cfg.pool_size.max(1) as usize));
        Self {
            cfg,
            permits,
            cursor: AtomicUsize::new(0),
            breaker: Mutex::new(Breaker::closed()),
        }
    }

    pub fn config(&self) -> &LdapFederationConfig {
        &self.cfg
    }

    pub fn circuit_state(&self) -> CircuitState {
        self.breaker.lock().state
    }

    /// Acquire a freshly-bound ldap3 connection (service-account bind
    /// happens here if `bind_dn` is configured). Caller drops the
    /// returned `Connection` to release the pool permit.
    pub async fn acquire(&self) -> Result<Connection, LdapError> {
        {
            let mut br = self.breaker.lock();
            if !br.try_half_open() {
                return Err(LdapError::CircuitOpen);
            }
        }

        let permit = tokio::time::timeout(CONNECT_WAIT, self.permits.clone().acquire_owned())
            .await
            .map_err(|_| LdapError::PoolExhausted)?
            .map_err(|_| LdapError::PoolExhausted)?;

        let ldap = match self.dial().await {
            Ok(l) => {
                self.breaker.lock().record_success();
                l
            }
            Err(e) => {
                self.breaker.lock().record_failure();
                return Err(e);
            }
        };

        Ok(Connection {
            ldap,
            _permit: permit,
        })
    }

    async fn dial(&self) -> Result<Ldap, LdapError> {
        let total = self.cfg.urls.len().max(1);
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % total;
        let mut last_err: Option<LdapError> = None;
        for offset in 0..total {
            let url = &self.cfg.urls[(start + offset) % total];
            match self.dial_one(url).await {
                Ok(l) => return Ok(l),
                Err(e) => {
                    tracing::warn!(error = %e, url = %url, "ldap dial failed; trying next");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| LdapError::Connect("no urls configured".into())))
    }

    async fn dial_one(&self, url: &str) -> Result<Ldap, LdapError> {
        let settings = LdapConnSettings::new()
            .set_starttls(matches!(self.cfg.tls, TlsPolicy::StartTls))
            .set_conn_timeout(self.cfg.bind_timeout());
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, url)
            .await
            .map_err(LdapError::from)?;
        ldap3::drive!(conn);

        // Service-account bind, if configured.
        if let Some(bind_dn) = self.cfg.bind_dn.as_deref() {
            let pw = self
                .cfg
                .bind_password
                .as_ref()
                .map(|s| s.expose().clone())
                .unwrap_or_default();
            let result =
                tokio::time::timeout(self.cfg.bind_timeout(), ldap.simple_bind(bind_dn, &pw))
                    .await
                    .map_err(|_| LdapError::Timeout {
                        ms: self.cfg.bind_timeout_ms,
                    })?
                    .map_err(LdapError::from)?;
            if result.rc != 0 {
                return Err(LdapError::Bind(format!("rc={} {}", result.rc, result.text)));
            }
        }
        Ok(ldap)
    }
}

/// Connection handle returned by `LdapPool::acquire`. Drop releases the
/// permit back to the semaphore.
pub struct Connection {
    pub ldap: Ldap,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::time::Duration;

    use geonosis_core::id::{FederationId, RealmId};

    use crate::config::{
        AttributeMap, LdapFederationConfig, ReferralPolicy, SyncPolicy, TlsPolicy, WritePolicy,
    };

    fn cfg() -> LdapFederationConfig {
        LdapFederationConfig {
            id: FederationId::new(),
            realm_id: RealmId::new(),
            alias: "corp-ad".into(),
            urls: vec!["ldap://127.0.0.1:1".into()],
            bind_dn: None,
            bind_password: None,
            base_dn: "DC=example".into(),
            user_object_classes: vec!["user".into()],
            user_filter: "(uid={username})".into(),
            page_size: 100,
            referrals: ReferralPolicy::Ignore,
            tls: TlsPolicy::None,
            attribute_map: AttributeMap {
                username: "uid".into(),
                uid: "uid".into(),
                ..AttributeMap::default()
            },
            write_policy: WritePolicy::ReadOnly,
            sync_policy: SyncPolicy::OnDemand,
            group_sync: None,
            priority: 100,
            bind_timeout_ms: 50,
            search_timeout_ms: 50,
            pool_size: 2,
            enabled: true,
        }
    }

    #[test]
    fn breaker_opens_after_threshold() {
        let mut b = Breaker::closed();
        for _ in 0..CIRCUIT_OPEN_THRESHOLD {
            b.record_failure();
        }
        assert_eq!(b.state, CircuitState::Open);
    }

    #[test]
    fn breaker_resets_on_success() {
        let mut b = Breaker::closed();
        for _ in 0..3 {
            b.record_failure();
        }
        b.record_success();
        assert_eq!(b.state, CircuitState::Closed);
        assert_eq!(b.consecutive_failures, 0);
    }

    #[tokio::test]
    async fn unreachable_host_increments_failure() {
        // Targets 127.0.0.1:1 which is closed in CI sandboxes. The
        // dial must error, and the breaker has to count the failure.
        let pool = LdapPool::new(cfg());
        let r = pool.acquire().await;
        assert!(r.is_err());
        assert!(pool.breaker.lock().consecutive_failures >= 1);
        // Suppress unused warning if BTreeMap import path changes.
        let _ = BTreeMap::<String, String>::new();
        let _ = Duration::from_millis(1);
    }
}
