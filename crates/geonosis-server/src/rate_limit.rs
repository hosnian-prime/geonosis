//! Per-realm rate limiter for the hot OIDC endpoints.
//!
//! Per `docs/12-security-crypto.md` §"Rate limiting":
//! - Each realm gets its own rate limit bucket.
//! - Two tiers: per-pod token bucket (lock-free, always active) AND
//!   cluster-wide Redis sliding window (when Redis is available).
//! - Applied to `/authorize`, `/token`, `/userinfo`, `/par` since
//!   those are the predictable abuse vectors. Admin endpoints are
//!   excluded — their callers are operator-owned identities.
//!
//! The middleware checks the cluster-wide limiter first (if configured),
//! then the per-pod limiter. Both must allow the request. When Redis
//! is unavailable, the system gracefully degrades to per-pod only.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use parking_lot::RwLock;

use geonosis_core::id::RealmId;

/// Defaults tuned for a moderately-busy 4 vCPU realm. Operators can
/// override per realm in v0.1.x once the admin surface lands.
pub const DEFAULT_BURST: u64 = 200;
pub const DEFAULT_REFILL_PER_SEC: u64 = 100;

/// Single-bucket state. Tokens are stored as integers; sub-token
/// fractional refill carries in the `last_refill_nanos` field so the
/// bucket recovers smoothly under sustained load.
struct Bucket {
    tokens: AtomicU64,
    last_refill_nanos: AtomicU64,
    capacity: u64,
    refill_per_sec: u64,
}

impl Bucket {
    fn new(capacity: u64, refill_per_sec: u64, _base: Instant) -> Self {
        Self {
            tokens: AtomicU64::new(capacity),
            // Anchor at zero: every try_consume measures elapsed via
            // `now.duration_since(base)`, so zero means "no refill due
            // yet". Using `base.elapsed()` here would offset by the
            // (non-zero) time between `base` capture and Bucket::new,
            // which eats into the first refill window.
            last_refill_nanos: AtomicU64::new(0),
            capacity,
            refill_per_sec,
        }
    }

    /// Attempt to consume one token. Returns `true` on success,
    /// `false` when the bucket is empty (caller emits 429).
    fn try_consume(&self, now: Instant, base: Instant) -> bool {
        // 1. Refill.
        let now_ns = now.duration_since(base).as_nanos() as u64;
        let last_ns = self.last_refill_nanos.load(Ordering::Acquire);
        if now_ns > last_ns {
            let elapsed_ns = now_ns - last_ns;
            // tokens added = rate * elapsed_secs = rate * elapsed_ns / 1e9
            let add = (elapsed_ns as u128 * self.refill_per_sec as u128) / 1_000_000_000;
            if add > 0 {
                let add = add as u64;
                // CAS-loop on the timestamp so two threads refilling
                // simultaneously don't double-count.
                if self
                    .last_refill_nanos
                    .compare_exchange(last_ns, now_ns, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    // Saturating add — cap at capacity.
                    let mut cur = self.tokens.load(Ordering::Acquire);
                    loop {
                        let new = (cur + add).min(self.capacity);
                        match self.tokens.compare_exchange_weak(
                            cur,
                            new,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => break,
                            Err(actual) => cur = actual,
                        }
                    }
                }
            }
        }
        // 2. Consume.
        let mut cur = self.tokens.load(Ordering::Acquire);
        loop {
            if cur == 0 {
                return false;
            }
            match self.tokens.compare_exchange_weak(
                cur,
                cur - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }
}

/// Per-realm bucket registry. Read-mostly RwLock so the hot path is
/// effectively lock-free once a realm has been touched once.
pub struct PerRealmRateLimiter {
    buckets: RwLock<HashMap<RealmId, Arc<Bucket>>>,
    base: Instant,
    default_capacity: u64,
    default_refill_per_sec: u64,
}

impl PerRealmRateLimiter {
    pub fn new(default_capacity: u64, default_refill_per_sec: u64) -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
            base: Instant::now(),
            default_capacity,
            default_refill_per_sec,
        }
    }

    pub fn default_v0_1() -> Self {
        Self::new(DEFAULT_BURST, DEFAULT_REFILL_PER_SEC)
    }

    /// Try to consume one token for `realm`. Returns false on overload.
    pub fn try_consume(&self, realm: RealmId) -> bool {
        // Fast path: bucket already exists.
        if let Some(b) = self.buckets.read().get(&realm).cloned() {
            return b.try_consume(Instant::now(), self.base);
        }
        // Slow path: insert + retry.
        let new = Arc::new(Bucket::new(
            self.default_capacity,
            self.default_refill_per_sec,
            self.base,
        ));
        let mut w = self.buckets.write();
        let b = w.entry(realm).or_insert(new).clone();
        drop(w);
        b.try_consume(Instant::now(), self.base)
    }
}

/// Approximate seconds until the next token would be available.
/// Conservative — we round up so the client never spins.
fn retry_after_secs(refill_per_sec: u64) -> u32 {
    if refill_per_sec == 0 {
        return 60;
    }
    // One token returns in (1 / refill_per_sec) seconds. We bump to at
    // least 1 second so the client doesn't hammer.
    let secs = (1.0_f64 / refill_per_sec as f64).ceil() as u32;
    secs.max(1)
}

/// Cluster-wide rate limiter using Redis sliding window. When Redis
/// is unavailable, `try_consume` returns `true` (graceful degradation
/// to per-pod only). The window is 1 second with a configurable max
/// count per realm.
#[cfg(feature = "redis-rate-limit")]
pub struct ClusterRateLimiter {
    conn: tokio::sync::Mutex<redis::aio::ConnectionManager>,
    max_per_window: u64,
    window_secs: i64,
}

#[cfg(feature = "redis-rate-limit")]
impl ClusterRateLimiter {
    pub fn new(conn: redis::aio::ConnectionManager, max_per_window: u64) -> Self {
        Self {
            conn: tokio::sync::Mutex::new(conn),
            max_per_window,
            window_secs: 1,
        }
    }

    /// Try to consume one token from the cluster-wide bucket.
    /// Returns `true` if allowed, `false` if the window is exhausted.
    /// On Redis errors, returns `true` (graceful degradation).
    ///
    /// Uses a Lua script to atomically INCR + EXPIRE in a single
    /// round-trip, preventing the key from persisting forever if the
    /// process crashes between the two operations.
    pub async fn try_consume(&self, realm: RealmId) -> bool {
        let key = format!("geonosis:rl:{realm}");
        let mut conn = self.conn.lock().await;
        // Atomic INCR + conditional EXPIRE via Lua script.
        let script = redis::Script::new(
            r#"
            local c = redis.call('INCR', KEYS[1])
            if c == 1 then
                redis.call('EXPIRE', KEYS[1], ARGV[1])
            end
            return c
            "#,
        );
        let count: u64 = match script
            .key(&key)
            .arg(self.window_secs)
            .invoke_async(&mut *conn)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "Redis rate limit script failed; falling back to per-pod");
                return true;
            }
        };
        count <= self.max_per_window
    }
}

/// Composite rate limiter: cluster-wide (optional) + per-pod (always).
pub struct CompositeRateLimiter {
    pub local: PerRealmRateLimiter,
    #[cfg(feature = "redis-rate-limit")]
    pub cluster: Option<ClusterRateLimiter>,
}

impl CompositeRateLimiter {
    pub fn local_only() -> Self {
        Self {
            local: PerRealmRateLimiter::default_v0_1(),
            #[cfg(feature = "redis-rate-limit")]
            cluster: None,
        }
    }

    #[cfg(feature = "redis-rate-limit")]
    pub fn with_redis(conn: redis::aio::ConnectionManager, cluster_max: u64) -> Self {
        Self {
            local: PerRealmRateLimiter::default_v0_1(),
            cluster: Some(ClusterRateLimiter::new(conn, cluster_max)),
        }
    }

    /// Check both tiers. Cluster-wide is checked first; if it rejects,
    /// the per-pod bucket is not consumed (preserving local capacity).
    pub async fn try_consume(&self, realm: RealmId) -> bool {
        #[cfg(feature = "redis-rate-limit")]
        if let Some(ref cluster) = self.cluster {
            if !cluster.try_consume(realm).await {
                return false;
            }
        }
        self.local.try_consume(realm)
    }
}

/// Wrapper around the limiter that axum middleware mounts. Held in
/// `AppState` so a single shared limiter spans all routes.
pub type SharedRateLimiter = Arc<CompositeRateLimiter>;

/// Axum middleware: extracts realm slug from the path, looks up the
/// realm to get the realm id, applies the per-realm bucket. 429 with
/// Retry-After on overload.
///
/// The realm lookup itself adds one cache hit per request — Storage's
/// `get_realm_by_slug` is already cached under `CacheClass::Realm`
/// so the cost is negligible.
pub async fn limit_per_realm(
    State(state): State<crate::state::AppState>,
    Path(slug): Path<String>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let realm = match state.storage.get_realm_by_slug(&slug).await {
        Ok(r) => r,
        // Unknown realm — let the downstream handler return the proper
        // OAuth error so the rate-limit layer never owns 404s.
        Err(_) => return next.run(req).await,
    };
    if state.rate_limiter.try_consume(realm.id).await {
        return next.run(req).await;
    }
    let retry = retry_after_secs(DEFAULT_REFILL_PER_SEC);
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            ("retry-after", retry.to_string()),
            ("content-type", "application/json".into()),
        ],
        r#"{"error":"rate_limited","error_description":"realm bucket exhausted"}"#,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn bucket_consumes_until_empty() {
        let base = Instant::now();
        let b = Bucket::new(3, 100, base);
        assert!(b.try_consume(base, base));
        assert!(b.try_consume(base, base));
        assert!(b.try_consume(base, base));
        // Same instant — no refill.
        assert!(!b.try_consume(base, base));
    }

    #[test]
    fn bucket_refills_over_time() {
        let base = Instant::now();
        let b = Bucket::new(10, 100, base); // 100 tokens/sec
                                            // Drain the bucket.
        for _ in 0..10 {
            assert!(b.try_consume(base, base));
        }
        assert!(!b.try_consume(base, base));
        // Wait 50ms → 5 tokens refilled.
        let later = base + Duration::from_millis(50);
        assert!(b.try_consume(later, base));
        assert!(b.try_consume(later, base));
        assert!(b.try_consume(later, base));
        assert!(b.try_consume(later, base));
        assert!(b.try_consume(later, base));
        // 6th token must wait.
        assert!(!b.try_consume(later, base));
    }

    #[test]
    fn refill_caps_at_capacity() {
        let base = Instant::now();
        let b = Bucket::new(5, 100, base);
        // Wait a long time — refill must not exceed capacity.
        let later = base + Duration::from_secs(60);
        for _ in 0..5 {
            assert!(b.try_consume(later, base));
        }
        // 6th still fails because cap is 5.
        assert!(!b.try_consume(later, base));
    }

    #[test]
    fn per_realm_isolation() {
        let limiter = PerRealmRateLimiter::new(2, 10);
        let a = RealmId::new();
        let b = RealmId::new();
        assert!(limiter.try_consume(a));
        assert!(limiter.try_consume(a));
        assert!(!limiter.try_consume(a)); // exhausted
                                          // Realm b unaffected.
        assert!(limiter.try_consume(b));
        assert!(limiter.try_consume(b));
    }

    #[test]
    fn retry_after_floors_at_one_second() {
        assert_eq!(retry_after_secs(10), 1);
        assert_eq!(retry_after_secs(1), 1);
        assert_eq!(retry_after_secs(0), 60);
    }
}
