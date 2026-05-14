//! Per-realm token-bucket rate limiter for the hot OIDC endpoints.
//!
//! Per `docs/12-security-crypto.md` §"Rate limiting":
//! - Each realm gets its own token bucket (capacity + refill rate).
//! - In-process for v0.1; cluster-wide enforcement via Redis-backed
//!   counters lands in v0.2.
//! - Applied to `/authorize`, `/token`, `/userinfo`, `/par` since
//!   those are the predictable abuse vectors. Admin endpoints are
//!   excluded — their callers are operator-owned identities.
//!
//! Algorithm: classic continuous token bucket with monotonic-clock
//! refill. Atomic state per realm so the hot path stays lock-free.

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

/// Wrapper around the limiter that axum middleware mounts. Held in
/// `AppState` so a single shared limiter spans all routes.
pub type SharedRateLimiter = Arc<PerRealmRateLimiter>;

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
    if state.rate_limiter.try_consume(realm.id) {
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
