//! Brute-force lockout runtime — per `docs/12-security-crypto.md`.
//!
//! Operates on the `failed_attempts`, `locked_until`, `last_failed_at`
//! columns added to `app_user` by the v0.1 migration set. The password
//! authenticator wraps each verification with `check_locked` (pre-flight)
//! and `record_outcome` (post-flight) so the policy is enforced
//! storage-blind.
//!
//! Strategy (verbatim from doc §"Brute-force protection"):
//! - Counter increments on each failed attempt.
//! - Counter resets to 0 on success OR after `failure_reset_window` of
//!   inactivity.
//! - Lockout triggers when `failed_attempts >= max_login_failures`.
//! - Lockout duration is linear: `wait = min(wait_increment * attempts,
//!   max_wait)`.
//! - `permanent_lockout = true` skips auto-unlock — admin reset only.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use thiserror::Error;

use geonosis_core::realm::BruteForcePolicy;
use geonosis_core::{RealmId, User, UserId};
use geonosis_storage::Storage;

#[derive(Debug, Error)]
pub enum BruteForceError {
    #[error("storage: {0}")]
    Storage(String),
    #[error("user is locked until {until}")]
    Locked { until: DateTime<Utc> },
}

/// Pre-flight: refuse to even attempt verification when the user is
/// currently locked.
pub async fn check_locked(
    storage: &dyn Storage,
    realm: RealmId,
    user_id: UserId,
    now: DateTime<Utc>,
) -> Result<(), BruteForceError> {
    let user = storage
        .get_user(realm, user_id)
        .await
        .map_err(|e| BruteForceError::Storage(e.to_string()))?;
    if let Some(until) = user.locked_until {
        if until > now {
            return Err(BruteForceError::Locked { until });
        }
    }
    Ok(())
}

/// Record a successful authentication. Resets the failure counter and
/// clears any lockout.
pub async fn record_success(
    storage: &dyn Storage,
    realm: RealmId,
    user_id: UserId,
) -> Result<(), BruteForceError> {
    let mut user = storage
        .get_user(realm, user_id)
        .await
        .map_err(|e| BruteForceError::Storage(e.to_string()))?;
    if user.failed_attempts == 0 && user.locked_until.is_none() && user.last_failed_at.is_none() {
        // Fast path — no state to clear.
        return Ok(());
    }
    user.failed_attempts = 0;
    user.locked_until = None;
    user.last_failed_at = None;
    storage
        .update_user(user)
        .await
        .map_err(|e| BruteForceError::Storage(e.to_string()))
}

/// Record a failed authentication. Increments the counter; if the
/// policy threshold is reached, sets `locked_until`. Returns the new
/// `User` row (so the caller can decide whether to surface
/// `BruteForceError::Locked` to the user).
pub async fn record_failure(
    storage: &dyn Storage,
    realm: RealmId,
    user_id: UserId,
    policy: &BruteForcePolicy,
    now: DateTime<Utc>,
) -> Result<User, BruteForceError> {
    let mut user = storage
        .get_user(realm, user_id)
        .await
        .map_err(|e| BruteForceError::Storage(e.to_string()))?;

    // Reset the counter if the failure window has elapsed since the
    // last failed attempt.
    let reset_after = ChronoDuration::from_std(policy.failure_reset)
        .unwrap_or_else(|_| ChronoDuration::seconds(0));
    if let Some(last) = user.last_failed_at {
        if now.signed_duration_since(last) > reset_after {
            user.failed_attempts = 0;
        }
    }
    user.failed_attempts = user.failed_attempts.saturating_add(1);
    user.last_failed_at = Some(now);

    if policy.enabled && user.failed_attempts >= policy.max_login_failures {
        // Linear backoff capped at `max_wait`.
        let increment = ChronoDuration::from_std(policy.wait_increment)
            .unwrap_or_else(|_| ChronoDuration::seconds(60));
        let max_wait = ChronoDuration::from_std(policy.max_wait)
            .unwrap_or_else(|_| ChronoDuration::seconds(15 * 60));
        let attempts_over = user
            .failed_attempts
            .saturating_sub(policy.max_login_failures)
            + 1;
        let raw = increment * (attempts_over as i32);
        let wait = if raw > max_wait { max_wait } else { raw };
        user.locked_until = if policy.permanent_lockout {
            // Sentinel far future = "until admin clears".
            Some(now + ChronoDuration::days(365 * 100))
        } else {
            Some(now + wait)
        };
    }

    storage
        .update_user(user.clone())
        .await
        .map_err(|e| BruteForceError::Storage(e.to_string()))?;
    Ok(user)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use chrono::{Duration as ChronoDuration, Utc};
    use geonosis_core::User;
    use geonosis_storage::{MemoryStorage, Storage};

    fn policy() -> BruteForcePolicy {
        BruteForcePolicy {
            enabled: true,
            max_login_failures: 3,
            wait_increment: Duration::from_secs(60),
            max_wait: Duration::from_secs(15 * 60),
            failure_reset: Duration::from_secs(12 * 3600),
            permanent_lockout: false,
        }
    }

    async fn fixture() -> (Arc<dyn Storage>, RealmId, UserId) {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let realm = RealmId::new();
        let u = User {
            username: "ada".into(),
            realm_id: realm,
            ..User::default()
        };
        let uid = u.id;
        storage.create_user(u).await.unwrap();
        (storage, realm, uid)
    }

    #[tokio::test]
    async fn first_failure_increments_counter_no_lock() {
        let (s, realm, uid) = fixture().await;
        let p = policy();
        let u = record_failure(&*s, realm, uid, &p, Utc::now())
            .await
            .unwrap();
        assert_eq!(u.failed_attempts, 1);
        assert!(u.locked_until.is_none());
    }

    #[tokio::test]
    async fn threshold_triggers_lock_with_linear_backoff() {
        let (s, realm, uid) = fixture().await;
        let p = policy();
        let now = Utc::now();
        for _ in 0..3 {
            record_failure(&*s, realm, uid, &p, now).await.unwrap();
        }
        let u = s.get_user(realm, uid).await.unwrap();
        assert_eq!(u.failed_attempts, 3);
        let locked = u.locked_until.expect("must be locked");
        // First lockout: 1 attempt past threshold * 60s = 60s.
        assert!(locked > now);
        assert!(locked <= now + ChronoDuration::seconds(60 + 1));
    }

    #[tokio::test]
    async fn backoff_caps_at_max_wait() {
        let (s, realm, uid) = fixture().await;
        let mut p = policy();
        p.wait_increment = Duration::from_secs(60);
        p.max_wait = Duration::from_secs(120); // tiny cap for the test
        let now = Utc::now();
        for _ in 0..100 {
            record_failure(&*s, realm, uid, &p, now).await.unwrap();
        }
        let u = s.get_user(realm, uid).await.unwrap();
        let locked = u.locked_until.expect("locked");
        // Should not exceed 120s.
        let delta = (locked - now).num_seconds();
        assert!(delta <= 121, "delta={delta}");
    }

    #[tokio::test]
    async fn check_locked_blocks_during_lockout() {
        let (s, realm, uid) = fixture().await;
        let p = policy();
        let now = Utc::now();
        for _ in 0..3 {
            record_failure(&*s, realm, uid, &p, now).await.unwrap();
        }
        let err = check_locked(&*s, realm, uid, now).await.unwrap_err();
        assert!(matches!(err, BruteForceError::Locked { .. }));
    }

    #[tokio::test]
    async fn check_locked_passes_after_window() {
        let (s, realm, uid) = fixture().await;
        let p = policy();
        let now = Utc::now();
        for _ in 0..3 {
            record_failure(&*s, realm, uid, &p, now).await.unwrap();
        }
        let later = now + ChronoDuration::minutes(10);
        // Lockout is 60s for the first overflow attempt — after 10 min
        // the window has cleared.
        check_locked(&*s, realm, uid, later).await.unwrap();
    }

    #[tokio::test]
    async fn record_success_clears_state() {
        let (s, realm, uid) = fixture().await;
        let p = policy();
        let now = Utc::now();
        for _ in 0..2 {
            record_failure(&*s, realm, uid, &p, now).await.unwrap();
        }
        record_success(&*s, realm, uid).await.unwrap();
        let u = s.get_user(realm, uid).await.unwrap();
        assert_eq!(u.failed_attempts, 0);
        assert!(u.locked_until.is_none());
        assert!(u.last_failed_at.is_none());
    }

    #[tokio::test]
    async fn failure_reset_window_clears_old_counter() {
        let (s, realm, uid) = fixture().await;
        let mut p = policy();
        p.failure_reset = Duration::from_secs(60); // 1-min window for test
        let t0 = Utc::now();
        record_failure(&*s, realm, uid, &p, t0).await.unwrap();
        record_failure(&*s, realm, uid, &p, t0).await.unwrap();
        // Two minutes later, the window has elapsed — counter resets.
        let later = t0 + ChronoDuration::minutes(2);
        let u = record_failure(&*s, realm, uid, &p, later).await.unwrap();
        assert_eq!(u.failed_attempts, 1, "counter should reset");
    }

    #[tokio::test]
    async fn permanent_lockout_uses_far_future() {
        let (s, realm, uid) = fixture().await;
        let mut p = policy();
        p.permanent_lockout = true;
        let now = Utc::now();
        for _ in 0..3 {
            record_failure(&*s, realm, uid, &p, now).await.unwrap();
        }
        let u = s.get_user(realm, uid).await.unwrap();
        let until = u.locked_until.unwrap();
        // ~100 years out.
        let years = (until - now).num_days() / 365;
        assert!(years > 50, "got {years} years");
    }

    #[tokio::test]
    async fn disabled_policy_never_locks() {
        let (s, realm, uid) = fixture().await;
        let mut p = policy();
        p.enabled = false;
        let now = Utc::now();
        for _ in 0..10 {
            record_failure(&*s, realm, uid, &p, now).await.unwrap();
        }
        let u = s.get_user(realm, uid).await.unwrap();
        assert!(u.locked_until.is_none());
        assert_eq!(u.failed_attempts, 10);
    }
}
