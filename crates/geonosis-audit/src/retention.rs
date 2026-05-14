//! Per-realm audit retention enforcement.
//!
//! Per `docs/13-observability.md` §"Audit retention":
//! - Each realm's `EventConfig.retention_days` decides the cutoff;
//!   `0` means "keep indefinitely" (operator opt-in).
//! - The minimum effective retention is 30 days even when the operator
//!   configures less, to satisfy the v0.1 audit-trail commitment.
//! - The runner is a long-lived tokio task that wakes on an interval
//!   and deletes rows older than the cutoff. Failures log + continue;
//!   never panic the runtime.
//!
//! The Postgres `audit_event` table is partitioned by month — for
//! month-aligned retention we could drop entire partitions, but that
//! breaks the per-realm semantic. v0.1 uses range deletes against the
//! partitioned table; v0.2 promotes month-aligned realms (those with
//! retention as a multiple of 30 days) into the partition-drop path.

use std::time::Duration;

use sqlx::postgres::PgPool;

/// Floor for any realm's retention window. Aligns with doc 13's
/// "minimum 30 days" requirement.
pub const MIN_RETENTION_DAYS: u32 = 30;

/// Default tick interval — once per hour. Cheap because the
/// `WHERE occurred_at <` predicate has the partition pruner do the
/// heavy lifting.
pub const DEFAULT_RUN_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Outcome of a single retention pass. Returned for tests and metrics;
/// the production runner just logs it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPassStats {
    pub realms_scanned: u64,
    pub rows_deleted: u64,
    pub errors: u64,
}

/// Spawn a long-lived retention task. Returns the JoinHandle so the
/// caller can `abort()` on shutdown.
pub fn spawn_runner(
    pool: PgPool,
    list_realm_retention: ListRetentionFn,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // `interval` fires immediately on first tick — skip that one so
        // the runner doesn't compete with the boot-time migrations.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match run_pass(&pool, &list_realm_retention).await {
                Ok(stats) => {
                    if stats.rows_deleted > 0 || stats.errors > 0 {
                        tracing::info!(
                            realms_scanned = stats.realms_scanned,
                            rows_deleted = stats.rows_deleted,
                            errors = stats.errors,
                            "audit retention pass complete",
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "audit retention pass failed");
                }
            }
        }
    })
}

/// Callback the runner uses to enumerate `(realm_id, retention_days)`
/// tuples. We don't take the full `Storage` trait here because the
/// audit crate must not depend on storage; the server bootstrap
/// wires a closure that reads from the storage backend.
pub type ListRetentionFn = std::sync::Arc<
    dyn Fn() -> futures_util::future::BoxFuture<'static, Result<Vec<(String, u32)>, String>>
        + Send
        + Sync,
>;

async fn run_pass(
    pool: &PgPool,
    list_realm_retention: &ListRetentionFn,
) -> Result<RetentionPassStats, String> {
    let realms = (list_realm_retention)().await?;
    let mut stats = RetentionPassStats::default();
    for (realm_id, retention_days) in realms {
        stats.realms_scanned += 1;
        // `0` means "keep indefinitely" — operator-explicit opt-out.
        if retention_days == 0 {
            continue;
        }
        let effective = retention_days.max(MIN_RETENTION_DAYS) as i64;
        match prune_realm(pool, &realm_id, effective).await {
            Ok(n) => stats.rows_deleted += n,
            Err(e) => {
                stats.errors += 1;
                tracing::warn!(
                    realm_id = %realm_id,
                    error = %e,
                    "audit retention prune failed for realm",
                );
            }
        }
    }
    Ok(stats)
}

async fn prune_realm(
    pool: &PgPool,
    realm_id: &str,
    retention_days: i64,
) -> Result<u64, sqlx::Error> {
    // Bare INTERVAL with a parameter requires the `make_interval`
    // function — keeps the SQL portable across Postgres 14/15/16
    // without the legacy `'$1 days'::interval` quirk.
    let result = sqlx::query(
        "DELETE FROM audit_event
         WHERE realm_id = $1
           AND occurred_at < now() - make_interval(days => $2::int)",
    )
    .bind(realm_id)
    .bind(retention_days)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_retention_floor_is_30_days() {
        // Doc 13 contract: operators cannot drop below 30 days.
        assert_eq!(MIN_RETENTION_DAYS, 30);
    }

    #[test]
    fn default_run_interval_is_hourly() {
        assert_eq!(DEFAULT_RUN_INTERVAL, Duration::from_secs(60 * 60));
    }

    #[test]
    fn pass_stats_defaults_to_zero() {
        let s = RetentionPassStats::default();
        assert_eq!(s.realms_scanned, 0);
        assert_eq!(s.rows_deleted, 0);
        assert_eq!(s.errors, 0);
    }
}
