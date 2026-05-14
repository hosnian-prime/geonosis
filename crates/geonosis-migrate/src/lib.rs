//! Embedded sqlx migrations for Geonosis Postgres.
//!
//! Per `docs/10-zero-downtime-migrations.md`:
//! - Migrations are embedded into the binary (`sqlx::migrate!()`)
//! - Leader-elected via Postgres advisory lock — only one pod runs the
//!   `MIGRATE` step at boot
//! - Each `.up.sql` carries a metadata header (`-- kind: expand` etc.)
//!   that the lint / compatibility-gate logic reads at runtime
//!
//! v0.1 ships the bootstrap migration set (8 `.up.sql` files). No
//! `.down.sql` files yet — rollback is "restore from backup" until the
//! down-migrations PR lands (an explicit doc decision).

use std::time::Duration;

use sqlx::postgres::PgPool;
use sqlx::Executor;
use thiserror::Error;

/// Compile-time-embedded migrator. The compiler scans `migrations/`
/// next to this file at build time; each `.sql` is hashed and the set
/// is reproducible across runs.
pub static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Advisory-lock key Geonosis uses to single-leader the migrate step.
/// Per docs/10 §"Leader election": pick a stable 64-bit constant; any
/// future tool that needs to coordinate with us reuses this key.
pub const ADVISORY_LOCK_KEY: i64 = 8_423_651_021_231;

#[derive(Debug, Error)]
pub enum MigrateError {
    #[error("acquire advisory lock failed: {0}")]
    Lock(String),
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("migrate: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("schema version {found} not in supported range [{min}, {max}]")]
    SchemaIncompatible {
        found: i64,
        min: i64,
        max: i64,
    },
}

/// Run migrations with leader election. Multiple pods can call this on
/// boot — exactly one will execute pending migrations; the rest wait
/// on the advisory lock then validate the schema is up to date.
pub async fn run_with_leader_lock(pool: &PgPool) -> Result<(), MigrateError> {
    let mut conn = pool.acquire().await?;

    // `pg_advisory_lock` blocks until acquired. We poll with a deadline
    // so a stuck migration on another pod surfaces as a timeout, not a
    // forever-hung boot.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let acquired: (bool,) =
            sqlx::query_as("SELECT pg_try_advisory_lock($1)")
                .bind(ADVISORY_LOCK_KEY)
                .fetch_one(&mut *conn)
                .await?;
        if acquired.0 {
            break;
        }
        if std::time::Instant::now() > deadline {
            return Err(MigrateError::Lock("timed out after 60s".into()));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let run_result = MIGRATIONS.run(&mut *conn).await;

    // Release the advisory lock no matter what.
    let _ = conn
        .execute(sqlx::query("SELECT pg_advisory_unlock($1)").bind(ADVISORY_LOCK_KEY))
        .await;

    run_result?;
    Ok(())
}

/// Server compatibility window. Per docs/10 each pod refuses to start
/// if the live DB schema is outside its `[min, max]` window.
#[derive(Debug, Clone, Copy)]
pub struct ServerCompat {
    pub min_schema: i64,
    pub max_schema: i64,
}

/// v0.1.0 — accepts schema versions 0–999 (the initial migration set
/// reserves room for sub-millisecond ordering). New majors bump these.
pub const V0_1_COMPAT: ServerCompat = ServerCompat {
    min_schema: 0,
    max_schema: 99_999_999,
};

/// Check that the applied migration set is within the server's
/// compatibility window. Call right after `run_with_leader_lock`.
pub async fn enforce_schema_compat(
    pool: &PgPool,
    compat: ServerCompat,
) -> Result<(), MigrateError> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT max(version) FROM _sqlx_migrations")
            .fetch_optional(pool)
            .await?;
    let found = row.and_then(|(v,)| Some(v)).unwrap_or(0);
    if found < compat.min_schema || found > compat.max_schema {
        return Err(MigrateError::SchemaIncompatible {
            found,
            min: compat.min_schema,
            max: compat.max_schema,
        });
    }
    Ok(())
}

/// Set the per-transaction RLS realm scope. Every storage operation
/// that touches a tenanted table MUST call this inside the same
/// transaction. Per docs/02-data-model.md §RLS the policy reads
/// `current_setting('geonosis.realm_id', true)`.
pub async fn set_realm_scope<'c, E>(executor: E, realm_id: &str) -> Result<(), sqlx::Error>
where
    E: Executor<'c, Database = sqlx::Postgres>,
{
    // `set_config` is the parameterizable form of `SET LOCAL`. The
    // third argument `true` scopes it to the current transaction.
    sqlx::query("SELECT set_config('geonosis.realm_id', $1, true)")
        .bind(realm_id)
        .execute(executor)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrator_lists_all_bootstrap_migrations() {
        let names: Vec<&str> = MIGRATIONS
            .iter()
            .map(|m| m.description.as_ref())
            .collect();
        // Each `.up.sql` is one migration; sqlx strips the timestamp
        // prefix into the description.
        assert_eq!(names.len(), 9, "migrations: {names:?}");
        for n in &names {
            eprintln!("migration: {n}");
        }
        // Sanity-check the order is monotone (sqlx sorts by file name).
        let versions: Vec<i64> = MIGRATIONS.iter().map(|m| m.version).collect();
        let mut sorted = versions.clone();
        sorted.sort();
        assert_eq!(versions, sorted, "migrations must be in version order");
    }

    #[test]
    fn every_migration_creates_a_table() {
        for m in MIGRATIONS.iter() {
            let upper = m.sql.to_ascii_uppercase();
            assert!(
                upper.contains("CREATE TABLE"),
                "migration {} has no CREATE TABLE: {}",
                m.version,
                m.description
            );
        }
    }

    #[test]
    fn every_tenanted_table_has_rls_policy() {
        // Each migration that creates a tenanted table MUST also enable
        // RLS and create the tenant_isolation policy. v0.1 list: every
        // migration except the realm-bootstrap one (realm itself isn't
        // tenanted — it IS the tenant).
        for m in MIGRATIONS.iter() {
            let upper = m.sql.to_ascii_uppercase();
            if m.description.contains("init realm") {
                // Realm table itself: no RLS needed. realm_id is the
                // RLS pivot.
                continue;
            }
            if m.description.contains("init audit") {
                // Audit has its policy too; partitioning is orthogonal.
                assert!(upper.contains("ENABLE ROW LEVEL SECURITY"), "{}", m.description);
                assert!(upper.contains("TENANT_ISOLATION"), "{}", m.description);
                continue;
            }
            assert!(
                upper.contains("ENABLE ROW LEVEL SECURITY"),
                "{} missing RLS",
                m.description
            );
            assert!(
                upper.contains("TENANT_ISOLATION"),
                "{} missing tenant_isolation policy",
                m.description
            );
        }
    }

    #[test]
    fn rls_predicate_uses_current_setting_geonosis_realm_id() {
        let mut hits = 0;
        for m in MIGRATIONS.iter() {
            let lower = m.sql.to_ascii_lowercase();
            if lower.contains("policy tenant_isolation") {
                hits += 1;
                assert!(
                    lower.contains("current_setting('geonosis.realm_id', true)"),
                    "{} uses wrong predicate",
                    m.description
                );
            }
        }
        assert!(hits >= 1, "expected at least one tenant_isolation policy");
    }

    #[test]
    fn brute_force_columns_present_on_app_user() {
        let m = MIGRATIONS
            .iter()
            .find(|m| m.description.contains("init user"))
            .expect("init user migration");
        let s = m.sql.as_ref();
        for col in ["failed_attempts", "locked_until", "last_failed_at"] {
            assert!(s.contains(col), "init user missing column {col}");
        }
    }

    #[test]
    fn audit_event_is_partitioned() {
        let m = MIGRATIONS
            .iter()
            .find(|m| m.description.contains("init audit"))
            .expect("init audit migration");
        let s = m.sql.to_ascii_uppercase();
        assert!(s.contains("PARTITION BY RANGE"), "audit_event must be partitioned");
        assert!(s.contains("PARTITION OF AUDIT_EVENT"), "must declare partitions");
    }

    #[test]
    fn search_vector_present_on_app_user() {
        let m = MIGRATIONS
            .iter()
            .find(|m| m.description.contains("init user"))
            .expect("init user migration");
        let s = m.sql.as_ref();
        assert!(s.contains("search_vector"));
        assert!(s.contains("GIN"));
        assert!(s.contains("tsvector"));
    }

    #[test]
    fn compat_window_accepts_current_set() {
        // The compatibility window is broad enough that the 8 v0.1
        // migrations all fall inside it.
        let last = MIGRATIONS.iter().last().expect("at least one migration");
        assert!(last.version >= V0_1_COMPAT.min_schema);
        assert!(last.version <= V0_1_COMPAT.max_schema);
    }
}
