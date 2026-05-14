//! `geoctl migrate` — apply / inspect database migrations.
//!
//! Direct-Postgres path (see `commands/mod.rs` dispatch rule): leader
//! election + DDL safety lives in `geonosis-migrate` and the leader
//! advisory lock is per-database, not per-pod. Routing this through
//! the HTTP admin API would re-implement the lock on the server side
//! and break operators running migrations against a database with no
//! live server (cold-start, rollback scenarios).

use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum MigrateCmd {
    /// Apply all pending migrations (leader-locked).
    Up,
    /// Print the embedded migration set + applied versions.
    Status,
}

pub async fn run(database_url: &str, cmd: MigrateCmd) -> anyhow::Result<()> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(database_url)
        .await?;
    match cmd {
        MigrateCmd::Up => {
            geonosis_migrate::run_with_leader_lock(&pool).await?;
            geonosis_migrate::enforce_schema_compat(&pool, geonosis_migrate::V0_1_COMPAT).await?;
            println!("migrations applied");
        }
        MigrateCmd::Status => {
            let applied: Vec<(i64,)> =
                sqlx::query_as("SELECT version FROM _sqlx_migrations ORDER BY version")
                    .fetch_all(&pool)
                    .await
                    .unwrap_or_default();
            let applied: std::collections::BTreeSet<i64> =
                applied.into_iter().map(|(v,)| v).collect();
            println!("{:<25} {:<10}", "migration", "status");
            for m in geonosis_migrate::MIGRATIONS.iter() {
                let status = if applied.contains(&m.version) {
                    "applied"
                } else {
                    "pending"
                };
                println!("{:<25} {:<10}", m.description, status);
            }
        }
    }
    Ok(())
}
