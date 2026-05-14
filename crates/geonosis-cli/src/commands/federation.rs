//! `geoctl federation` — LDAP / AD federation sync + list.
//!
//! Direct-Postgres path (see `commands/mod.rs`). The sync routine
//! reads the LDAP source config out of the DB, opens a pool against
//! the directory, and writes the resulting user/group rows back
//! through the storage trait. Routing through HTTP would force the
//! admin server to talk LDAP — which is the operator's responsibility,
//! not the request-path server's.

use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum FederationCmd {
    /// Run a synchronization pass against a federated LDAP source.
    Sync {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        source: String,
        /// Walk the whole tree (default). Pass `--since` for an
        /// incremental sync starting from that RFC 3339 timestamp.
        #[arg(long, conflicts_with = "since")]
        full: bool,
        #[arg(long)]
        since: Option<String>,
    },
    /// List configured LDAP sources for a realm.
    List {
        #[arg(long)]
        realm: String,
    },
}

pub async fn run(database_url: &str, cmd: FederationCmd) -> anyhow::Result<()> {
    use geonosis_storage::Storage;

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(database_url)
        .await?;
    let storage = geonosis_storage::PostgresStorage::new(pool);
    match cmd {
        FederationCmd::List { realm } => {
            let r = storage.get_realm_by_slug(&realm).await?;
            let sources = storage.list_ldap_sources(r.id).await?;
            for s in sources {
                println!(
                    "{:<24} pri={:<4} {} {}",
                    s.alias,
                    s.priority,
                    if s.enabled { "enabled" } else { "disabled" },
                    s.urls.join(",")
                );
            }
        }
        FederationCmd::Sync {
            realm,
            source,
            full: _,
            since,
        } => {
            let r = storage.get_realm_by_slug(&realm).await?;
            let cfg = storage.get_ldap_source(r.id, &source).await?;
            let pool = geonosis_federation_ldap::LdapPool::new(cfg);
            let report = if let Some(s) = since {
                let dt = chrono::DateTime::parse_from_rfc3339(&s)?.with_timezone(&chrono::Utc);
                let (rep, outcomes) =
                    geonosis_federation_ldap::run_incremental_sync(&pool, r.id, dt).await?;
                println!("incremental sync: {} entries", outcomes.len());
                rep
            } else {
                let (rep, outcomes) = geonosis_federation_ldap::run_full_sync(&pool, r.id).await?;
                println!("full sync: {} entries", outcomes.len());
                rep
            };
            println!(
                "started_at={}  finished_at={}",
                report.started_at.to_rfc3339(),
                report.finished_at.to_rfc3339()
            );
        }
    }
    Ok(())
}
