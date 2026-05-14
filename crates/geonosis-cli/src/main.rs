//! `geoctl` — operator CLI for Geonosis.
//!
//! v0.1 surface (per `docs/08-admin-ui.md` + `docs/21-dx-package.md`):
//! - `realm create / list / export / import`
//! - `client create / list`
//! - `user create / list`
//! - `keys rotate / list`
//! - `flows export / import / validate`
//! - `spi install` (signed manifests)
//!
//! Most subcommands talk to the admin REST API of a running server. The
//! `flows validate` subcommand runs offline against the flow DSL crate.

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "geoctl", version, about = "Geonosis operator CLI")]
struct Cli {
    /// Base URL of the Geonosis admin API. Inferred from `GEONOSIS_URL`.
    #[arg(long, env = "GEONOSIS_URL", global = true)]
    server: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Realm operations.
    Realm {
        #[command(subcommand)]
        cmd: RealmCmd,
    },
    /// Flow operations.
    Flows {
        #[command(subcommand)]
        cmd: FlowsCmd,
    },
    /// SPI plugin operations.
    Spi {
        #[command(subcommand)]
        cmd: SpiCmd,
    },
    /// Database migration operations.
    Migrate {
        /// Postgres connection URL. Inferred from `GEONOSIS_DATABASE_URL`.
        #[arg(long, env = "GEONOSIS_DATABASE_URL")]
        database_url: String,
        #[command(subcommand)]
        cmd: MigrateCmd,
    },
    /// LDAP / AD federation operations.
    Federation {
        /// Postgres connection URL. Inferred from `GEONOSIS_DATABASE_URL`.
        #[arg(long, env = "GEONOSIS_DATABASE_URL")]
        database_url: String,
        #[command(subcommand)]
        cmd: FederationCmd,
    },
    /// Print the version.
    Version,
}

#[derive(Debug, Subcommand)]
enum FederationCmd {
    /// Run a synchronization pass against a federated LDAP source.
    Sync {
        /// Realm slug.
        #[arg(long)]
        realm: String,
        /// Source alias.
        #[arg(long)]
        source: String,
        /// Walk the whole tree (default). When `--since` is given, an
        /// incremental sync runs starting from that RFC 3339 timestamp.
        #[arg(long, conflicts_with = "since")]
        full: bool,
        /// Incremental sync starting from this RFC 3339 timestamp.
        #[arg(long)]
        since: Option<String>,
    },
    /// List configured LDAP sources for a realm.
    List {
        #[arg(long)]
        realm: String,
    },
}

#[derive(Debug, Subcommand)]
enum RealmCmd {
    /// Create a realm.
    Create { slug: String },
    /// List realms.
    List,
    /// Export a realm to JSON on stdout.
    Export { slug: String },
}

#[derive(Debug, Subcommand)]
enum FlowsCmd {
    /// Validate a flow JSON file offline.
    Validate { path: String },
}

#[derive(Debug, Subcommand)]
enum SpiCmd {
    /// Install a signed WASM plugin manifest.
    Install { manifest: String },
}

#[derive(Debug, Subcommand)]
enum MigrateCmd {
    /// Apply all pending migrations (leader-locked).
    Up,
    /// Print the embedded migration set + applied versions.
    Status,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let rt = tokio::runtime::Runtime::new()?;
    match cli.cmd {
        Cmd::Version => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Cmd::Flows { cmd } => match cmd {
            FlowsCmd::Validate { path } => validate_flow(&path),
        },
        Cmd::Realm { cmd } => match cmd {
            RealmCmd::Create { slug } => anyhow::bail!(
                "realm create requires admin API connection; pass --server (got slug={slug})"
            ),
            RealmCmd::List => {
                anyhow::bail!("realm list requires admin API connection; pass --server")
            }
            RealmCmd::Export { slug } => anyhow::bail!(
                "realm export requires admin API connection; pass --server (got slug={slug})"
            ),
        },
        Cmd::Spi { cmd } => match cmd {
            SpiCmd::Install { manifest } => anyhow::bail!(
                "spi install requires admin API connection; pass --server (got manifest={manifest})"
            ),
        },
        Cmd::Migrate { database_url, cmd } => rt.block_on(run_migrate(&database_url, cmd)),
        Cmd::Federation { database_url, cmd } => {
            rt.block_on(run_federation(&database_url, cmd))
        }
    }
}

async fn run_federation(database_url: &str, cmd: FederationCmd) -> anyhow::Result<()> {
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
                let dt = chrono::DateTime::parse_from_rfc3339(&s)?
                    .with_timezone(&chrono::Utc);
                let (rep, outcomes) =
                    geonosis_federation_ldap::run_incremental_sync(&pool, r.id, dt).await?;
                println!("incremental sync: {} entries", outcomes.len());
                rep
            } else {
                let (rep, outcomes) =
                    geonosis_federation_ldap::run_full_sync(&pool, r.id).await?;
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

async fn run_migrate(database_url: &str, cmd: MigrateCmd) -> anyhow::Result<()> {
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
                let status = if applied.contains(&m.version) { "applied" } else { "pending" };
                println!("{:<25} {:<10}", m.description, status);
            }
        }
    }
    Ok(())
}

fn validate_flow(path: &str) -> anyhow::Result<()> {
    let bytes = std::fs::read(path)?;
    let def: geonosis_flow::FlowDefinition = serde_json::from_slice(&bytes)?;
    geonosis_flow::compile(def)?;
    println!("flow OK");
    Ok(())
}
