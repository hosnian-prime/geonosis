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
        /// Postgres connection URL. Inferred from `GEONOSIS_DATABASE_URL`.
        #[arg(long, env = "GEONOSIS_DATABASE_URL")]
        database_url: String,
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
    /// Print the version.
    Version,
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
    /// Install a WASM plugin under a realm. Uploads bytes + creates the
    /// SPI binding row (one transaction-ish flow; admins may roll the
    /// upload back by deleting the binding).
    Install {
        /// Realm slug.
        #[arg(long)]
        realm: String,
        /// Stable WIT interface name, e.g. `geonosis:mapper@0.1.0`.
        #[arg(long)]
        interface: String,
        /// Operator-chosen alias; becomes `wasm:{alias}:{interface-short}`.
        #[arg(long)]
        alias: String,
        /// Path to the compiled `.wasm` component.
        #[arg(long)]
        module: String,
        /// Provider priority. Lower binds higher in the chain.
        #[arg(long, default_value_t = 500)]
        priority: i32,
        /// Force-disables a built-in (URN) while this binding is enabled.
        #[arg(long)]
        replaces: Option<String>,
        /// JSON-encoded provider config.
        #[arg(long, default_value = "{}")]
        config: String,
    },
    /// List installed bindings for an interface.
    List {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        interface: String,
    },
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
        Cmd::Spi { database_url, cmd } => rt.block_on(run_spi(&database_url, cmd)),
        Cmd::Migrate { database_url, cmd } => rt.block_on(run_migrate(&database_url, cmd)),
    }
}

async fn run_spi(database_url: &str, cmd: SpiCmd) -> anyhow::Result<()> {
    use geonosis_core::id::{SpiBindingId, WasmModuleId};
    use geonosis_storage::{SpiBindingRow, Storage, WasmModule};

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(database_url)
        .await?;
    let storage = geonosis_storage::PostgresStorage::new(pool);
    match cmd {
        SpiCmd::Install {
            realm,
            interface,
            alias,
            module,
            priority,
            replaces,
            config,
        } => {
            let realm_row = storage.get_realm_by_slug(&realm).await?;
            let bytecode = std::fs::read(&module)?;
            let sha = {
                use sha2::Digest;
                let mut h = sha2::Sha256::new();
                h.update(&bytecode);
                hex::encode(h.finalize())
            };
            let size = bytecode.len() as i64;
            let m = WasmModule {
                id: WasmModuleId::new(),
                realm_id: realm_row.id,
                alias: alias.clone(),
                interface: interface.clone(),
                sha256_hex: sha.clone(),
                size_bytes: size,
                bytecode,
                uploaded_by: None,
                created_at: chrono::Utc::now(),
            };
            storage.upload_wasm_module(m).await?;
            let cfg_json: serde_json::Value = serde_json::from_str(&config)?;
            let now = chrono::Utc::now();
            let urn_short = interface
                .strip_prefix("geonosis:")
                .and_then(|s| s.split_once('@').map(|(p, _)| p))
                .unwrap_or(&interface);
            let urn = format!("wasm:{alias}:{urn_short}");
            let binding = SpiBindingRow {
                id: SpiBindingId::new(),
                realm_id: realm_row.id,
                interface: interface.clone(),
                provider_urn: urn.clone(),
                priority,
                enabled: true,
                config: cfg_json,
                replaces,
                created_at: now,
                updated_at: now,
            };
            storage.create_spi_binding(binding).await?;
            println!("installed urn={urn} sha256={sha} bytes={size}");
        }
        SpiCmd::List { realm, interface } => {
            let r = storage.get_realm_by_slug(&realm).await?;
            let rows = storage.list_spi_bindings(r.id, &interface).await?;
            for row in rows {
                println!(
                    "{:<5} {:<60} {} {}",
                    row.priority,
                    row.provider_urn,
                    if row.enabled { "enabled" } else { "disabled" },
                    row.replaces.as_deref().unwrap_or("-")
                );
            }
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
