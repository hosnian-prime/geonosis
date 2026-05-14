//! `geoctl` — operator CLI for Geonosis.
//!
//! v0.1 surface mirrors the admin REST API in `docs/08-admin-ui.md`
//! plus a handful of database-admin commands (migrate, spi install,
//! federation sync) that run directly against Postgres because they
//! carry artefacts the HTTP path can't shape well (megabyte-scale
//! WASM blobs, leader-locked DDL, LDAP credentials).
//!
//! The split lives in `commands/mod.rs`: entity-management commands
//! go through [`AdminClient`] (one bearer token, one error mapper,
//! one user-agent), database-admin commands take `--database-url`.

mod commands;
mod http;

use clap::{Parser, Subcommand};

use crate::http::AdminClient;

#[derive(Debug, Parser)]
#[command(name = "geoctl", version, about = "Geonosis operator CLI")]
struct Cli {
    /// Base URL of the Geonosis admin API. Inferred from `GEONOSIS_URL`.
    /// Required for any command that talks to the admin REST API.
    #[arg(long, env = "GEONOSIS_URL", global = true)]
    server: Option<String>,

    /// Bearer token for the admin API. Inferred from
    /// `GEONOSIS_ADMIN_TOKEN`. v0.1 bootstrap reads it directly; the
    /// OAuth client-credentials login flow lands with `geoctl login`
    /// in v0.1.x.
    #[arg(long, env = "GEONOSIS_ADMIN_TOKEN", global = true)]
    token: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Realm CRUD.
    Realms {
        #[command(subcommand)]
        cmd: commands::realms::RealmCmd,
    },
    /// User CRUD + admin credential ops.
    Users {
        #[command(subcommand)]
        cmd: commands::users::UserCmd,
    },
    /// OIDC / SAML client CRUD.
    Clients {
        #[command(subcommand)]
        cmd: commands::clients::ClientCmd,
    },
    /// Organization CRUD + sub-resources (domains, members,
    /// invitations, roles, IdP bindings).
    Orgs {
        #[command(subcommand)]
        cmd: commands::orgs::OrgCmd,
    },
    /// AI / M2M agent CRUD + revoke.
    Agents {
        #[command(subcommand)]
        cmd: commands::agents::AgentCmd,
    },
    /// Realm signing-key inspection.
    Keys {
        #[command(subcommand)]
        cmd: commands::keys::KeyCmd,
    },
    /// Audit event log queries.
    Events {
        #[command(subcommand)]
        cmd: commands::events::EventCmd,
    },
    /// Flow DSL validate / export / import.
    Flows {
        #[command(subcommand)]
        cmd: commands::flows::FlowsCmd,
    },
    /// SPI plugin operations (direct DB).
    Spi {
        /// Postgres connection URL. Inferred from `GEONOSIS_DATABASE_URL`.
        #[arg(long, env = "GEONOSIS_DATABASE_URL")]
        database_url: String,
        #[command(subcommand)]
        cmd: commands::spi::SpiCmd,
    },
    /// Database migration operations (direct DB, leader-locked).
    Migrate {
        #[arg(long, env = "GEONOSIS_DATABASE_URL")]
        database_url: String,
        #[command(subcommand)]
        cmd: commands::migrate::MigrateCmd,
    },
    /// LDAP / AD federation operations (direct DB).
    Federation {
        #[arg(long, env = "GEONOSIS_DATABASE_URL")]
        database_url: String,
        #[command(subcommand)]
        cmd: commands::federation::FederationCmd,
    },
    /// Print the version.
    Version,
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
        Cmd::Realms { cmd } => {
            let client = admin_client(cli.server.as_deref(), cli.token.clone())?;
            rt.block_on(commands::realms::run(&client, cmd))
        }
        Cmd::Users { cmd } => {
            let client = admin_client(cli.server.as_deref(), cli.token.clone())?;
            rt.block_on(commands::users::run(&client, cmd))
        }
        Cmd::Clients { cmd } => {
            let client = admin_client(cli.server.as_deref(), cli.token.clone())?;
            rt.block_on(commands::clients::run(&client, cmd))
        }
        Cmd::Orgs { cmd } => {
            let client = admin_client(cli.server.as_deref(), cli.token.clone())?;
            rt.block_on(commands::orgs::run(&client, cmd))
        }
        Cmd::Agents { cmd } => {
            let client = admin_client(cli.server.as_deref(), cli.token.clone())?;
            rt.block_on(commands::agents::run(&client, cmd))
        }
        Cmd::Keys { cmd } => {
            let client = admin_client(cli.server.as_deref(), cli.token.clone())?;
            rt.block_on(commands::keys::run(&client, cmd))
        }
        Cmd::Events { cmd } => {
            let client = admin_client(cli.server.as_deref(), cli.token.clone())?;
            rt.block_on(commands::events::run(&client, cmd))
        }
        Cmd::Flows { cmd } => {
            // `validate` runs offline; the others need the admin API.
            // Build the client lazily inside the command module via the
            // shared helper: a malformed `--server` should still let
            // `flows validate` work.
            if matches!(cmd, commands::flows::FlowsCmd::Validate { .. }) {
                let dummy = AdminClient::new("http://localhost/", None)?;
                rt.block_on(commands::flows::run(&dummy, cmd))
            } else {
                let client = admin_client(cli.server.as_deref(), cli.token.clone())?;
                rt.block_on(commands::flows::run(&client, cmd))
            }
        }
        Cmd::Spi { database_url, cmd } => rt.block_on(commands::spi::run(&database_url, cmd)),
        Cmd::Migrate { database_url, cmd } => {
            rt.block_on(commands::migrate::run(&database_url, cmd))
        }
        Cmd::Federation { database_url, cmd } => {
            rt.block_on(commands::federation::run(&database_url, cmd))
        }
    }
}

fn admin_client(server: Option<&str>, token: Option<String>) -> anyhow::Result<AdminClient> {
    let server = server.ok_or_else(|| {
        anyhow::anyhow!("admin API URL required; pass --server or set GEONOSIS_URL")
    })?;
    AdminClient::new(server, token)
}
