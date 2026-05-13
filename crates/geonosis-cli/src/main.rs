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
    /// Install a signed WASM plugin manifest.
    Install { manifest: String },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Version => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Cmd::Flows { cmd } => match cmd {
            FlowsCmd::Validate { path } => validate_flow(&path),
        },
        Cmd::Realm { cmd } => match cmd {
            RealmCmd::Create { slug } => {
                anyhow::bail!(
                    "realm create requires admin API connection; pass --server (got slug={slug})"
                );
            }
            RealmCmd::List => {
                anyhow::bail!("realm list requires admin API connection; pass --server");
            }
            RealmCmd::Export { slug } => {
                anyhow::bail!(
                    "realm export requires admin API connection; pass --server (got slug={slug})"
                );
            }
        },
        Cmd::Spi { cmd } => match cmd {
            SpiCmd::Install { manifest } => {
                anyhow::bail!(
                    "spi install requires admin API connection; pass --server (got manifest={manifest})"
                );
            }
        },
    }
}

fn validate_flow(path: &str) -> anyhow::Result<()> {
    let bytes = std::fs::read(path)?;
    let def: geonosis_flow::FlowDefinition = serde_json::from_slice(&bytes)?;
    geonosis_flow::compile(def)?;
    println!("flow OK");
    Ok(())
}
