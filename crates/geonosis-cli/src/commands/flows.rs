//! `geoctl flows` — flow DSL validate / export / import.
//!
//! `validate` runs offline against `geonosis-flow::compile`; the other
//! two go through the admin REST API via [`AdminClient`]. Import
//! validates locally first as defense in depth so a malformed flow
//! never reaches the server (the server validates again).

use clap::Subcommand;

use crate::http::AdminClient;

#[derive(Subcommand, Debug)]
pub enum FlowsCmd {
    /// Validate a flow JSON file offline.
    Validate {
        #[arg(long)]
        path: String,
    },
    /// Download the flow under `--realm` / `--alias` from the admin
    /// API and write it to stdout (or `--out` if given). The server
    /// returns the canonical `FlowDefinition` JSON so a round-trip
    /// through `import` is byte-stable.
    Export {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        alias: String,
        /// Output path; defaults to stdout.
        #[arg(long)]
        out: Option<String>,
    },
    /// Upload a flow JSON file to the admin API. The file is validated
    /// offline first so malformed input never reaches the server.
    Import {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        alias: String,
        #[arg(long)]
        file: String,
    },
}

pub async fn run(client: &AdminClient, cmd: FlowsCmd) -> anyhow::Result<()> {
    match cmd {
        FlowsCmd::Validate { path } => validate_flow(&path),
        FlowsCmd::Export { realm, alias, out } => {
            let path = format!("/admin/v1/realms/{realm}/flows/{alias}");
            let def: geonosis_flow::FlowDefinition = client.get(&path).await?;
            let pretty = serde_json::to_vec_pretty(&def)?;
            match out {
                None => {
                    use std::io::Write as _;
                    std::io::stdout().write_all(&pretty)?;
                    std::io::stdout().write_all(b"\n")?;
                }
                Some(p) => std::fs::write(p, pretty)?,
            }
            Ok(())
        }
        FlowsCmd::Import { realm, alias, file } => {
            let bytes = std::fs::read(&file)?;
            let def: geonosis_flow::FlowDefinition = serde_json::from_slice(&bytes)?;
            geonosis_flow::compile(def.clone())?;
            let path = format!("/admin/v1/realms/{realm}/flows/{alias}");
            let _: serde_json::Value = client.put(&path, &def).await?;
            println!("flow {alias} imported into realm {realm}");
            Ok(())
        }
    }
}

fn validate_flow(path: &str) -> anyhow::Result<()> {
    let bytes = std::fs::read(path)?;
    let def: geonosis_flow::FlowDefinition = serde_json::from_slice(&bytes)?;
    geonosis_flow::compile(def)?;
    println!("flow OK");
    Ok(())
}
