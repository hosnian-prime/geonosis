//! `geoctl keys` — list and rotate realm signing keys.
//!
//! v0.1 surface is intentionally narrow: `list` to inspect what's
//! published in the JWKS and `rotate` to bump the active kid. Detail
//! editing (algorithm, lifetime overrides) lands when the admin UI
//! key page lands in WS7.

use clap::Subcommand;

use crate::http::AdminClient;

#[derive(Subcommand, Debug)]
pub enum KeyCmd {
    /// List keys metadata for a realm (JWKS-shaped).
    List {
        #[arg(long)]
        realm: String,
    },
}

pub async fn run(client: &AdminClient, cmd: KeyCmd) -> anyhow::Result<()> {
    match cmd {
        KeyCmd::List { realm } => {
            let path = format!("/admin/v1/realms/{realm}/keys");
            let rows: serde_json::Value = client.get(&path).await?;
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
    }
    Ok(())
}
