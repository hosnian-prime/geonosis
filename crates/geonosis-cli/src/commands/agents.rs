//! `geoctl agents` — AI / M2M agent CRUD + revoke.
//!
//! Recipe 08 drives this surface.

use clap::{Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

use crate::http::AdminClient;

#[derive(Subcommand, Debug)]
pub enum AgentCmd {
    Create {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        alias: String,
        #[arg(long)]
        display_name: String,
        #[arg(long, value_enum, default_value_t = AgentKindArg::Assistant)]
        kind: AgentKindArg,
        /// Parent user-id (ULID) the agent acts on behalf of.
        #[arg(long)]
        parent_user_id: String,
        #[arg(long, value_enum, default_value_t = AuthMethodArg::PrivateKeyJwt)]
        auth_method: AuthMethodArg,
        #[arg(long)]
        model_hint: Option<String>,
        #[arg(long)]
        vendor: Option<String>,
    },
    List {
        #[arg(long)]
        realm: String,
    },
    Get {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        alias: String,
    },
    /// Permanent revocation. Sets `revoked_at` + `enabled=false`; the
    /// agent's tokens stop minting on the next /token call.
    Revoke {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        alias: String,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentKindArg {
    Assistant,
    Scraper,
    Webhook,
    Batch,
}

#[derive(ValueEnum, Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMethodArg {
    PrivateKeyJwt,
    DpopBoundKey,
    TokenExchangeOnly,
}

#[derive(Debug, Serialize)]
struct CreateBody<'a> {
    alias: &'a str,
    display_name: &'a str,
    kind: AgentKindArg,
    parent_subject: ParentSubjectWire<'a>,
    model_hint: Option<&'a str>,
    vendor: Option<&'a str>,
    auth_method: AuthMethodArg,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum ParentSubjectWire<'a> {
    User {
        #[serde(rename = "user_id")]
        user_id: &'a str,
    },
}

#[derive(Debug, Deserialize)]
struct AgentRow {
    alias: String,
    display_name: String,
    enabled: bool,
}

pub async fn run(client: &AdminClient, cmd: AgentCmd) -> anyhow::Result<()> {
    match cmd {
        AgentCmd::Create {
            realm,
            alias,
            display_name,
            kind,
            parent_user_id,
            auth_method,
            model_hint,
            vendor,
        } => {
            let path = format!("/admin/v1/realms/{realm}/agents");
            let body = CreateBody {
                alias: &alias,
                display_name: &display_name,
                kind,
                parent_subject: ParentSubjectWire::User {
                    user_id: &parent_user_id,
                },
                model_hint: model_hint.as_deref(),
                vendor: vendor.as_deref(),
                auth_method,
            };
            let _: serde_json::Value = client.post(&path, &body).await?;
            println!("created agent realm={realm} alias={alias}");
        }
        AgentCmd::List { realm } => {
            let path = format!("/admin/v1/realms/{realm}/agents");
            let rows: Vec<AgentRow> = client.get(&path).await?;
            println!("{:<32} {:<32} ENABLED", "ALIAS", "DISPLAY NAME");
            for r in rows {
                println!(
                    "{:<32} {:<32} {}",
                    r.alias,
                    r.display_name,
                    if r.enabled { "yes" } else { "no" }
                );
            }
        }
        AgentCmd::Get { realm, alias } => {
            let path = format!("/admin/v1/realms/{realm}/agents/{alias}");
            let row: serde_json::Value = client.get(&path).await?;
            println!("{}", serde_json::to_string_pretty(&row)?);
        }
        AgentCmd::Revoke { realm, alias } => {
            client
                .delete(&format!("/admin/v1/realms/{realm}/agents/{alias}"))
                .await?;
            println!("revoked agent realm={realm} alias={alias}");
        }
    }
    Ok(())
}
