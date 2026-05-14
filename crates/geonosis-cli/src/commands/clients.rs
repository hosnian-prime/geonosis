//! `geoctl clients` — OIDC / SAML client CRUD.

use clap::{Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

use crate::http::AdminClient;

#[derive(Subcommand, Debug)]
pub enum ClientCmd {
    /// Register a client.
    Create {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        display_name: Option<String>,
        #[arg(long, value_enum)]
        kind: ClientKindArg,
        /// One redirect URI; pass `--redirect-uri` multiple times for
        /// more.
        #[arg(long = "redirect-uri")]
        redirect_uris: Vec<String>,
    },
    List {
        #[arg(long)]
        realm: String,
    },
    Get {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        client_id: String,
    },
    Delete {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        client_id: String,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientKindArg {
    Public,
    Confidential,
    BearerOnly,
    ServiceAccount,
    SamlServiceProvider,
    ScimClient,
}

#[derive(Debug, Serialize)]
struct CreateBody<'a> {
    client_id: &'a str,
    display_name: Option<&'a str>,
    kind: ClientKindArg,
    redirect_uris: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ClientRow {
    client_id: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    kind: serde_json::Value,
    enabled: bool,
}

pub async fn run(client: &AdminClient, cmd: ClientCmd) -> anyhow::Result<()> {
    match cmd {
        ClientCmd::Create {
            realm,
            client_id,
            display_name,
            kind,
            redirect_uris,
        } => {
            let path = format!("/admin/v1/realms/{realm}/clients");
            let body = CreateBody {
                client_id: &client_id,
                display_name: display_name.as_deref(),
                kind,
                redirect_uris,
            };
            let _: ClientRow = client.post(&path, &body).await?;
            println!("created client realm={realm} client_id={client_id}");
        }
        ClientCmd::List { realm } => {
            let path = format!("/admin/v1/realms/{realm}/clients");
            let rows: Vec<ClientRow> = client.get(&path).await?;
            println!("{:<32} {:<24} {:<16} {}", "CLIENT_ID", "DISPLAY NAME", "KIND", "ENABLED");
            for r in rows {
                println!(
                    "{:<32} {:<24} {:<16} {}",
                    r.client_id,
                    r.display_name.unwrap_or_default(),
                    r.kind.as_str().unwrap_or(""),
                    if r.enabled { "yes" } else { "no" }
                );
            }
        }
        ClientCmd::Get { realm, client_id } => {
            let path = format!("/admin/v1/realms/{realm}/clients/{client_id}");
            let row: serde_json::Value = client.get(&path).await?;
            println!("{}", serde_json::to_string_pretty(&row)?);
        }
        ClientCmd::Delete { realm, client_id } => {
            let path = format!("/admin/v1/realms/{realm}/clients/{client_id}");
            client.delete(&path).await?;
            println!("deleted client realm={realm} client_id={client_id}");
        }
    }
    Ok(())
}
