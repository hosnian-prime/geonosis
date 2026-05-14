//! `geoctl realms` — realm CRUD.
//!
//! Talks to `/admin/v1/realms` via the shared [`AdminClient`].
//! Canonical pattern other command modules clone.

use clap::Subcommand;
use serde::{Deserialize, Serialize};

use crate::http::AdminClient;

#[derive(Subcommand, Debug)]
pub enum RealmCmd {
    /// Create a realm.
    Create {
        #[arg(long)]
        slug: String,
        #[arg(long)]
        display_name: String,
        #[arg(long, default_value_t = true)]
        enabled: bool,
    },
    /// List every realm on this server.
    List,
    /// Show a single realm by slug.
    Get {
        #[arg(long)]
        slug: String,
    },
    /// Toggle `enabled` on a realm. v0.1 surfaces only the most
    /// common patch; richer field-level updates land with the
    /// admin-UI form-builder in WS7.
    Patch {
        #[arg(long)]
        slug: String,
        #[arg(long)]
        enabled: Option<bool>,
        #[arg(long)]
        display_name: Option<String>,
    },
    /// Delete a realm. Cascades to every realm-scoped row.
    Delete {
        #[arg(long)]
        slug: String,
    },
}

#[derive(Debug, Serialize)]
struct CreateBody<'a> {
    slug: &'a str,
    display_name: &'a str,
    enabled: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct RealmRow {
    slug: String,
    display_name: String,
    enabled: bool,
    #[serde(default)]
    id: Option<String>,
}

pub async fn run(client: &AdminClient, cmd: RealmCmd) -> anyhow::Result<()> {
    match cmd {
        RealmCmd::Create {
            slug,
            display_name,
            enabled,
        } => {
            let body = CreateBody {
                slug: &slug,
                display_name: &display_name,
                enabled,
            };
            let created: RealmRow = client.post("/admin/v1/realms", &body).await?;
            println!("created realm slug={}", created.slug);
        }
        RealmCmd::List => {
            let rows: Vec<RealmRow> = client.get("/admin/v1/realms").await?;
            print_table(&rows);
        }
        RealmCmd::Get { slug } => {
            let path = format!("/admin/v1/realms/{slug}");
            let row: serde_json::Value = client.get(&path).await?;
            println!("{}", serde_json::to_string_pretty(&row)?);
        }
        RealmCmd::Patch {
            slug,
            enabled,
            display_name,
        } => {
            // Fetch, mutate the requested fields, PUT back. v0.1
            // patch-by-replace; v0.2 will use JSON Patch once the
            // server-side handler supports it.
            let path = format!("/admin/v1/realms/{slug}");
            let mut row: serde_json::Value = client.get(&path).await?;
            if let Some(e) = enabled {
                row["enabled"] = serde_json::Value::Bool(e);
            }
            if let Some(d) = display_name {
                row["display_name"] = serde_json::Value::String(d);
            }
            let updated: serde_json::Value = client.put(&path, &row).await?;
            println!("patched realm slug={slug} enabled={}", updated["enabled"]);
        }
        RealmCmd::Delete { slug } => {
            client.delete(&format!("/admin/v1/realms/{slug}")).await?;
            println!("deleted realm slug={slug}");
        }
    }
    Ok(())
}

fn print_table(rows: &[RealmRow]) {
    println!("{:<24} {:<32} {}", "SLUG", "DISPLAY NAME", "ENABLED");
    for r in rows {
        println!(
            "{:<24} {:<32} {}",
            r.slug,
            r.display_name,
            if r.enabled { "yes" } else { "no" }
        );
    }
}
