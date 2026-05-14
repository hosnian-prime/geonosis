//! `geoctl users` — user CRUD + admin credential ops.
//!
//! Covers the recipe-blocking commands: `create`, `verify-email`,
//! `password-set`, `list`, `get`, `delete`.

use clap::Subcommand;
use serde::{Deserialize, Serialize};

use crate::http::AdminClient;

#[derive(Subcommand, Debug)]
pub enum UserCmd {
    /// Create a user.
    Create {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        email: Option<String>,
        #[arg(long, default_value_t = false)]
        email_verified: bool,
        #[arg(long, default_value_t = true)]
        enabled: bool,
    },
    /// List users (up to `--limit` rows).
    List {
        #[arg(long)]
        realm: String,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Show one user by username.
    Get {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        username: String,
    },
    /// Mark `email_verified = true` (admin override; recipe 01 uses
    /// this to skip the verify-email flow during local dev).
    VerifyEmail {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        username: String,
    },
    /// Set / rotate the password hash. Plaintext stays on the wire
    /// only between CLI and server; the server Argon2id-hashes it
    /// before persisting.
    PasswordSet {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
    },
    /// Delete a user. Cascades to credentials, sessions, consents.
    Delete {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        username: String,
    },
}

#[derive(Debug, Serialize)]
struct CreateBody<'a> {
    username: &'a str,
    email: Option<&'a str>,
    email_verified: bool,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct UserRow {
    username: String,
    #[serde(default)]
    email: Option<String>,
    email_verified: bool,
    enabled: bool,
}

#[derive(Debug, Serialize)]
struct SetPasswordBody<'a> {
    password: &'a str,
}

pub async fn run(client: &AdminClient, cmd: UserCmd) -> anyhow::Result<()> {
    match cmd {
        UserCmd::Create {
            realm,
            username,
            email,
            email_verified,
            enabled,
        } => {
            let path = format!("/admin/v1/realms/{realm}/users");
            let body = CreateBody {
                username: &username,
                email: email.as_deref(),
                email_verified,
                enabled,
            };
            let _: UserRow = client.post(&path, &body).await?;
            println!("created user realm={realm} username={username}");
        }
        UserCmd::List { realm, limit } => {
            let path = format!("/admin/v1/realms/{realm}/users?limit={limit}");
            let rows: Vec<UserRow> = client.get(&path).await?;
            println!(
                "{:<24} {:<32} {:<10} {}",
                "USERNAME", "EMAIL", "VERIFIED", "ENABLED"
            );
            for r in rows {
                println!(
                    "{:<24} {:<32} {:<10} {}",
                    r.username,
                    r.email.unwrap_or_default(),
                    if r.email_verified { "yes" } else { "no" },
                    if r.enabled { "yes" } else { "no" }
                );
            }
        }
        UserCmd::Get { realm, username } => {
            let path = format!("/admin/v1/realms/{realm}/users/{username}");
            let row: serde_json::Value = client.get(&path).await?;
            println!("{}", serde_json::to_string_pretty(&row)?);
        }
        UserCmd::VerifyEmail { realm, username } => {
            let path = format!("/admin/v1/realms/{realm}/users/{username}/verify-email");
            client.post_empty(&path).await?;
            println!("verified email realm={realm} username={username}");
        }
        UserCmd::PasswordSet {
            realm,
            username,
            password,
        } => {
            let path = format!("/admin/v1/realms/{realm}/users/{username}/password");
            client
                .put_no_response(&path, &SetPasswordBody { password: &password })
                .await?;
            println!("password set realm={realm} username={username}");
        }
        UserCmd::Delete { realm, username } => {
            let path = format!("/admin/v1/realms/{realm}/users/{username}");
            client.delete(&path).await?;
            println!("deleted user realm={realm} username={username}");
        }
    }
    Ok(())
}
