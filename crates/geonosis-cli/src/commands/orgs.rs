//! `geoctl orgs` — Organization CRUD + sub-resources.
//!
//! Sub-resources: domains, members, invitations, roles, consent
//! policies, IdP bindings. Recipes 09, 14, 15 lean on this surface.

use clap::Subcommand;
use serde::{Deserialize, Serialize};

use crate::http::AdminClient;

#[derive(Subcommand, Debug)]
pub enum OrgCmd {
    Create {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        alias: String,
        #[arg(long)]
        display_name: String,
        #[arg(long)]
        description: Option<String>,
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
    Delete {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        alias: String,
    },
    /// Add a candidate domain. Unverified by default; pair with
    /// `domain-verify` after the DNS TXT challenge succeeds.
    DomainAdd {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        alias: String,
        #[arg(long)]
        domain: String,
    },
    DomainVerify {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        alias: String,
        #[arg(long)]
        domain: String,
    },
    DomainList {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        alias: String,
    },
    DomainDelete {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        alias: String,
        #[arg(long)]
        domain: String,
    },
    /// Add a member by user-id (ULID).
    MemberAdd {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        alias: String,
        #[arg(long)]
        user_id: String,
    },
    MemberList {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        alias: String,
    },
    MemberRemove {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        alias: String,
        #[arg(long)]
        user_id: String,
    },
    /// Issue an invitation. The token is printed once.
    Invite {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        alias: String,
        #[arg(long)]
        email: String,
        #[arg(long)]
        invited_by: String,
    },
    /// Bind an IdP alias to the org so members SSO via that IdP.
    IdpBind {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        alias: String,
        #[arg(long)]
        idp_alias: String,
        #[arg(long, default_value_t = 0)]
        priority: i32,
    },
    /// Create an org-scoped role.
    RoleCreate {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        alias: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        description: Option<String>,
    },
    RoleList {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        alias: String,
    },
}

#[derive(Debug, Serialize)]
struct CreateBody<'a> {
    alias: &'a str,
    display_name: &'a str,
    description: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct OrgRow {
    alias: String,
    display_name: String,
    enabled: bool,
}

#[derive(Debug, Serialize)]
struct DomainBody<'a> {
    domain: &'a str,
}

#[derive(Debug, Serialize)]
struct MemberBody<'a> {
    user_id: &'a str,
}

#[derive(Debug, Serialize)]
struct InviteBody<'a> {
    email: &'a str,
    invited_by: &'a str,
}

#[derive(Debug, Serialize)]
struct IdpBindingBody<'a> {
    idp_alias: &'a str,
    priority: i32,
    enabled: bool,
}

#[derive(Debug, Serialize)]
struct OrgRoleBody<'a> {
    name: &'a str,
    description: Option<&'a str>,
}

pub async fn run(client: &AdminClient, cmd: OrgCmd) -> anyhow::Result<()> {
    match cmd {
        OrgCmd::Create {
            realm,
            alias,
            display_name,
            description,
        } => {
            let path = format!("/admin/v1/realms/{realm}/orgs");
            let body = CreateBody {
                alias: &alias,
                display_name: &display_name,
                description: description.as_deref(),
            };
            let _: OrgRow = client.post(&path, &body).await?;
            println!("created org realm={realm} alias={alias}");
        }
        OrgCmd::List { realm } => {
            let path = format!("/admin/v1/realms/{realm}/orgs");
            let rows: Vec<OrgRow> = client.get(&path).await?;
            println!("{:<24} {:<32} {}", "ALIAS", "DISPLAY NAME", "ENABLED");
            for r in rows {
                println!(
                    "{:<24} {:<32} {}",
                    r.alias,
                    r.display_name,
                    if r.enabled { "yes" } else { "no" }
                );
            }
        }
        OrgCmd::Get { realm, alias } => {
            let path = format!("/admin/v1/realms/{realm}/orgs/{alias}");
            let row: serde_json::Value = client.get(&path).await?;
            println!("{}", serde_json::to_string_pretty(&row)?);
        }
        OrgCmd::Delete { realm, alias } => {
            client
                .delete(&format!("/admin/v1/realms/{realm}/orgs/{alias}"))
                .await?;
            println!("deleted org realm={realm} alias={alias}");
        }
        OrgCmd::DomainAdd { realm, alias, domain } => {
            let path = format!("/admin/v1/realms/{realm}/orgs/{alias}/domains");
            let body = DomainBody { domain: &domain };
            let _: serde_json::Value = client.post(&path, &body).await?;
            println!("added domain={domain} (unverified) realm={realm} org={alias}");
        }
        OrgCmd::DomainVerify { realm, alias, domain } => {
            let path =
                format!("/admin/v1/realms/{realm}/orgs/{alias}/domains/{domain}/verify");
            client.post_empty(&path).await?;
            println!("verified domain={domain} realm={realm} org={alias}");
        }
        OrgCmd::DomainList { realm, alias } => {
            let path = format!("/admin/v1/realms/{realm}/orgs/{alias}/domains");
            let rows: serde_json::Value = client.get(&path).await?;
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        OrgCmd::DomainDelete { realm, alias, domain } => {
            client
                .delete(&format!("/admin/v1/realms/{realm}/orgs/{alias}/domains/{domain}"))
                .await?;
            println!("deleted domain={domain} realm={realm} org={alias}");
        }
        OrgCmd::MemberAdd { realm, alias, user_id } => {
            let path = format!("/admin/v1/realms/{realm}/orgs/{alias}/memberships");
            let _: serde_json::Value =
                client.post(&path, &MemberBody { user_id: &user_id }).await?;
            println!("added member user_id={user_id} realm={realm} org={alias}");
        }
        OrgCmd::MemberList { realm, alias } => {
            let path = format!("/admin/v1/realms/{realm}/orgs/{alias}/memberships");
            let rows: serde_json::Value = client.get(&path).await?;
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        OrgCmd::MemberRemove { realm, alias, user_id } => {
            client
                .delete(&format!("/admin/v1/realms/{realm}/orgs/{alias}/memberships/{user_id}"))
                .await?;
            println!("removed member user_id={user_id} realm={realm} org={alias}");
        }
        OrgCmd::Invite { realm, alias, email, invited_by } => {
            let path = format!("/admin/v1/realms/{realm}/orgs/{alias}/invitations");
            let inv: serde_json::Value = client
                .post(
                    &path,
                    &InviteBody {
                        email: &email,
                        invited_by: &invited_by,
                    },
                )
                .await?;
            println!("invitation for email={email} token={}", inv["token"]);
        }
        OrgCmd::IdpBind { realm, alias, idp_alias, priority } => {
            let path = format!("/admin/v1/realms/{realm}/orgs/{alias}/idps");
            let _: serde_json::Value = client
                .post(
                    &path,
                    &IdpBindingBody {
                        idp_alias: &idp_alias,
                        priority,
                        enabled: true,
                    },
                )
                .await?;
            println!("bound idp={idp_alias} → org={alias} priority={priority}");
        }
        OrgCmd::RoleCreate { realm, alias, name, description } => {
            let path = format!("/admin/v1/realms/{realm}/orgs/{alias}/roles");
            let _: serde_json::Value = client
                .post(
                    &path,
                    &OrgRoleBody {
                        name: &name,
                        description: description.as_deref(),
                    },
                )
                .await?;
            println!("created org role realm={realm} org={alias} name={name}");
        }
        OrgCmd::RoleList { realm, alias } => {
            let path = format!("/admin/v1/realms/{realm}/orgs/{alias}/roles");
            let rows: serde_json::Value = client.get(&path).await?;
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
    }
    Ok(())
}
