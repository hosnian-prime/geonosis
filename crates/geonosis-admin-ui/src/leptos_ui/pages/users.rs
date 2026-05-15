//! `/admin/realms/{slug}/users` — list, create, detail with 8 tabs.
//! Per `docs/08-admin-ui.md` §2.4.

use leptos::prelude::*;

use geonosis_core::attribute::{AttributeValue, RequiredAction};
use geonosis_core::credential::CredentialKind;
use geonosis_core::User;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::breadcrumb::Crumb;
use crate::leptos_ui::components::form::{ActionBar, Field, TextInput, Toggle};
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;
use crate::leptos_ui::components::tabs::{TabBar, TabItem};
use crate::leptos_ui::components::widgets::{
    Alert, AlertKind, Badge, BadgeKind, ButtonKind, EmptyState, LinkButton, StateBadge,
};

#[derive(Clone, Debug)]
pub struct UserRow {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub enabled: bool,
    pub created_at: String,
}

#[component]
pub fn UsersPage(
    realm_slug: String,
    rows: Vec<UserRow>,
    ctx: PageContext,
    #[prop(default = String::new())] search: String,
) -> impl IntoView {
    let ctx = ctx
        .with_title("Users")
        .with_section("users")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::current("Users"),
        ]);
    let create_href = format!("/admin/realms/{realm_slug}/users/new");
    let search_action = format!("/admin/realms/{realm_slug}/users");
    let is_empty = rows.is_empty();
    view! {
        <Page context=ctx>
            <PageHeader
                title="Users".into()
                subtitle=Some("People who sign in to applications.".into())
                actions=Some(view! {
                    <LinkButton href=create_href.clone() label="+ Create user".to_string() kind=ButtonKind::Primary/>
                }.into_any())
            />
            <form method="get" action=search_action class="gn-filter-bar">
                <input class="gn-input" type="search" name="search" value=search.clone()
                    placeholder="Search by username, email or name"/>
                <button type="submit" class="gn-btn">"Search"</button>
            </form>
            {if is_empty {
                view! {
                    <EmptyState
                        title="No users match this filter".into()
                        description="Create the first user or relax the search.".into()
                    />
                }.into_any()
            } else {
                view! {
                    <ListTable headers=vec!["Username", "Email", "State", "Created"]>
                        {rows.into_iter().map(|u| {
                            let href = format!("/admin/realms/{realm_slug}/users/{}", u.username);
                            view! {
                                <tr>
                                    <td data-label="Username">
                                        <a href=href.clone()><code>{u.username}</code></a>
                                    </td>
                                    <td data-label="Email">{u.email.unwrap_or_else(|| "—".into())}</td>
                                    <td data-label="State"><StateBadge enabled=u.enabled/></td>
                                    <td data-label="Created" class="gn-text-subtle gn-text-sm">{u.created_at}</td>
                                </tr>
                            }
                        }).collect_view()}
                    </ListTable>
                }.into_any()
            }}
        </Page>
    }
}

#[component]
pub fn UserCreatePage(
    realm_slug: String,
    ctx: PageContext,
    #[prop(default = None)] error: Option<String>,
) -> impl IntoView {
    let ctx = ctx
        .with_title("Create user")
        .with_section("users")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::link("Users", format!("/admin/realms/{realm_slug}/users")),
            Crumb::current("Create"),
        ]);
    let action = format!("/admin/realms/{realm_slug}/users");
    let cancel = format!("/admin/realms/{realm_slug}/users");
    view! {
        <Page context=ctx>
            <PageHeader title="Create user".into()/>
            {error.map(|e| view! { <Alert message=e kind=AlertKind::Danger/> })}
            <form method="post" action=action class="gn-form">
                <Field label="Username".into() name="username".into() required=true>
                    <TextInput name="username".into() required=true autocomplete="off".into()/>
                </Field>
                <Field label="Email".into() name="email".into()>
                    <TextInput name="email".into() input_type="email".into() autocomplete="off".into()/>
                </Field>
                <Field label="First name".into() name="first_name".into()>
                    <TextInput name="first_name".into()/>
                </Field>
                <Field label="Last name".into() name="last_name".into()>
                    <TextInput name="last_name".into()/>
                </Field>
                <Toggle name="enabled".into() label="Enabled".into() checked=true/>
                <Toggle name="email_verified".into() label="Email verified".into() checked=false/>
                <Field label="Initial password".into() name="password".into()
                    hint=Some("Optional. Leave empty to require the user to set one on first login.".into())>
                    <TextInput name="password".into() input_type="password".into() autocomplete="new-password".into()/>
                </Field>
                <ActionBar>
                    <LinkButton href=cancel label="Cancel".to_string()/>
                    <button type="submit" class="gn-btn gn-btn--primary">"Create user"</button>
                </ActionBar>
            </form>
        </Page>
    }
}

pub const USER_TABS: &[(&str, &str)] = &[
    ("general", "General"),
    ("attributes", "Attributes"),
    ("credentials", "Credentials"),
    ("roles", "Roles"),
    ("groups", "Groups"),
    ("orgs", "Organizations"),
    ("sessions", "Sessions"),
    ("consents", "Consents"),
];

#[derive(Clone, Debug)]
pub struct UserDetailData {
    pub user: User,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    pub orgs: Vec<String>,
    pub sessions: Vec<UserSessionRow>,
}

#[derive(Clone, Debug)]
pub struct UserSessionRow {
    pub id: String,
    pub started_at: String,
    pub last_seen_at: String,
    pub client_count: usize,
}

#[component]
pub fn UserDetailPage(
    realm_slug: String,
    data: UserDetailData,
    active_tab: String,
    ctx: PageContext,
) -> impl IntoView {
    let username = data.user.username.clone();
    let display_name_str = display_name(data.user.clone());
    let ctx = ctx
        .with_title(format!("User · {username}"))
        .with_section("users")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::link("Users", format!("/admin/realms/{realm_slug}/users")),
            Crumb::current(username.clone()),
        ]);
    let tab_items = USER_TABS
        .iter()
        .map(|(k, label)| {
            TabItem::new(
                *k,
                *label,
                format!("/admin/realms/{realm_slug}/users/{username}?tab={k}"),
            )
        })
        .collect::<Vec<_>>();
    let panel = match active_tab.as_str() {
        "general" => render_general(realm_slug.clone(), data.user.clone()).into_any(),
        "attributes" => render_attributes(data.user.clone()).into_any(),
        "credentials" => render_credentials(realm_slug.clone(), data.user.clone()).into_any(),
        "roles" => render_roles(data.roles.clone()).into_any(),
        "groups" => render_groups(data.groups.clone()).into_any(),
        "orgs" => render_orgs(data.orgs.clone()).into_any(),
        "sessions" => {
            render_sessions(realm_slug.clone(), username.clone(), data.sessions.clone()).into_any()
        }
        "consents" => render_consents().into_any(),
        _ => view! { <Alert message="Unknown tab.".into() kind=AlertKind::Warning/> }.into_any(),
    };
    view! {
        <Page context=ctx>
            <PageHeader
                title=display_name_str
                subtitle=Some(format!("@{username}"))
            />
            <TabBar active=active_tab.clone() items=tab_items/>
            {panel}
        </Page>
    }
}

fn render_general(realm_slug: String, u: User) -> impl IntoView {
    let username = u.username.clone();
    let email = u.email.clone().unwrap_or_default();
    let first = u
        .name
        .as_ref()
        .and_then(|n| n.given.clone())
        .unwrap_or_default();
    let last = u
        .name
        .as_ref()
        .and_then(|n| n.family.clone())
        .unwrap_or_default();
    let action = format!("/admin/realms/{realm_slug}/users/{username}/general");
    let required_actions_csv = u
        .required_actions
        .iter()
        .map(required_action_value)
        .collect::<Vec<_>>()
        .join(", ");
    let forced_flow = u.required_flow.clone().unwrap_or_default();
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Username".into() name="username".into() required=true>
                <TextInput name="username".into() value=username.clone() read_only=true/>
            </Field>
            <Field label="Email".into() name="email".into()>
                <TextInput name="email".into() input_type="email".into() value=email/>
            </Field>
            <Toggle name="email_verified".into() label="Email verified".into() checked=u.email_verified/>
            <Field label="First name".into() name="first_name".into()>
                <TextInput name="first_name".into() value=first/>
            </Field>
            <Field label="Last name".into() name="last_name".into()>
                <TextInput name="last_name".into() value=last/>
            </Field>
            <Toggle name="enabled".into() label="Account enabled".into() checked=u.enabled/>
            <Field label="Required actions".into() name="required_actions".into()
                hint=Some("Comma-separated. E.g. update-password, verify-email, configure-otp.".into())>
                <TextInput name="required_actions".into() value=required_actions_csv/>
            </Field>
            <Field label="Forced flow".into() name="required_flow".into()
                hint=Some("Override the realm browser flow for this user on next login.".into())>
                <TextInput name="required_flow".into() value=forced_flow/>
            </Field>
            <ActionBar>
                <button type="submit" class="gn-btn gn-btn--primary">"Save user"</button>
            </ActionBar>
        </form>
    }
}

fn render_attributes(u: User) -> impl IntoView {
    if u.attributes.is_empty() {
        return view! {
            <EmptyState
                title="No custom attributes".into()
                description="Attach typed key-value attributes via the admin API or the CLI.".into()
            />
        }
        .into_any();
    }
    view! {
        <ListTable headers=vec!["Key", "Value", "Type"]>
            {u.attributes.iter().map(|(k, v)| {
                let (vstr, kind) = format_attribute(v);
                view! {
                    <tr>
                        <td data-label="Key"><code>{k.clone()}</code></td>
                        <td data-label="Value">{vstr}</td>
                        <td data-label="Type"><Badge label=kind.to_string() kind=BadgeKind::Info/></td>
                    </tr>
                }
            }).collect_view()}
        </ListTable>
    }.into_any()
}

fn format_attribute(v: &AttributeValue) -> (String, &'static str) {
    match v {
        AttributeValue::String(s) => (s.clone(), "string"),
        AttributeValue::Strings(l) => (l.join(", "), "list"),
        AttributeValue::Integer(n) => (n.to_string(), "integer"),
        AttributeValue::Float(n) => (n.to_string(), "float"),
        AttributeValue::Bool(b) => (b.to_string(), "bool"),
        AttributeValue::Null => ("—".into(), "null"),
    }
}

fn render_credentials(realm_slug: String, u: User) -> impl IntoView {
    let username = u.username.clone();
    let action = format!("/admin/realms/{realm_slug}/users/{username}/password");
    let creds_view = if u.credentials.is_empty() {
        view! {
            <EmptyState
                title="No registered credentials".into()
                description="Once the user sets a password or registers a security key it appears here.".into()
            />
        }.into_any()
    } else {
        view! {
            <ListTable headers=vec!["Type", "Label", "Created", "Last used"]>
                {u.credentials.iter().map(|c| view! {
                    <tr>
                        <td data-label="Type"><Badge label=credential_kind_label(c.kind) kind=BadgeKind::Accent/></td>
                        <td data-label="Label">{c.label.clone().unwrap_or_else(|| "—".into())}</td>
                        <td data-label="Created" class="gn-text-subtle">{c.created_at.to_rfc3339()}</td>
                        <td data-label="Last used" class="gn-text-subtle">
                            {c.last_used_at.map(|t| t.to_rfc3339()).unwrap_or_else(|| "never".into())}
                        </td>
                    </tr>
                }).collect_view()}
            </ListTable>
        }.into_any()
    };
    view! {
        <div class="gn-stack">
            <div class="gn-card">
                <div class="gn-card__title">"Set password"</div>
                <form method="post" action=action class="gn-form">
                    <Field label="New password".into() name="password".into() required=true>
                        <TextInput name="password".into() input_type="password".into()
                            autocomplete="new-password".into() required=true/>
                    </Field>
                    <Toggle name="temporary".into() label="Temporary (force change on next login)".into() checked=false/>
                    <ActionBar>
                        <button type="submit" class="gn-btn gn-btn--primary">"Set password"</button>
                    </ActionBar>
                </form>
            </div>
            <div>
                <h2>"Registered credentials"</h2>
                {creds_view}
            </div>
        </div>
    }
}

fn render_roles(roles: Vec<String>) -> impl IntoView {
    if roles.is_empty() {
        view! {
            <EmptyState
                title="No roles assigned".into()
                description="Assign realm or client roles to grant this user permissions.".into()
            />
        }
        .into_any()
    } else {
        view! {
            <ListTable headers=vec!["Role"]>
                {roles.iter().map(|r| view! {
                    <tr><td data-label="Role"><code>{r.clone()}</code></td></tr>
                }).collect_view()}
            </ListTable>
        }
        .into_any()
    }
}

fn render_groups(groups: Vec<String>) -> impl IntoView {
    if groups.is_empty() {
        view! {
            <EmptyState
                title="Not in any groups".into()
                description="Adding a user to a group inherits the group's role assignments.".into()
            />
        }
        .into_any()
    } else {
        view! {
            <ListTable headers=vec!["Group path"]>
                {groups.iter().map(|g| view! {
                    <tr><td data-label="Group"><code>{g.clone()}</code></td></tr>
                }).collect_view()}
            </ListTable>
        }
        .into_any()
    }
}

fn render_orgs(orgs: Vec<String>) -> impl IntoView {
    if orgs.is_empty() {
        view! {
            <EmptyState
                title="Not a member of any organization".into()
                description="Memberships appear once the user accepts an invitation or auto-joins a verified domain.".into()
            />
        }.into_any()
    } else {
        view! {
            <ListTable headers=vec!["Organization"]>
                {orgs.iter().map(|o| view! {
                    <tr><td data-label="Org"><code>{o.clone()}</code></td></tr>
                }).collect_view()}
            </ListTable>
        }
        .into_any()
    }
}

fn render_sessions(
    realm_slug: String,
    username: String,
    sessions: Vec<UserSessionRow>,
) -> impl IntoView {
    if sessions.is_empty() {
        return view! {
            <EmptyState
                title="No active sessions".into()
                description="The user is not signed in anywhere right now.".into()
            />
        }
        .into_any();
    }
    let realm = realm_slug.to_string();
    let user = username.to_string();
    view! {
        <ListTable headers=vec!["Session", "Started", "Last seen", "Clients", "Actions"]>
            {sessions.iter().map(|s| {
                let action = format!("/admin/realms/{realm}/users/{user}/sessions/{}/revoke", s.id);
                view! {
                    <tr>
                        <td data-label="Session"><code class="gn-truncate">{s.id.clone()}</code></td>
                        <td data-label="Started" class="gn-text-subtle">{s.started_at.clone()}</td>
                        <td data-label="Last seen" class="gn-text-subtle">{s.last_seen_at.clone()}</td>
                        <td data-label="Clients">{s.client_count.to_string()}</td>
                        <td data-label="Actions" class="gn-table__actions">
                            <form method="post" action=action style="display:inline" data-gn-confirm="Revoke this session?">
                                <button type="submit" class="gn-btn gn-btn--sm gn-btn--danger">"Revoke"</button>
                            </form>
                        </td>
                    </tr>
                }
            }).collect_view()}
        </ListTable>
    }.into_any()
}

fn render_consents() -> impl IntoView {
    view! {
        <EmptyState
            title="Consent grants land here".into()
            description="Per-client OAuth consent records — granted scopes and timestamp — appear once the user authorises a client.".into()
        />
    }
}

fn display_name(u: User) -> String {
    if let Some(name) = &u.name {
        let parts = [&name.given, &name.family]
            .iter()
            .filter_map(|s| (*s).clone())
            .collect::<Vec<_>>();
        if !parts.is_empty() {
            return parts.join(" ");
        }
    }
    u.username.clone()
}

fn credential_kind_label(k: CredentialKind) -> String {
    match k {
        CredentialKind::Password => "Password".into(),
        CredentialKind::Otp => "OTP".into(),
        CredentialKind::Webauthn => "WebAuthn".into(),
        CredentialKind::WebauthnPasswordless => "Passkey".into(),
        CredentialKind::RecoveryCode => "Recovery code".into(),
        CredentialKind::MagicLink => "Magic link".into(),
    }
}

fn required_action_value(a: &RequiredAction) -> String {
    match a {
        RequiredAction::UpdatePassword => "update-password".into(),
        RequiredAction::ConfigureOtp => "configure-otp".into(),
        RequiredAction::ConfigureWebauthn => "configure-webauthn".into(),
        RequiredAction::VerifyEmail => "verify-email".into(),
        RequiredAction::UpdateProfile => "update-profile".into(),
        RequiredAction::AcceptTerms => "accept-terms".into(),
        RequiredAction::DeleteAccount => "delete-account".into(),
        RequiredAction::Custom(s) => s.clone(),
    }
}
