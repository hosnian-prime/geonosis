//! `/admin/realms/{slug}/orgs` — list, create, detail with 8 tabs.

use leptos::prelude::*;

use geonosis_core::organization::{
    MembershipState, OrgConsentMode, OrgPermission, Organization, OrganizationBranding,
};

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::breadcrumb::Crumb;
use crate::leptos_ui::components::form::{ActionBar, Field, TextInput, Textarea, Toggle};
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;
use crate::leptos_ui::components::tabs::{TabBar, TabItem};
use crate::leptos_ui::components::widgets::{
    Alert, AlertKind, Badge, BadgeKind, ButtonKind, EmptyState, LinkButton, StateBadge,
};

#[derive(Clone, Debug)]
pub struct OrgRow {
    pub alias: String,
    pub display_name: String,
    pub default_idp_alias: Option<String>,
    pub enabled: bool,
}

#[component]
pub fn OrgsPage(realm_slug: String, rows: Vec<OrgRow>, ctx: PageContext) -> impl IntoView {
    let ctx = ctx
        .with_title("Organizations")
        .with_section("orgs")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::current("Organizations"),
        ]);
    let create_href = format!("/admin/realms/{realm_slug}/orgs/new");
    let is_empty = rows.is_empty();
    view! {
        <Page context=ctx>
            <PageHeader
                title="Organizations".into()
                subtitle=Some("B2B sub-tenants — invitations, domains, per-org IdPs.".into())
                actions=Some(view! {
                    <LinkButton href=create_href.clone() label="+ Create organization".to_string() kind=ButtonKind::Primary/>
                }.into_any())
            />
            {if is_empty {
                view! {
                    <EmptyState title="No organizations".into()
                        description="Enable Organizations on the realm settings page first.".into()/>
                }.into_any()
            } else {
                view! {
                    <ListTable headers=vec!["Alias", "Display name", "Default IdP", "State"]>
                        {rows.into_iter().map(|r| {
                            let href = format!("/admin/realms/{realm_slug}/orgs/{}", r.alias);
                            view! {
                                <tr>
                                    <td data-label="Alias"><a href=href.clone()><code>{r.alias}</code></a></td>
                                    <td data-label="Display name">{r.display_name}</td>
                                    <td data-label="Default IdP">{r.default_idp_alias.unwrap_or_else(|| "—".into())}</td>
                                    <td data-label="State"><StateBadge enabled=r.enabled/></td>
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
pub fn OrgCreatePage(
    realm_slug: String,
    ctx: PageContext,
    #[prop(default = None)] error: Option<String>,
) -> impl IntoView {
    let ctx = ctx
        .with_title("Create organization")
        .with_section("orgs")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::link("Organizations", format!("/admin/realms/{realm_slug}/orgs")),
            Crumb::current("Create"),
        ]);
    let action = format!("/admin/realms/{realm_slug}/orgs");
    let cancel = format!("/admin/realms/{realm_slug}/orgs");
    view! {
        <Page context=ctx>
            <PageHeader title="Create organization".into()/>
            {error.map(|e| view! { <Alert message=e kind=AlertKind::Danger/> })}
            <form method="post" action=action class="gn-form">
                <Field label="Alias".into() name="alias".into() required=true>
                    <TextInput name="alias".into() required=true placeholder="acme-eu".into()/>
                </Field>
                <Field label="Display name".into() name="display_name".into() required=true>
                    <TextInput name="display_name".into() required=true placeholder="Acme Europe".into()/>
                </Field>
                <Field label="Description".into() name="description".into()>
                    <Textarea name="description".into() rows=3/>
                </Field>
                <Toggle name="enabled".into() label="Enabled".into() checked=true/>
                <ActionBar>
                    <LinkButton href=cancel label="Cancel".to_string()/>
                    <button type="submit" class="gn-btn gn-btn--primary">"Create organization"</button>
                </ActionBar>
            </form>
        </Page>
    }
}

pub const ORG_TABS: &[(&str, &str)] = &[
    ("general", "General"),
    ("branding", "Branding"),
    ("domains", "Domains"),
    ("members", "Members"),
    ("invitations", "Invitations"),
    ("roles", "Roles"),
    ("idps", "IdP bindings"),
    ("consent", "Consent policies"),
];

#[derive(Clone, Debug)]
pub struct OrgDetailData {
    pub org: Organization,
    pub domains: Vec<OrgDomainRow>,
    pub members: Vec<OrgMemberRow>,
    pub invitations: Vec<OrgInviteRow>,
    pub roles: Vec<OrgRoleRow>,
    pub idp_bindings: Vec<OrgIdpRow>,
    pub consent_policies: Vec<OrgConsentRow>,
}

#[derive(Clone, Debug)]
pub struct OrgDomainRow {
    pub domain: String,
    pub verified: bool,
    pub verified_at: Option<String>,
}

#[derive(Clone, Debug)]
pub struct OrgMemberRow {
    pub user_id: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub state: MembershipState,
    pub roles: Vec<String>,
    pub joined_at: String,
}

#[derive(Clone, Debug)]
pub struct OrgInviteRow {
    pub email: String,
    pub roles: Vec<String>,
    pub expires_at: String,
    pub accepted: bool,
}

#[derive(Clone, Debug)]
pub struct OrgRoleRow {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<OrgPermission>,
    pub built_in: bool,
}

#[derive(Clone, Debug)]
pub struct OrgIdpRow {
    pub idp_alias: String,
    pub priority: i32,
}

#[derive(Clone, Debug)]
pub struct OrgConsentRow {
    pub client_id: String,
    pub mode: OrgConsentMode,
    pub pre_approved: Vec<String>,
    pub blocked: Vec<String>,
}

#[component]
pub fn OrgDetailPage(
    realm_slug: String,
    data: OrgDetailData,
    active_tab: String,
    ctx: PageContext,
) -> impl IntoView {
    let alias = data.org.alias.clone();
    let display = data.org.display_name.clone();
    let ctx = ctx
        .with_title(format!("Org · {display}"))
        .with_section("orgs")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::link("Organizations", format!("/admin/realms/{realm_slug}/orgs")),
            Crumb::current(display.clone()),
        ]);
    let tab_items = ORG_TABS
        .iter()
        .map(|(k, l)| TabItem::new(*k, *l, format!("/admin/realms/{realm_slug}/orgs/{alias}?tab={k}")))
        .collect::<Vec<_>>();
    let panel = match active_tab.as_str() {
        "general" => render_general(realm_slug.clone(), data.org.clone()).into_any(),
        "branding" => render_branding(realm_slug.clone(), data.org.clone()).into_any(),
        "domains" => render_domains(realm_slug.clone(), alias.clone(), data.domains.clone()).into_any(),
        "members" => render_members(data.members.clone()).into_any(),
        "invitations" => render_invitations(realm_slug.clone(), alias.clone(), data.invitations.clone()).into_any(),
        "roles" => render_org_roles(data.roles.clone()).into_any(),
        "idps" => render_idps(data.idp_bindings.clone()).into_any(),
        "consent" => render_consent(data.consent_policies.clone()).into_any(),
        _ => view! { <Alert message="Unknown tab.".into() kind=AlertKind::Warning/> }.into_any(),
    };
    view! {
        <Page context=ctx>
            <PageHeader title=display subtitle=Some(format!("Alias: {alias}"))/>
            <TabBar active=active_tab.clone() items=tab_items/>
            {panel}
        </Page>
    }
}

fn render_general(realm_slug: String, o: Organization) -> impl IntoView {
    let action = format!("/admin/realms/{realm_slug}/orgs/{}/general", o.alias);
    let desc = o.description.clone().unwrap_or_default();
    let default_idp = o.default_idp_alias.clone().unwrap_or_default();
    let redirect = o.redirect_url.as_ref().map(|u| u.to_string()).unwrap_or_default();
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Alias".into() name="alias".into()>
                <TextInput name="alias".into() value=o.alias.clone() read_only=true/>
            </Field>
            <Field label="Display name".into() name="display_name".into() required=true>
                <TextInput name="display_name".into() value=o.display_name.clone() required=true/>
            </Field>
            <Field label="Description".into() name="description".into()>
                <Textarea name="description".into() value=desc rows=3/>
            </Field>
            <Field label="Default IdP alias".into() name="default_idp_alias".into()>
                <TextInput name="default_idp_alias".into() value=default_idp/>
            </Field>
            <Field label="Redirect URL".into() name="redirect_url".into()>
                <TextInput name="redirect_url".into() input_type="url".into() value=redirect/>
            </Field>
            <Toggle name="enabled".into() label="Enabled".into() checked=o.enabled/>
            <ActionBar>
                <button type="submit" class="gn-btn gn-btn--primary">"Save"</button>
            </ActionBar>
        </form>
    }
}

fn render_branding(realm_slug: String, o: Organization) -> impl IntoView {
    let action = format!("/admin/realms/{realm_slug}/orgs/{}/branding", o.alias);
    let b: &OrganizationBranding = &o.branding;
    let logo = b.logo_url.as_ref().map(|u| u.to_string()).unwrap_or_default();
    let color = b.primary_color.clone().unwrap_or_default();
    let theme = b.theme.clone().unwrap_or_default();
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Logo URL".into() name="logo_url".into()>
                <TextInput name="logo_url".into() input_type="url".into() value=logo/>
            </Field>
            <Field label="Primary color".into() name="primary_color".into()
                hint=Some("Hex value, e.g. #2563eb".into())>
                <TextInput name="primary_color".into() value=color placeholder="#2563eb".into()/>
            </Field>
            <Field label="Theme".into() name="theme".into()>
                <TextInput name="theme".into() value=theme/>
            </Field>
            <ActionBar>
                <button type="submit" class="gn-btn gn-btn--primary">"Save branding"</button>
            </ActionBar>
        </form>
    }
}

fn render_domains(realm_slug: String, alias: String, rows: Vec<OrgDomainRow>) -> impl IntoView {
    let add_action = format!("/admin/realms/{realm_slug}/orgs/{alias}/domains");
    let table = if rows.is_empty() {
        view! {
            <EmptyState title="No domains".into()
                description="Add a domain to enable email-based auto-join.".into()/>
        }.into_any()
    } else {
        let realm = realm_slug.to_string();
        let alias_owned = alias.to_string();
        view! {
            <ListTable headers=vec!["Domain", "Verified", "Verified at", "Actions"]>
                {rows.iter().map(|d| {
                    let verify = format!("/admin/realms/{realm}/orgs/{alias_owned}/domains/{}/verify", d.domain);
                    let remove = format!("/admin/realms/{realm}/orgs/{alias_owned}/domains/{}/remove", d.domain);
                    let verified_badge = if d.verified {
                        view! { <Badge label="verified".into() kind=BadgeKind::Success dot=true/> }.into_any()
                    } else {
                        view! { <Badge label="pending".into() kind=BadgeKind::Warning dot=true/> }.into_any()
                    };
                    view! {
                        <tr>
                            <td data-label="Domain"><code>{d.domain.clone()}</code></td>
                            <td data-label="Verified">{verified_badge}</td>
                            <td data-label="Verified at">{d.verified_at.clone().unwrap_or_else(|| "—".into())}</td>
                            <td data-label="Actions" class="gn-table__actions">
                                <form method="post" action=verify style="display:inline">
                                    <button class="gn-btn gn-btn--sm" type="submit">"Verify"</button>
                                </form>
                                " "
                                <form method="post" action=remove style="display:inline" data-gn-confirm="Remove this domain?">
                                    <button class="gn-btn gn-btn--sm gn-btn--danger" type="submit">"Remove"</button>
                                </form>
                            </td>
                        </tr>
                    }
                }).collect_view()}
            </ListTable>
        }.into_any()
    };
    view! {
        <div class="gn-stack">
            <div class="gn-card">
                <div class="gn-card__title">"Add domain"</div>
                <form method="post" action=add_action class="gn-form">
                    <Field label="Domain".into() name="domain".into() required=true>
                        <TextInput name="domain".into() required=true placeholder="example.com".into()/>
                    </Field>
                    <ActionBar>
                        <button type="submit" class="gn-btn gn-btn--primary">"Add"</button>
                    </ActionBar>
                </form>
            </div>
            {table}
        </div>
    }
}

fn render_members(rows: Vec<OrgMemberRow>) -> impl IntoView {
    if rows.is_empty() {
        view! {
            <EmptyState title="No members yet".into()
                description="Invite members from the Invitations tab.".into()/>
        }.into_any()
    } else {
        view! {
            <ListTable headers=vec!["User", "Email", "Roles", "State", "Joined"]>
                {rows.iter().map(|m| {
                    let state_badge = match m.state {
                        MembershipState::Active => view! { <Badge label="Active".into() kind=BadgeKind::Success/> }.into_any(),
                        MembershipState::Invited => view! { <Badge label="Invited".into() kind=BadgeKind::Warning/> }.into_any(),
                        MembershipState::Suspended => view! { <Badge label="Suspended".into() kind=BadgeKind::Danger/> }.into_any(),
                    };
                    view! {
                        <tr>
                            <td data-label="User">{m.username.clone().unwrap_or_else(|| m.user_id.clone())}</td>
                            <td data-label="Email">{m.email.clone().unwrap_or_else(|| "—".into())}</td>
                            <td data-label="Roles">{m.roles.join(", ")}</td>
                            <td data-label="State">{state_badge}</td>
                            <td data-label="Joined" class="gn-text-subtle">{m.joined_at.clone()}</td>
                        </tr>
                    }
                }).collect_view()}
            </ListTable>
        }.into_any()
    }
}

fn render_invitations(realm_slug: String, alias: String, rows: Vec<OrgInviteRow>) -> impl IntoView {
    let action = format!("/admin/realms/{realm_slug}/orgs/{alias}/invitations");
    let table = if rows.is_empty() {
        view! {
            <EmptyState title="No invitations sent".into()
                description="Invite a member by email to onboard them into this organization.".into()/>
        }.into_any()
    } else {
        view! {
            <ListTable headers=vec!["Email", "Roles", "Expires", "Status"]>
                {rows.iter().map(|i| {
                    let badge = if i.accepted {
                        view! { <Badge label="Accepted".into() kind=BadgeKind::Success/> }.into_any()
                    } else {
                        view! { <Badge label="Pending".into() kind=BadgeKind::Warning/> }.into_any()
                    };
                    view! {
                        <tr>
                            <td data-label="Email">{i.email.clone()}</td>
                            <td data-label="Roles">{i.roles.join(", ")}</td>
                            <td data-label="Expires" class="gn-text-subtle">{i.expires_at.clone()}</td>
                            <td data-label="Status">{badge}</td>
                        </tr>
                    }
                }).collect_view()}
            </ListTable>
        }.into_any()
    };
    view! {
        <div class="gn-stack">
            <div class="gn-card">
                <div class="gn-card__title">"Invite a member"</div>
                <form method="post" action=action class="gn-form">
                    <Field label="Email".into() name="email".into() required=true>
                        <TextInput name="email".into() input_type="email".into() required=true/>
                    </Field>
                    <Field label="Roles".into() name="roles".into()
                        hint=Some("Comma-separated org-role names. Defaults to the realm's self-signup role.".into())>
                        <TextInput name="roles".into() placeholder="member".into()/>
                    </Field>
                    <ActionBar>
                        <button type="submit" class="gn-btn gn-btn--primary">"Send invitation"</button>
                    </ActionBar>
                </form>
            </div>
            {table}
        </div>
    }
}

fn render_org_roles(rows: Vec<OrgRoleRow>) -> impl IntoView {
    if rows.is_empty() {
        view! {
            <EmptyState title="No org roles".into()
                description="Define org roles to delegate permissions inside this organization.".into()/>
        }.into_any()
    } else {
        view! {
            <ListTable headers=vec!["Name", "Description", "Permissions", "Built-in"]>
                {rows.iter().map(|r| {
                    let perms = r.permissions.iter().map(|p| permission_label(p)).collect::<Vec<_>>().join(", ");
                    let badge = if r.built_in {
                        view! { <Badge label="built-in".into() kind=BadgeKind::Info/> }.into_any()
                    } else {
                        view! { <Badge label="custom".into() kind=BadgeKind::Accent/> }.into_any()
                    };
                    view! {
                        <tr>
                            <td data-label="Name"><code>{r.name.clone()}</code></td>
                            <td data-label="Description">{r.description.clone().unwrap_or_else(|| "—".into())}</td>
                            <td data-label="Permissions">{perms}</td>
                            <td data-label="Built-in">{badge}</td>
                        </tr>
                    }
                }).collect_view()}
            </ListTable>
        }.into_any()
    }
}

fn render_idps(rows: Vec<OrgIdpRow>) -> impl IntoView {
    if rows.is_empty() {
        view! {
            <EmptyState title="No IdP bindings".into()
                description="Bind a realm IdP to this organization to scope SSO entry points.".into()/>
        }.into_any()
    } else {
        view! {
            <ListTable headers=vec!["IdP alias", "Priority"]>
                {rows.iter().map(|r| view! {
                    <tr>
                        <td data-label="Alias"><code>{r.idp_alias.clone()}</code></td>
                        <td data-label="Priority">{r.priority.to_string()}</td>
                    </tr>
                }).collect_view()}
            </ListTable>
        }.into_any()
    }
}

fn render_consent(rows: Vec<OrgConsentRow>) -> impl IntoView {
    if rows.is_empty() {
        view! {
            <EmptyState title="No consent policies".into()
                description="Per-client policies override the realm consent rules for this organization.".into()/>
        }.into_any()
    } else {
        view! {
            <ListTable headers=vec!["Client", "Mode", "Pre-approved", "Blocked"]>
                {rows.iter().map(|p| {
                    let mode = match p.mode {
                        OrgConsentMode::UserDecides => "User decides",
                        OrgConsentMode::OrgPreApproved => "Org pre-approved",
                        OrgConsentMode::OrgManaged => "Org managed",
                    };
                    view! {
                        <tr>
                            <td data-label="Client"><code>{p.client_id.clone()}</code></td>
                            <td data-label="Mode"><Badge label=mode.into() kind=BadgeKind::Info/></td>
                            <td data-label="Pre-approved">{p.pre_approved.join(", ")}</td>
                            <td data-label="Blocked">{p.blocked.join(", ")}</td>
                        </tr>
                    }
                }).collect_view()}
            </ListTable>
        }.into_any()
    }
}

fn permission_label(p: &OrgPermission) -> String {
    match p {
        OrgPermission::Admin => "admin".into(),
        OrgPermission::InviteMembers => "invite-members".into(),
        OrgPermission::ManageDomains => "manage-domains".into(),
        OrgPermission::ManageIdps => "manage-idps".into(),
        OrgPermission::ManageRoles => "manage-roles".into(),
        OrgPermission::ManageConsent => "manage-consent".into(),
        OrgPermission::ViewMembers => "view-members".into(),
        OrgPermission::Custom(s) => s.clone(),
    }
}
