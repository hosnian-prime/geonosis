//! `/admin/realms/{slug}/roles` — list, create, detail with composites.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::breadcrumb::Crumb;
use crate::leptos_ui::components::form::{ActionBar, Field, TextInput, Textarea};
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;
use crate::leptos_ui::components::tabs::{TabBar, TabItem};
use crate::leptos_ui::components::widgets::{
    Alert, AlertKind, Badge, BadgeKind, ButtonKind, EmptyState, LinkButton,
};

#[derive(Clone, Debug)]
pub struct RoleRow {
    pub name: String,
    pub description: Option<String>,
    pub client_scope: Option<String>,
    pub composite_count: usize,
}

#[component]
pub fn RolesPage(realm_slug: String, rows: Vec<RoleRow>, ctx: PageContext) -> impl IntoView {
    let ctx = ctx
        .with_title("Roles")
        .with_section("roles")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::current("Roles"),
        ]);
    let create_href = format!("/admin/realms/{realm_slug}/roles/new");
    let is_empty = rows.is_empty();
    view! {
        <Page context=ctx>
            <PageHeader
                title="Roles".into()
                subtitle=Some("Realm and client roles assigned to users, groups and agents.".into())
                actions=Some(view! {
                    <LinkButton href=create_href.clone() label="+ Create role".to_string() kind=ButtonKind::Primary/>
                }.into_any())
            />
            {if is_empty {
                view! {
                    <EmptyState
                        title="No roles defined".into()
                        description="Realm roles apply globally; client roles scope to one client.".into()
                    />
                }.into_any()
            } else {
                view! {
                    <ListTable headers=vec!["Name", "Description", "Scope", "Composites"]>
                        {rows.into_iter().map(|r| {
                            let href = format!("/admin/realms/{realm_slug}/roles/{}", r.name);
                            let scope = match r.client_scope {
                                Some(c) => view! { <Badge label=format!("client:{c}") kind=BadgeKind::Accent/> }.into_any(),
                                None => view! { <Badge label="realm".into() kind=BadgeKind::Info/> }.into_any(),
                            };
                            view! {
                                <tr>
                                    <td data-label="Name"><a href=href.clone()><code>{r.name}</code></a></td>
                                    <td data-label="Description">{r.description.unwrap_or_else(|| "—".into())}</td>
                                    <td data-label="Scope">{scope}</td>
                                    <td data-label="Composites">{r.composite_count.to_string()}</td>
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
pub fn RoleCreatePage(
    realm_slug: String,
    ctx: PageContext,
    #[prop(default = None)] error: Option<String>,
) -> impl IntoView {
    let ctx = ctx
        .with_title("Create role")
        .with_section("roles")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::link("Roles", format!("/admin/realms/{realm_slug}/roles")),
            Crumb::current("Create"),
        ]);
    let action = format!("/admin/realms/{realm_slug}/roles");
    let cancel = format!("/admin/realms/{realm_slug}/roles");
    view! {
        <Page context=ctx>
            <PageHeader title="Create role".into()/>
            {error.map(|e| view! { <Alert message=e kind=AlertKind::Danger/> })}
            <form method="post" action=action class="gn-form">
                <Field label="Name".into() name="name".into() required=true>
                    <TextInput name="name".into() required=true placeholder="reader".into()/>
                </Field>
                <Field label="Description".into() name="description".into()>
                    <Textarea name="description".into() rows=3/>
                </Field>
                <Field label="Client (optional)".into() name="client_id".into()
                    hint=Some("Leave blank for a realm role; supply a client ID to scope to that client.".into())>
                    <TextInput name="client_id".into() placeholder="my-app".into()/>
                </Field>
                <ActionBar>
                    <LinkButton href=cancel label="Cancel".to_string()/>
                    <button type="submit" class="gn-btn gn-btn--primary">"Create role"</button>
                </ActionBar>
            </form>
        </Page>
    }
}

pub const ROLE_TABS: &[(&str, &str)] = &[
    ("general", "General"),
    ("composites", "Composites"),
    ("users", "Assigned users"),
    ("groups", "Assigned groups"),
];

#[derive(Clone, Debug)]
pub struct RoleDetailData {
    pub name: String,
    pub description: Option<String>,
    pub client_scope: Option<String>,
    pub composites_realm: Vec<String>,
    pub composites_client: Vec<(String, Vec<String>)>,
    pub assigned_users: Vec<String>,
    pub assigned_groups: Vec<String>,
}

#[component]
pub fn RoleDetailPage(
    realm_slug: String,
    data: RoleDetailData,
    active_tab: String,
    ctx: PageContext,
) -> impl IntoView {
    let name = data.name.clone();
    let ctx = ctx
        .with_title(format!("Role · {name}"))
        .with_section("roles")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::link("Roles", format!("/admin/realms/{realm_slug}/roles")),
            Crumb::current(name.clone()),
        ]);
    let tab_items = ROLE_TABS
        .iter()
        .map(|(k, l)| TabItem::new(*k, *l, format!("/admin/realms/{realm_slug}/roles/{name}?tab={k}")))
        .collect::<Vec<_>>();
    let panel = match active_tab.as_str() {
        "general" => render_general(realm_slug.clone(), data.clone()).into_any(),
        "composites" => render_composites(data.clone()).into_any(),
        "users" => render_users(data.assigned_users.clone()).into_any(),
        "groups" => render_groups(data.assigned_groups.clone()).into_any(),
        _ => view! { <Alert message="Unknown tab.".into() kind=AlertKind::Warning/> }.into_any(),
    };
    let scope_badge = match &data.client_scope {
        Some(c) => format!("client:{c}"),
        None => "realm".into(),
    };
    view! {
        <Page context=ctx>
            <PageHeader
                title=name.clone()
                subtitle=Some(format!("Scope: {scope_badge}"))
            />
            <TabBar active=active_tab.clone() items=tab_items/>
            {panel}
        </Page>
    }
}

fn render_general(realm_slug: String, d: RoleDetailData) -> impl IntoView {
    let action = format!("/admin/realms/{realm_slug}/roles/{}/general", d.name);
    let desc = d.description.clone().unwrap_or_default();
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Name".into() name="name".into() required=true>
                <TextInput name="name".into() value=d.name.clone() read_only=true/>
            </Field>
            <Field label="Description".into() name="description".into()>
                <Textarea name="description".into() value=desc rows=3/>
            </Field>
            <ActionBar>
                <button type="submit" class="gn-btn gn-btn--primary">"Save"</button>
            </ActionBar>
        </form>
    }
}

fn render_composites(d: RoleDetailData) -> impl IntoView {
    let realm_section = if d.composites_realm.is_empty() {
        view! { <p class="gn-text-muted">"None."</p> }.into_any()
    } else {
        view! {
            <ListTable headers=vec!["Role"]>
                {d.composites_realm.iter().map(|r| view! {
                    <tr><td data-label="Role"><code>{r.clone()}</code></td></tr>
                }).collect_view()}
            </ListTable>
        }.into_any()
    };
    let client_section = if d.composites_client.is_empty() {
        view! { <p class="gn-text-muted">"None."</p> }.into_any()
    } else {
        view! {
            <ListTable headers=vec!["Client", "Roles"]>
                {d.composites_client.iter().map(|(client, roles)| view! {
                    <tr>
                        <td data-label="Client"><code>{client.clone()}</code></td>
                        <td data-label="Roles">{roles.join(", ")}</td>
                    </tr>
                }).collect_view()}
            </ListTable>
        }.into_any()
    };
    view! {
        <div class="gn-stack">
            <div>
                <h2>"Included realm roles"</h2>
                {realm_section}
            </div>
            <div>
                <h2>"Included client roles"</h2>
                {client_section}
            </div>
        </div>
    }
}

fn render_users(users: Vec<String>) -> impl IntoView {
    if users.is_empty() {
        view! {
            <EmptyState title="No users assigned".into()
                description="Users gain this role through direct assignment, group membership, or composites.".into()/>
        }.into_any()
    } else {
        view! {
            <ListTable headers=vec!["User"]>
                {users.iter().map(|u| view! {
                    <tr><td data-label="User"><code>{u.clone()}</code></td></tr>
                }).collect_view()}
            </ListTable>
        }.into_any()
    }
}

fn render_groups(groups: Vec<String>) -> impl IntoView {
    if groups.is_empty() {
        view! {
            <EmptyState title="No groups assigned".into()
                description="Group assignments grant this role to all current and future members.".into()/>
        }.into_any()
    } else {
        view! {
            <ListTable headers=vec!["Group"]>
                {groups.iter().map(|g| view! {
                    <tr><td data-label="Group"><code>{g.clone()}</code></td></tr>
                }).collect_view()}
            </ListTable>
        }.into_any()
    }
}
