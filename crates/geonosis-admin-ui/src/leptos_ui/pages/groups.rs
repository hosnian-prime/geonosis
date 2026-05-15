//! `/admin/realms/{slug}/groups` — list, create, detail.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::breadcrumb::Crumb;
use crate::leptos_ui::components::form::{ActionBar, Field, TextInput};
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;
use crate::leptos_ui::components::tabs::{TabBar, TabItem};
use crate::leptos_ui::components::widgets::{Alert, AlertKind, ButtonKind, EmptyState, LinkButton};

#[derive(Clone, Debug)]
pub struct GroupRow {
    pub id: String,
    pub path: String,
    pub name: String,
    pub realm_role_count: usize,
    pub member_count: usize,
}

#[component]
pub fn GroupsPage(realm_slug: String, rows: Vec<GroupRow>, ctx: PageContext) -> impl IntoView {
    let ctx = ctx
        .with_title("Groups")
        .with_section("groups")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::current("Groups"),
        ]);
    let create_href = format!("/admin/realms/{realm_slug}/groups/new");
    let is_empty = rows.is_empty();
    view! {
        <Page context=ctx>
            <PageHeader
                title="Groups".into()
                subtitle=Some("Hierarchical, slash-delimited paths. Roles propagate through membership.".into())
                actions=Some(view! {
                    <LinkButton href=create_href.clone() label="+ Create group".to_string() kind=ButtonKind::Primary/>
                }.into_any())
            />
            {if is_empty {
                view! {
                    <EmptyState
                        title="No groups defined".into()
                        description="Use the path field to nest: /engineering/backend.".into()
                    />
                }.into_any()
            } else {
                view! {
                    <ListTable headers=vec!["Path", "Name", "Members", "Realm roles"]>
                        {rows.into_iter().map(|r| {
                            let href = format!("/admin/realms/{realm_slug}/groups/{}", r.id);
                            view! {
                                <tr>
                                    <td data-label="Path"><a href=href.clone()><code>{r.path}</code></a></td>
                                    <td data-label="Name">{r.name}</td>
                                    <td data-label="Members">{r.member_count.to_string()}</td>
                                    <td data-label="Realm roles">{r.realm_role_count.to_string()}</td>
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
pub fn GroupCreatePage(
    realm_slug: String,
    ctx: PageContext,
    #[prop(default = None)] error: Option<String>,
) -> impl IntoView {
    let ctx = ctx
        .with_title("Create group")
        .with_section("groups")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::link("Groups", format!("/admin/realms/{realm_slug}/groups")),
            Crumb::current("Create"),
        ]);
    let action = format!("/admin/realms/{realm_slug}/groups");
    let cancel = format!("/admin/realms/{realm_slug}/groups");
    view! {
        <Page context=ctx>
            <PageHeader title="Create group".into()/>
            {error.map(|e| view! { <Alert message=e kind=AlertKind::Danger/> })}
            <form method="post" action=action class="gn-form">
                <Field label="Name".into() name="name".into() required=true>
                    <TextInput name="name".into() required=true placeholder="backend".into()/>
                </Field>
                <Field label="Parent group ID (optional)".into() name="parent_id".into()
                    hint=Some("Leave blank to create at the root.".into())>
                    <TextInput name="parent_id".into()/>
                </Field>
                <ActionBar>
                    <LinkButton href=cancel label="Cancel".to_string()/>
                    <button type="submit" class="gn-btn gn-btn--primary">"Create group"</button>
                </ActionBar>
            </form>
        </Page>
    }
}

pub const GROUP_TABS: &[(&str, &str)] = &[
    ("general", "General"),
    ("attributes", "Attributes"),
    ("roles", "Roles"),
    ("members", "Members"),
];

#[derive(Clone, Debug)]
pub struct GroupDetailData {
    pub id: String,
    pub name: String,
    pub path: String,
    pub realm_role_count: usize,
    pub member_count: usize,
    pub members: Vec<String>,
    pub realm_roles: Vec<String>,
}

#[component]
pub fn GroupDetailPage(
    realm_slug: String,
    data: GroupDetailData,
    active_tab: String,
    ctx: PageContext,
) -> impl IntoView {
    let id = data.id.clone();
    let name = data.name.clone();
    let path = data.path.clone();
    let ctx = ctx
        .with_title(format!("Group · {name}"))
        .with_section("groups")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::link("Groups", format!("/admin/realms/{realm_slug}/groups")),
            Crumb::current(name.clone()),
        ]);
    let tab_items = GROUP_TABS
        .iter()
        .map(|(k, l)| {
            TabItem::new(
                *k,
                *l,
                format!("/admin/realms/{realm_slug}/groups/{id}?tab={k}"),
            )
        })
        .collect::<Vec<_>>();
    let panel = match active_tab.as_str() {
        "general" => render_general(realm_slug.clone(), data.clone()).into_any(),
        "attributes" => view! {
            <EmptyState title="No attributes".into()
                description="Attach key-value attributes via the admin API.".into()/>
        }
        .into_any(),
        "roles" => render_roles(data.realm_roles.clone()).into_any(),
        "members" => render_members(data.members.clone()).into_any(),
        _ => view! { <Alert message="Unknown tab.".into() kind=AlertKind::Warning/> }.into_any(),
    };
    view! {
        <Page context=ctx>
            <PageHeader title=name subtitle=Some(format!("Path: {path}"))/>
            <TabBar active=active_tab.clone() items=tab_items/>
            {panel}
        </Page>
    }
}

fn render_general(realm_slug: String, d: GroupDetailData) -> impl IntoView {
    let action = format!("/admin/realms/{realm_slug}/groups/{}/general", d.id);
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Name".into() name="name".into() required=true>
                <TextInput name="name".into() value=d.name.clone() required=true/>
            </Field>
            <Field label="Path".into() name="path".into()>
                <TextInput name="path".into() value=d.path.clone() read_only=true/>
            </Field>
            <ActionBar>
                <button type="submit" class="gn-btn gn-btn--primary">"Save"</button>
            </ActionBar>
        </form>
    }
}

fn render_roles(roles: Vec<String>) -> impl IntoView {
    if roles.is_empty() {
        view! {
            <EmptyState title="No roles assigned".into()
                description="Assign roles to apply them to all current and future members.".into()/>
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

fn render_members(members: Vec<String>) -> impl IntoView {
    if members.is_empty() {
        view! {
            <EmptyState title="No members".into()
                description="Add users to this group from the user detail page.".into()/>
        }
        .into_any()
    } else {
        view! {
            <ListTable headers=vec!["User"]>
                {members.iter().map(|m| view! {
                    <tr><td data-label="User"><code>{m.clone()}</code></td></tr>
                }).collect_view()}
            </ListTable>
        }
        .into_any()
    }
}
