//! `/admin-next/realms/:slug/roles` — list realm roles.
//!
//! v0.1 ships realm-scope roles only. Client-scope role filtering
//! (per `Role.client_id`) lands in v0.1.x with the role-detail page.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;

#[derive(Clone, Debug)]
pub struct RoleRow {
    pub name: String,
    pub description: Option<String>,
    pub client_scope: Option<String>,
}

#[component]
pub fn RolesPage(realm_slug: String, rows: Vec<RoleRow>) -> impl IntoView {
    let ctx = PageContext {
        title: "Roles".into(),
        active_section: "roles",
    };
    let back = format!("/admin-next/realms/{realm_slug}");
    view! {
        <Page context=ctx>
            <PageHeader
                title="Roles"
                back_href=back
                subtitle="Realm + client-scoped roles. Composite roles + role attributes drive token claims."
            />
            <ListTable headers=vec!["Name", "Description", "Scope"]>
                {rows.into_iter().map(|r| view! {
                    <tr>
                        <td><code>{r.name}</code></td>
                        <td>{r.description.unwrap_or_default()}</td>
                        <td>{r.client_scope.unwrap_or_else(|| "realm".into())}</td>
                    </tr>
                }).collect_view()}
            </ListTable>
        </Page>
    }
}
