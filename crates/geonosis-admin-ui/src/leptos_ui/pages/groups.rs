//! `/admin-next/realms/:slug/groups` — list realm groups.
//!
//! Groups are hierarchical (slash-delimited `path` per docs/02). The
//! tree view + drag-to-reparent UI lands in v0.1.x; v0.1 ships the
//! flat list.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;

#[derive(Clone, Debug)]
pub struct GroupRow {
    pub path: String,
    pub name: String,
    pub realm_role_count: usize,
}

#[component]
pub fn GroupsPage(realm_slug: String, rows: Vec<GroupRow>) -> impl IntoView {
    let ctx = PageContext {
        title: "Groups".into(),
        active_section: "groups",
    };
    let back = format!("/admin-next/realms/{realm_slug}");
    view! {
        <Page context=ctx>
            <PageHeader
                title="Groups"
                back_href=back
                subtitle="Hierarchical, slash-delimited paths. Composite roles propagate through group membership."
            />
            <ListTable headers=vec!["Path", "Name", "Realm roles"]>
                {rows.into_iter().map(|r| view! {
                    <tr>
                        <td><code>{r.path}</code></td>
                        <td>{r.name}</td>
                        <td>{r.realm_role_count.to_string()}</td>
                    </tr>
                }).collect_view()}
            </ListTable>
        </Page>
    }
}
