//! `/admin-next/realms/:slug/users` — list users.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::list_table::{state_label, ListTable};
use crate::leptos_ui::components::page_header::PageHeader;

#[derive(Clone, Debug)]
pub struct UserRow {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub enabled: bool,
}

#[component]
pub fn UsersPage(realm_slug: String, rows: Vec<UserRow>) -> impl IntoView {
    let ctx = PageContext {
        title: "Users".into(),
        active_section: "users",
        realm_slug: Some(realm_slug.clone()),
    };
    let back = format!("/admin-next/realms/{realm_slug}");
    view! {
        <Page context=ctx>
            <PageHeader title="Users" back_href=back/>
            <ListTable headers=vec!["Username", "Email", "State"]>
                {rows.into_iter().map(|r| view! {
                    <tr>
                        <td>{r.username}</td>
                        <td>{r.email.unwrap_or_default()}</td>
                        <td>{state_label(r.enabled)}</td>
                    </tr>
                }).collect_view()}
            </ListTable>
        </Page>
    }
}
