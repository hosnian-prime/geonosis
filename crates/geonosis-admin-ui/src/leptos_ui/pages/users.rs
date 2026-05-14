//! `/admin-next/realms/:slug/users` — list users.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};

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
    };
    let back = format!("/admin-next/realms/{realm_slug}");
    view! {
        <Page context=ctx>
            <nav class="gn-breadcrumb"><a href=back>"← Realm"</a></nav>
            <h1>"Users"</h1>
            <table class="gn-table">
                <thead>
                    <tr><th>"Username"</th><th>"Email"</th><th>"State"</th></tr>
                </thead>
                <tbody>
                    {rows.into_iter().map(|r| view! {
                        <tr>
                            <td>{r.username}</td>
                            <td>{r.email.unwrap_or_default()}</td>
                            <td>{if r.enabled { "enabled" } else { "disabled" }}</td>
                        </tr>
                    }).collect_view()}
                </tbody>
            </table>
        </Page>
    }
}
