//! `/admin-next/realms/:slug/clients` — list clients.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};

#[derive(Clone, Debug)]
pub struct ClientRow {
    pub client_id: String,
    pub display_name: String,
    pub kind: String,
    pub enabled: bool,
}

#[component]
pub fn ClientsPage(realm_slug: String, rows: Vec<ClientRow>) -> impl IntoView {
    let ctx = PageContext {
        title: "Clients".into(),
        active_section: "clients",
    };
    let back = format!("/admin-next/realms/{realm_slug}");
    view! {
        <Page context=ctx>
            <nav class="gn-breadcrumb"><a href=back>"← Realm"</a></nav>
            <h1>"Clients"</h1>
            <table class="gn-table">
                <thead>
                    <tr><th>"Client ID"</th><th>"Name"</th><th>"Kind"</th><th>"State"</th></tr>
                </thead>
                <tbody>
                    {rows.into_iter().map(|r| view! {
                        <tr>
                            <td><code>{r.client_id}</code></td>
                            <td>{r.display_name}</td>
                            <td>{r.kind}</td>
                            <td>{if r.enabled { "enabled" } else { "disabled" }}</td>
                        </tr>
                    }).collect_view()}
                </tbody>
            </table>
        </Page>
    }
}
