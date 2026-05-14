//! `/admin-next/realms/:slug/clients` — list clients.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::list_table::{state_label, ListTable};
use crate::leptos_ui::components::page_header::PageHeader;

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
            <PageHeader title="Clients" back_href=back/>
            <ListTable headers=vec!["Client ID", "Name", "Kind", "State"]>
                {rows.into_iter().map(|r| view! {
                    <tr>
                        <td><code>{r.client_id}</code></td>
                        <td>{r.display_name}</td>
                        <td>{r.kind}</td>
                        <td>{state_label(r.enabled)}</td>
                    </tr>
                }).collect_view()}
            </ListTable>
        </Page>
    }
}
