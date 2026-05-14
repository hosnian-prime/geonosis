//! `/admin-next/realms/:slug/agents` — list agent (AI / M2M) identities.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::list_table::{state_label, ListTable};
use crate::leptos_ui::components::page_header::PageHeader;

#[derive(Clone, Debug)]
pub struct AgentRow {
    pub alias: String,
    pub display_name: String,
    pub kind: String,
    pub vendor: Option<String>,
    pub model_hint: Option<String>,
    pub enabled: bool,
}

#[component]
pub fn AgentsPage(realm_slug: String, rows: Vec<AgentRow>) -> impl IntoView {
    let ctx = PageContext {
        title: "Agents".into(),
        active_section: "agents",
        realm_slug: Some(realm_slug.clone()),
    };
    let back = format!("/admin-next/realms/{realm_slug}");
    view! {
        <Page context=ctx>
            <PageHeader
                title="Agents"
                back_href=back
                subtitle="AI / M2M delegated identities. Capabilities + rate limits per agent."
            />
            <ListTable headers=vec!["Alias", "Name", "Kind", "Vendor", "Model", "State"]>
                {rows.into_iter().map(|r| view! {
                    <tr>
                        <td><code>{r.alias}</code></td>
                        <td>{r.display_name}</td>
                        <td>{r.kind}</td>
                        <td>{r.vendor.unwrap_or_default()}</td>
                        <td>{r.model_hint.unwrap_or_default()}</td>
                        <td>{state_label(r.enabled)}</td>
                    </tr>
                }).collect_view()}
            </ListTable>
        </Page>
    }
}
