//! `/admin-next/realms/:slug/agents` — list agent (AI / M2M) identities.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};

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
    };
    let back = format!("/admin-next/realms/{realm_slug}");
    view! {
        <Page context=ctx>
            <nav class="gn-breadcrumb"><a href=back>"← Realm"</a></nav>
            <h1>"Agents"</h1>
            <p class="gn-subtitle">"AI / M2M delegated identities. Capabilities + rate limits per agent."</p>
            <table class="gn-table">
                <thead>
                    <tr><th>"Alias"</th><th>"Name"</th><th>"Kind"</th><th>"Vendor"</th><th>"Model"</th><th>"State"</th></tr>
                </thead>
                <tbody>
                    {rows.into_iter().map(|r| view! {
                        <tr>
                            <td><code>{r.alias}</code></td>
                            <td>{r.display_name}</td>
                            <td>{r.kind}</td>
                            <td>{r.vendor.unwrap_or_default()}</td>
                            <td>{r.model_hint.unwrap_or_default()}</td>
                            <td>{if r.enabled { "enabled" } else { "disabled" }}</td>
                        </tr>
                    }).collect_view()}
                </tbody>
            </table>
        </Page>
    }
}
