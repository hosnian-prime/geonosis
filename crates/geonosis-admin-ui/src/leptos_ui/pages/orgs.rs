//! `/admin-next/realms/:slug/orgs` — list organizations.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};

#[derive(Clone, Debug)]
pub struct OrgRow {
    pub alias: String,
    pub display_name: String,
    pub default_idp_alias: Option<String>,
    pub enabled: bool,
}

#[component]
pub fn OrgsPage(realm_slug: String, rows: Vec<OrgRow>) -> impl IntoView {
    let ctx = PageContext {
        title: "Organizations".into(),
        active_section: "orgs",
    };
    let back = format!("/admin-next/realms/{realm_slug}");
    view! {
        <Page context=ctx>
            <nav class="gn-breadcrumb"><a href=back>"← Realm"</a></nav>
            <h1>"Organizations"</h1>
            <p class="gn-subtitle">"B2B sub-tenants — invitations, domains, per-org IdPs."</p>
            <table class="gn-table">
                <thead>
                    <tr><th>"Alias"</th><th>"Name"</th><th>"Default IdP"</th><th>"State"</th></tr>
                </thead>
                <tbody>
                    {rows.into_iter().map(|r| view! {
                        <tr>
                            <td><code>{r.alias}</code></td>
                            <td>{r.display_name}</td>
                            <td>{r.default_idp_alias.unwrap_or_else(|| "—".into())}</td>
                            <td>{if r.enabled { "enabled" } else { "disabled" }}</td>
                        </tr>
                    }).collect_view()}
                </tbody>
            </table>
        </Page>
    }
}
