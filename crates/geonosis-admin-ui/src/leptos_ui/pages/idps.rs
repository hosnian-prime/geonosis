//! `/admin-next/realms/:slug/idps` — list identity providers (broker).

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};

#[derive(Clone, Debug)]
pub struct IdpRow {
    pub alias: String,
    pub display_name: String,
    pub kind: String,
    pub enabled: bool,
}

#[component]
pub fn IdpsPage(realm_slug: String, rows: Vec<IdpRow>) -> impl IntoView {
    let ctx = PageContext {
        title: "Identity providers".into(),
        active_section: "idps",
    };
    let back = format!("/admin-next/realms/{realm_slug}");
    view! {
        <Page context=ctx>
            <nav class="gn-breadcrumb"><a href=back>"← Realm"</a></nav>
            <h1>"Identity providers"</h1>
            <p class="gn-subtitle">"External OIDC + SAML IdPs the realm brokers against."</p>
            <table class="gn-table">
                <thead>
                    <tr><th>"Alias"</th><th>"Name"</th><th>"Kind"</th><th>"State"</th></tr>
                </thead>
                <tbody>
                    {rows.into_iter().map(|r| view! {
                        <tr>
                            <td><code>{r.alias}</code></td>
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
