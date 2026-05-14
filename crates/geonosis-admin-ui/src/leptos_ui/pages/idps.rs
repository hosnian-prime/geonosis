//! `/admin-next/realms/:slug/idps` — list identity providers (broker).

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::list_table::{state_label, ListTable};
use crate::leptos_ui::components::page_header::PageHeader;

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
            <PageHeader
                title="Identity providers"
                back_href=back
                subtitle="External OIDC + SAML IdPs the realm brokers against."
            />
            <ListTable headers=vec!["Alias", "Name", "Kind", "State"]>
                {rows.into_iter().map(|r| view! {
                    <tr>
                        <td><code>{r.alias}</code></td>
                        <td>{r.display_name}</td>
                        <td>{r.kind}</td>
                        <td>{state_label(r.enabled)}</td>
                    </tr>
                }).collect_view()}
            </ListTable>
        </Page>
    }
}
