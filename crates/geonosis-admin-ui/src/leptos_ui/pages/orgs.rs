//! `/admin-next/realms/:slug/orgs` — list organizations.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::list_table::{state_label, ListTable};
use crate::leptos_ui::components::page_header::PageHeader;

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
        realm_slug: Some(realm_slug.clone()),
    };
    let back = format!("/admin-next/realms/{realm_slug}");
    view! {
        <Page context=ctx>
            <PageHeader
                title="Organizations"
                back_href=back
                subtitle="B2B sub-tenants — invitations, domains, per-org IdPs."
            />
            <ListTable headers=vec!["Alias", "Name", "Default IdP", "State"]>
                {rows.into_iter().map(|r| view! {
                    <tr>
                        <td><code>{r.alias}</code></td>
                        <td>{r.display_name}</td>
                        <td>{r.default_idp_alias.unwrap_or_else(|| "—".into())}</td>
                        <td>{state_label(r.enabled)}</td>
                    </tr>
                }).collect_view()}
            </ListTable>
        </Page>
    }
}
