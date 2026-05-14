//! `/admin-next/realms` — realm list page.
//!
//! Server-rendered; no hydration island. Reuses the JSON
//! `/admin/v1/realms` contract so the data shape is shared with
//! the REST API surface.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::list_table::{state_label, ListTable};
use crate::leptos_ui::components::page_header::PageHeader;

#[derive(Clone, Debug)]
pub struct RealmRow {
    pub slug: String,
    pub display_name: String,
    pub enabled: bool,
}

#[component]
pub fn RealmsPage(realms: Vec<RealmRow>) -> impl IntoView {
    let ctx = PageContext {
        title: "Realms".into(),
        active_section: "realms",
    };
    view! {
        <Page context=ctx>
            <PageHeader
                title="Realms"
                subtitle="All identity universes hosted by this Geonosis instance."
            />
            <ListTable headers=vec!["Slug", "Display name", "State"]>
                {realms
                    .into_iter()
                    .map(|r| {
                        let detail_href = format!("/admin-next/realms/{}", r.slug);
                        view! {
                            <tr>
                                <td><a href=detail_href>{r.slug}</a></td>
                                <td>{r.display_name}</td>
                                <td>{state_label(r.enabled)}</td>
                            </tr>
                        }
                    })
                    .collect_view()}
            </ListTable>
        </Page>
    }
}
