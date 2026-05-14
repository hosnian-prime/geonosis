//! `/admin-next/realms` — proof-of-concept Leptos page.
//!
//! Lists every realm the storage backend knows about. Server-rendered;
//! no hydration island. Mirrors the data shape of the existing Maud
//! `page_realms_html` handler so the JSON `/admin/v1/realms` contract
//! is reused.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};

/// Minimal projection of a realm into something easy to render.
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
            <h1>"Realms"</h1>
            <p class="gn-subtitle">
                "All identity universes hosted by this Geonosis instance."
            </p>
            <table class="gn-table">
                <thead>
                    <tr>
                        <th>"Slug"</th>
                        <th>"Display name"</th>
                        <th>"State"</th>
                    </tr>
                </thead>
                <tbody>
                    {realms
                        .into_iter()
                        .map(|r| {
                            let state = if r.enabled { "enabled" } else { "disabled" };
                            let detail_href = format!("/admin-next/realms/{}", r.slug);
                            view! {
                                <tr>
                                    <td>
                                        <a href=detail_href>{r.slug}</a>
                                    </td>
                                    <td>{r.display_name}</td>
                                    <td>{state}</td>
                                </tr>
                            }
                        })
                        .collect_view()}
                </tbody>
            </table>
        </Page>
    }
}
