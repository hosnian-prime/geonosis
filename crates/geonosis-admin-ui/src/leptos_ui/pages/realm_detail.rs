//! `/admin-next/realms/:slug` — realm overview + links to sub-pages.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};

#[derive(Clone, Debug)]
pub struct RealmDetailData {
    pub slug: String,
    pub display_name: String,
    pub enabled: bool,
    pub organizations_enabled: bool,
}

#[component]
pub fn RealmDetailPage(data: RealmDetailData) -> impl IntoView {
    let ctx = PageContext {
        title: data.display_name.clone(),
        active_section: "realms",
    };
    let slug = data.slug.clone();
    let link = move |path: &'static str, label: &'static str| {
        let href = format!("/admin-next/realms/{slug}/{path}");
        view! { <li><a href=href>{label}</a></li> }
    };
    view! {
        <Page context=ctx>
            <h1>{data.display_name.clone()}</h1>
            <dl class="gn-meta">
                <dt>"Slug"</dt><dd><code>{data.slug.clone()}</code></dd>
                <dt>"Enabled"</dt><dd>{if data.enabled { "yes" } else { "no" }}</dd>
                <dt>"Organizations"</dt><dd>{if data.organizations_enabled { "enabled" } else { "disabled" }}</dd>
            </dl>
            <h2>"Sections"</h2>
            <ul class="gn-section-links">
                {link("clients", "Clients")}
                {link("users", "Users")}
                {link("roles", "Roles")}
                {link("groups", "Groups")}
                {link("orgs", "Organizations")}
                {link("agents", "Agents")}
                {link("idps", "Identity providers")}
                {link("flows", "Flows")}
                {link("events", "Audit events")}
            </ul>
        </Page>
    }
}
