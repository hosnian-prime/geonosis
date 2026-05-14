//! Shared page header: breadcrumb + title + optional subtitle.
//!
//! Captures the pattern every CRUD page repeats:
//!
//! ```ignore
//! <nav class="gn-breadcrumb"><a href="..">"← Realm"</a></nav>
//! <h1>"Page title"</h1>
//! <p class="gn-subtitle">"description"</p>
//! ```
//!
//! v0.1 hardcodes the back-link label to "← Realm" because every
//! existing sub-page returns to the realm detail. Once the admin UI
//! gains nested sub-pages (e.g. org-detail → members), the prop
//! widens to a typed `BackLink { label, href }`.

use leptos::prelude::*;

#[component]
pub fn PageHeader(
    title: &'static str,
    #[prop(optional)] back_href: Option<String>,
    #[prop(optional)] subtitle: Option<&'static str>,
) -> impl IntoView {
    view! {
        {back_href.map(|href| view! {
            <nav class="gn-breadcrumb"><a href=href>"← Realm"</a></nav>
        })}
        <h1>{title}</h1>
        {subtitle.map(|s| view! { <p class="gn-subtitle">{s}</p> })}
    }
}
