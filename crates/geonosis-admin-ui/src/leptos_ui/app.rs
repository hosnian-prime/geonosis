//! Top-level Leptos `App` shell.
//!
//! Wraps individual page components in a consistent layout (header,
//! sidebar, content slot). Future hydration islands attach as children
//! of the `<main>` slot; SSR-only pages render the entire tree on the
//! server and ship zero JS.

use leptos::prelude::*;

use crate::leptos_ui::components::layout::AdminLayout;

#[derive(Clone, Debug)]
pub struct PageContext {
    pub title: String,
    pub active_section: &'static str,
    pub realm_slug: Option<String>,
}

#[component]
pub fn Page(context: PageContext, children: Children) -> impl IntoView {
    let slug = context.realm_slug.clone().unwrap_or_default();
    view! {
        <AdminLayout title=context.title.clone() active_section=context.active_section realm_slug=slug>
            {children()}
        </AdminLayout>
    }
}
