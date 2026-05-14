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
}

#[component]
pub fn Page(context: PageContext, children: Children) -> impl IntoView {
    view! {
        <AdminLayout title=context.title.clone() active_section=context.active_section>
            {children()}
        </AdminLayout>
    }
}
