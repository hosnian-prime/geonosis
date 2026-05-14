//! Top-level layout component shared by every admin page.
//!
//! Mirrors the structural choices in the legacy Maud `html.rs`
//! (header + sidebar + main) so the design-token stylesheet works
//! unchanged across both renderers during the migration window.

use leptos::prelude::*;

use crate::leptos_ui::components::nav::SidebarNav;

#[component]
pub fn AdminLayout(
    title: String,
    active_section: &'static str,
    children: Children,
) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en" dir="ltr">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width,initial-scale=1"/>
                <title>{format!("{title} — Geonosis")}</title>
                <link rel="stylesheet" href="/static/admin.css"/>
            </head>
            <body>
                <header class="gn-header">
                    <div class="gn-brand">
                        <a href="/admin-next/realms">"Geonosis"</a>
                    </div>
                </header>
                <div class="gn-app">
                    <SidebarNav active=active_section/>
                    <main class="gn-main">
                        {children()}
                    </main>
                </div>
            </body>
        </html>
    }
}
