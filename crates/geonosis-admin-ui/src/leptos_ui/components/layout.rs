//! Top-level page shell shared by every admin page.
//!
//! Renders the full HTML document — head, boot script, header,
//! sidebar, main content — wrapping the page-specific body. Built so
//! that the same component works on every breakpoint: CSS in
//! `tokens.css` flips the sidebar into a slide-over drawer below
//! 768 px and the JS in `admin-chrome.js` adds the open/close
//! behaviour.

use leptos::prelude::*;

use crate::leptos_ui::components::chrome::{Header, ProfileContext, RealmChoice, Sidebar, BOOT_SCRIPT};

#[component]
pub fn AdminLayout(
    /// Browser tab title — typically the page title with " — Geonosis".
    title: String,
    /// Highlighted sidebar entry.
    active_section: &'static str,
    /// Active realm slug. Empty when on the realm list.
    #[prop(default = String::new())]
    realm_slug: String,
    /// Realm options for the header dropdown.
    #[prop(default = Vec::new())]
    realms: Vec<RealmChoice>,
    /// Authenticated user metadata.
    #[prop(default = ProfileContext::default())]
    profile: ProfileContext,
    /// Page body.
    children: Children,
) -> impl IntoView {
    let active_realm = if realm_slug.is_empty() {
        None
    } else {
        Some(realm_slug.clone())
    };
    let full_title = format!("{title} · Geonosis");
    view! {
        <html lang="en" dir="auto">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width,initial-scale=1"/>
                <title>{full_title}</title>
                <link rel="stylesheet" href="/static/admin.css"/>
                <script inner_html=BOOT_SCRIPT></script>
                <script src="/static/admin-chrome.js" defer="defer"></script>
            </head>
            <body>
                <div class="gn-shell">
                    <Header
                        active_realm=active_realm
                        realms=realms
                        profile=profile
                    />
                    <div class="gn-body">
                        <Sidebar active=active_section realm_slug=realm_slug.clone()/>
                        <main class="gn-main" id="gn-main">
                            {children()}
                        </main>
                    </div>
                </div>
            </body>
        </html>
    }
}
