//! Persistent admin shell — the header bar, sidebar drawer, and the
//! inline boot script that suppresses the light/dark flash.
//!
//! Per `docs/08-admin-ui.md` §1.1 every page shares this chrome. The
//! header carries the brand, a realm selector dropdown, the
//! light/dark theme toggle, and the profile avatar; the sidebar is
//! rendered grouped per spec §1.2. The same template renders on
//! desktop + mobile — CSS in `tokens.css` flips the sidebar into a
//! slide-over drawer below 768 px.

use leptos::prelude::*;

use crate::leptos_ui::components::nav::SidebarNav;

#[derive(Clone, Debug)]
pub struct RealmChoice {
    pub slug: String,
    pub display_name: String,
}

#[derive(Clone, Debug, Default)]
pub struct ProfileContext {
    /// Authenticated user's username — displayed as initials in the
    /// avatar circle. `None` means logged-out (chrome still renders
    /// so the login page can reuse the same shell theme).
    pub username: Option<String>,
}

#[component]
pub fn Header(
    /// The realm whose pages we're currently viewing (highlighted in
    /// the dropdown). `None` on the realm list page.
    #[prop(default = None)]
    active_realm: Option<String>,
    /// Realm options for the dropdown.
    #[prop(default = Vec::new())]
    realms: Vec<RealmChoice>,
    /// Authenticated user metadata for the profile avatar.
    #[prop(default = ProfileContext::default())]
    profile: ProfileContext,
) -> impl IntoView {
    let initials = profile
        .username
        .as_deref()
        .map(initials_from)
        .unwrap_or_else(|| "·".to_string());
    let realm_options = realms.clone();
    let selected_slug = active_realm.clone();
    view! {
        <header class="gn-header" role="banner">
            <button
                type="button"
                class="gn-header__menu-toggle"
                aria-label="Toggle navigation"
                aria-expanded="false"
                data-gn-menu-toggle="true"
            >
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
                    stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <line x1="3" y1="6" x2="21" y2="6"/>
                    <line x1="3" y1="12" x2="21" y2="12"/>
                    <line x1="3" y1="18" x2="21" y2="18"/>
                </svg>
            </button>
            <a class="gn-brand" href="/admin/realms">
                <span class="gn-brand__mark">"G"</span>
                <span>"Geonosis"</span>
            </a>
            <div class="gn-header__spacer"></div>
            <div class="gn-header__actions">
                <RealmSelector active=selected_slug realms=realm_options/>
                <ThemeToggle/>
                <ProfileMenu initials=initials/>
            </div>
        </header>
        <div class="gn-sidebar-backdrop" data-gn-sidebar-backdrop="true"></div>
    }
}

#[component]
fn RealmSelector(active: Option<String>, realms: Vec<RealmChoice>) -> impl IntoView {
    if realms.is_empty() {
        return view! { <div class="gn-realm-selector" hidden=true></div> }.into_any();
    }
    let current = active.clone().unwrap_or_default();
    view! {
        <label class="gn-realm-selector" aria-label="Active realm">
            <select data-gn-realm-selector="true">
                <option value="__root" selected=current.is_empty()>"All realms"</option>
                {realms
                    .into_iter()
                    .map(|r| {
                        let selected = r.slug == current;
                        view! {
                            <option value=r.slug.clone() selected=selected>
                                {r.display_name.clone()}
                            </option>
                        }
                    })
                    .collect_view()}
            </select>
        </label>
    }
    .into_any()
}

#[component]
fn ThemeToggle() -> impl IntoView {
    view! {
        <button
            type="button"
            class="gn-icon-btn gn-theme-toggle"
            aria-label="Toggle theme"
            data-gn-theme-toggle="true"
        >
            <svg class="gn-icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="4"/>
                <line x1="12" y1="2" x2="12" y2="4"/>
                <line x1="12" y1="20" x2="12" y2="22"/>
                <line x1="4.93" y1="4.93" x2="6.34" y2="6.34"/>
                <line x1="17.66" y1="17.66" x2="19.07" y2="19.07"/>
                <line x1="2" y1="12" x2="4" y2="12"/>
                <line x1="20" y1="12" x2="22" y2="12"/>
                <line x1="4.93" y1="19.07" x2="6.34" y2="17.66"/>
                <line x1="17.66" y1="6.34" x2="19.07" y2="4.93"/>
            </svg>
            <svg class="gn-icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
            </svg>
        </button>
    }
}

#[component]
fn ProfileMenu(initials: String) -> impl IntoView {
    view! {
        <a class="gn-profile__avatar" href="/admin/profile" aria-label="Profile">
            {initials}
        </a>
    }
}

#[component]
pub fn Sidebar(active: &'static str, realm_slug: String) -> impl IntoView {
    view! {
        <aside class="gn-sidebar" data-gn-sidebar="true" aria-label="Admin navigation">
            <SidebarNav active=active realm_slug=realm_slug/>
        </aside>
    }
}

/// Inline boot script — runs **before** the body renders so the
/// stored theme is applied before any pixels paint. The string is
/// tiny + escaped manually so no XSS surface opens.
pub const BOOT_SCRIPT: &str = r#"
(function(){
    try {
        var stored = localStorage.getItem("gn-theme");
        var theme;
        if (stored === "light" || stored === "dark") {
            theme = stored;
        } else {
            theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches
                ? "light"
                : "dark";
        }
        document.documentElement.setAttribute("data-theme", theme);
    } catch (_) {
        document.documentElement.setAttribute("data-theme", "dark");
    }
})();
"#;

fn initials_from(username: &str) -> String {
    let trimmed = username.trim();
    if trimmed.is_empty() {
        return "·".into();
    }
    let parts: Vec<&str> = trimmed.split(|c: char| c == '.' || c == '-' || c == '_' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .collect();
    let mut s = String::new();
    if let Some(first) = parts.first() {
        if let Some(c) = first.chars().next() {
            s.push(c.to_ascii_uppercase());
        }
    }
    if parts.len() > 1 {
        if let Some(c) = parts[1].chars().next() {
            s.push(c.to_ascii_uppercase());
        }
    } else if let Some(first) = parts.first() {
        if let Some(c) = first.chars().nth(1) {
            s.push(c.to_ascii_lowercase());
        }
    }
    s
}
