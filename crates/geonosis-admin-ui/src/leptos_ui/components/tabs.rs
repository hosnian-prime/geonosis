//! Tab bar rendered above a detail-page's content area.
//!
//! Tabs in the admin console are **navigation**, not in-page state.
//! Each tab is a server URL with `?tab=` selecting the active panel,
//! so the back/forward buttons work, deep links work, and every tab
//! renders fully on the server with no hydration.

use leptos::prelude::*;

#[derive(Clone, Debug)]
pub struct TabItem {
    pub key: String,
    pub label: String,
    pub href: String,
}

impl TabItem {
    pub fn new(key: impl Into<String>, label: impl Into<String>, href: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            label: label.into(),
            href: href.into(),
        }
    }
}

#[component]
pub fn TabBar(active: String, items: Vec<TabItem>) -> impl IntoView {
    view! {
        <nav class="gn-tabs" role="tablist" aria-label="Sections">
            {items
                .into_iter()
                .map(|t| {
                    let is_active = t.key == active;
                    let class = if is_active { "gn-tabs__item is-active" } else { "gn-tabs__item" };
                    view! {
                        <a
                            class=class
                            href=t.href
                            role="tab"
                            aria-selected=if is_active { "true" } else { "false" }
                        >
                            {t.label}
                        </a>
                    }
                })
                .collect_view()}
        </nav>
    }
}
