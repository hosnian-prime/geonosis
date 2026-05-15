//! Breadcrumb trail — the "Realms › master › Clients › master-web"
//! navigation chip strip rendered on every detail page per
//! `docs/08-admin-ui.md` §1.1.
//!
//! A crumb is one of `Crumb::Link { href, label }` (clickable) or
//! `Crumb::Current { label }` (the page itself). The page constructs
//! the slice on the server and the component renders separators
//! between them.

use leptos::prelude::*;

#[derive(Clone, Debug)]
pub enum Crumb {
    Link { label: String, href: String },
    Current { label: String },
}

impl Crumb {
    pub fn link(label: impl Into<String>, href: impl Into<String>) -> Self {
        Self::Link {
            label: label.into(),
            href: href.into(),
        }
    }
    pub fn current(label: impl Into<String>) -> Self {
        Self::Current {
            label: label.into(),
        }
    }
}

#[component]
pub fn Breadcrumb(crumbs: Vec<Crumb>) -> impl IntoView {
    if crumbs.is_empty() {
        return ().into_any();
    }
    let _last = crumbs.len().saturating_sub(1);
    view! {
        <nav class="gn-breadcrumb" aria-label="Breadcrumb">
            {crumbs
                .into_iter()
                .enumerate()
                .map(|(i, crumb)| {
                    let separator = if i > 0 {
                        Some(view! { <span class="gn-breadcrumb__sep" aria-hidden="true">"›"</span> })
                    } else {
                        None
                    };
                    let cell = match crumb {
                        Crumb::Link { label, href } => view! {
                            <a href=href>{label}</a>
                        }
                        .into_any(),
                        Crumb::Current { label } => view! {
                            <span class="gn-breadcrumb__current" aria-current="page">{label}</span>
                        }
                        .into_any(),
                    };
                    view! { {separator} {cell} }
                })
                .collect_view()}
        </nav>
    }
    .into_any()
}
