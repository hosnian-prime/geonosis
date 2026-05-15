//! Page header — title + optional subtitle + right-aligned action
//! buttons, rendered above every list / detail page.
//!
//! The action slot accepts an `AnyView` so pages can build whatever
//! buttons they want at call time (single CTA, button row, etc.)
//! without the component needing to know the row layout.

use leptos::prelude::*;

#[component]
pub fn PageHeader(
    title: String,
    #[prop(default = None)] subtitle: Option<String>,
    #[prop(default = None)] actions: Option<AnyView>,
) -> impl IntoView {
    view! {
        <header class="gn-page-header">
            <div class="gn-page-header__text">
                <h1 class="gn-page-title">{title}</h1>
                {subtitle.map(|s| view! { <p class="gn-page-subtitle">{s}</p> })}
            </div>
            {actions.map(|a| view! { <div class="gn-page-header__actions">{a}</div> })}
        </header>
    }
}
