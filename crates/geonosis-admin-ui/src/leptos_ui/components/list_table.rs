//! Shared list-table primitive.
//!
//! Every CRUD page in the admin UI renders the same `<table class="gn-table">`
//! shape: a fixed `<thead>` row of column labels and a `<tbody>` of rows
//! the page builds per its own data type. This component owns the
//! scaffolding so each page only writes its row cells.
//!
//! API choice — headers as `Vec<&'static str>` + `children: Children` for
//! rows. The page keeps full control of row markup (links, `<code>`,
//! conditional rendering) without ListTable having to be generic over
//! the row type. Headers are static strings because v0.1 has no i18n
//! routing into Leptos components yet; once `geonosis-i18n` is wired
//! into the SSR layer, the header type widens to `IntoView`.

use leptos::prelude::*;

#[component]
pub fn ListTable(headers: Vec<&'static str>, children: Children) -> impl IntoView {
    view! {
        <table class="gn-table">
            <thead>
                <tr>
                    {headers
                        .into_iter()
                        .map(|h| view! { <th>{h}</th> })
                        .collect_view()}
                </tr>
            </thead>
            <tbody>
                {children()}
            </tbody>
        </table>
    }
}

/// Conventional cell content for a boolean enabled/state column.
pub fn state_label(enabled: bool) -> &'static str {
    if enabled { "enabled" } else { "disabled" }
}
