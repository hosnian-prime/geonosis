//! Shared list-table primitive.
//!
//! Every CRUD page renders the same `<table class="gn-table">` shape:
//! a fixed `<thead>` row of column labels and a `<tbody>` of rows
//! the page builds per its own data type. This component owns the
//! scaffolding; the page only emits its own `<tr>` rows.
//!
//! Pages call `.with_data_label(col)` on each `<td>` (via the
//! `data-label` attribute) so the mobile card layout in `tokens.css`
//! can label each value when columns collapse below 768 px.

use leptos::prelude::*;

#[component]
pub fn ListTable(headers: Vec<&'static str>, children: Children) -> impl IntoView {
    view! {
        <div class="gn-table-wrap">
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
        </div>
    }
}

/// Conventional cell content for a boolean enabled/state column.
pub fn state_label(enabled: bool) -> &'static str {
    if enabled {
        "Enabled"
    } else {
        "Disabled"
    }
}
