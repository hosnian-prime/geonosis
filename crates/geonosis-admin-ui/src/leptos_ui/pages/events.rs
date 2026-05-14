//! `/admin-next/realms/:slug/events` — audit event explorer.
//!
//! Plain HTML form GET → re-renders the same page with the filter
//! reapplied. No hydration: per docs/08-admin-ui.md only the flow
//! editor is hydrated; filterable list pages stay SSR-only with a
//! `<form method="get">` so they work without JS.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;

#[derive(Clone, Debug, Default)]
pub struct EventFilter {
    pub action: Option<String>,
    pub actor: Option<String>,
    pub from: Option<String>,
    pub until: Option<String>,
}

#[derive(Clone, Debug)]
pub struct EventRow {
    pub occurred_at: String,
    pub actor: String,
    pub action: String,
    pub target: String,
}

#[component]
pub fn EventsPage(realm_slug: String, filter: EventFilter, rows: Vec<EventRow>) -> impl IntoView {
    let ctx = PageContext {
        title: "Audit events".into(),
        active_section: "events",
    };
    let back = format!("/admin-next/realms/{realm_slug}");
    let action = filter.action.unwrap_or_default();
    let actor = filter.actor.unwrap_or_default();
    let from = filter.from.unwrap_or_default();
    let until = filter.until.unwrap_or_default();
    let empty = rows.is_empty();
    view! {
        <Page context=ctx>
            <PageHeader
                title="Audit events"
                back_href=back
                subtitle="Append-only forensic stream. Filters apply server-side; results capped at 500."
            />
            <form class="gn-filter" method="get">
                <label>
                    "Action"
                    <input type="text" name="action" value=action
                        placeholder="oidc.token.issued"/>
                </label>
                <label>
                    "Actor"
                    <input type="text" name="actor" value=actor
                        placeholder="user / client / system / ULID"/>
                </label>
                <label>
                    "From"
                    <input type="datetime-local" name="from" value=from/>
                </label>
                <label>
                    "Until"
                    <input type="datetime-local" name="until" value=until/>
                </label>
                <button type="submit" class="gn-btn">"Apply"</button>
            </form>
            {if empty {
                view! { <p class="gn-empty">"No events match the current filter."</p> }.into_any()
            } else {
                view! {
                    <ListTable headers=vec!["Occurred at", "Actor", "Action", "Target"]>
                        {rows.into_iter().map(|r| view! {
                            <tr>
                                <td><time>{r.occurred_at}</time></td>
                                <td><code>{r.actor}</code></td>
                                <td>{r.action}</td>
                                <td><code>{r.target}</code></td>
                            </tr>
                        }).collect_view()}
                    </ListTable>
                }.into_any()
            }}
        </Page>
    }
}
