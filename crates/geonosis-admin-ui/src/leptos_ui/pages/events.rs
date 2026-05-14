//! `/admin/realms/{slug}/events` — audit event explorer.
//!
//! Plain HTML form GET → re-renders the same page with the filter
//! reapplied. SSR-only per spec §2.14.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::breadcrumb::Crumb;
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;
use crate::leptos_ui::components::widgets::EmptyState;

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
pub fn EventsPage(
    realm_slug: String,
    filter: EventFilter,
    rows: Vec<EventRow>,
    ctx: PageContext,
) -> impl IntoView {
    let ctx = ctx
        .with_title("Audit events")
        .with_section("events")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::current("Audit events"),
        ]);
    let action = filter.action.unwrap_or_default();
    let actor = filter.actor.unwrap_or_default();
    let from = filter.from.unwrap_or_default();
    let until = filter.until.unwrap_or_default();
    let is_empty = rows.is_empty();
    let form_action = format!("/admin/realms/{realm_slug}/events");
    view! {
        <Page context=ctx>
            <PageHeader
                title="Audit events".into()
                subtitle=Some("Append-only forensic stream. Filters apply server-side; results capped at 500.".into())
            />
            <form class="gn-filter-bar" method="get" action=form_action>
                <input class="gn-input" type="text" name="action" value=action placeholder="action (e.g. user.created)"/>
                <input class="gn-input" type="text" name="actor" value=actor placeholder="actor kind (user/client/system)"/>
                <input class="gn-input" type="datetime-local" name="from" value=from/>
                <input class="gn-input" type="datetime-local" name="until" value=until/>
                <button type="submit" class="gn-btn">"Apply"</button>
            </form>
            {if is_empty {
                view! {
                    <EmptyState title="No events match this filter".into()
                        description="Relax the filter or wait for new events to occur.".into()/>
                }.into_any()
            } else {
                view! {
                    <ListTable headers=vec!["Occurred at", "Actor", "Action", "Target"]>
                        {rows.into_iter().map(|r| view! {
                            <tr>
                                <td data-label="Occurred at" class="gn-text-subtle">{r.occurred_at}</td>
                                <td data-label="Actor"><code>{r.actor}</code></td>
                                <td data-label="Action">{r.action}</td>
                                <td data-label="Target"><code class="gn-truncate">{r.target}</code></td>
                            </tr>
                        }).collect_view()}
                    </ListTable>
                }.into_any()
            }}
        </Page>
    }
}
