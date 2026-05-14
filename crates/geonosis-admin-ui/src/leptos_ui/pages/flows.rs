//! `/admin-next/realms/:slug/flows` — flow list + per-alias edit.
//!
//! v0.1 ships the SSR skeleton called for in docs/08-admin-ui.md
//! §"Flow editor (special case)" with a textarea-based JSON editor.
//! The canvas-and-graph hydrated island lands once the hand-rolled
//! Leptos canvas component is built; the JSON path stays as the
//! durable contract underneath (round-tripping `FlowDefinition`),
//! which is also what `geoctl flows export/import` uses.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;

#[derive(Clone, Debug)]
pub struct FlowRow {
    pub alias: String,
    pub display_name: String,
    pub version: i32,
    pub node_count: usize,
}

#[component]
pub fn FlowsPage(realm_slug: String, rows: Vec<FlowRow>) -> impl IntoView {
    let ctx = PageContext {
        title: "Flows".into(),
        active_section: "flows",
    };
    let back = format!("/admin-next/realms/{realm_slug}");
    let realm = realm_slug.clone();
    view! {
        <Page context=ctx>
            <PageHeader
                title="Flows"
                back_href=back
                subtitle="Authentication graphs (DSL). Export / import via geoctl; per-flow edit below."
            />
            <ListTable headers=vec!["Alias", "Display name", "Version", "Nodes", ""]>
                {rows.into_iter().map(|r| {
                    let href = format!("/admin-next/realms/{}/flows/{}", realm, r.alias);
                    view! {
                        <tr>
                            <td><code>{r.alias}</code></td>
                            <td>{r.display_name}</td>
                            <td>{r.version.to_string()}</td>
                            <td>{r.node_count.to_string()}</td>
                            <td><a href=href>"edit"</a></td>
                        </tr>
                    }
                }).collect_view()}
            </ListTable>
        </Page>
    }
}

/// Detail page: server-rendered skeleton (per docs/08 the hydrated
/// canvas attaches to this static tree). Today the editing surface
/// is a `<textarea>` with the canonical JSON DSL pretty-printed; the
/// canvas island will hydrate `#gn-flow-canvas` once shipped.
#[component]
pub fn FlowEditPage(
    realm_slug: String,
    alias: String,
    json: String,
    #[prop(optional)] error: Option<String>,
) -> impl IntoView {
    let ctx = PageContext {
        title: format!("Edit flow {alias}"),
        active_section: "flows",
    };
    let back = format!("/admin-next/realms/{realm_slug}/flows");
    let post = format!("/admin-next/realms/{realm_slug}/flows/{alias}");
    let alias_display = alias.clone();
    view! {
        <Page context=ctx>
            <PageHeader
                title="Edit flow"
                back_href=back
                subtitle="JSON DSL editor. Server-side validate on save; canvas island lands after v0.1."
            />
            <p class="gn-meta">"Alias: " <code>{alias_display}</code></p>
            {error.map(|e| view! {
                <p class="gn-error" role="alert">"Validation error: " <code>{e}</code></p>
            })}
            <form method="post" action=post>
                <div id="gn-flow-canvas" class="gn-flow-canvas-skeleton" aria-hidden="true"></div>
                <label class="gn-field">
                    <span class="gn-field__label">"Flow definition"</span>
                    <textarea name="definition" rows="24" cols="120"
                        class="gn-textarea gn-textarea--mono">{json}</textarea>
                </label>
                <button type="submit" class="gn-btn">"Save"</button>
            </form>
        </Page>
    }
}
