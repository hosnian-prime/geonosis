//! `/admin/realms/{slug}/flows` — flow list + per-alias edit.
//!
//! Per `docs/08-admin-ui.md` §2.9 the flow editor is the one admin
//! page that requires extensive client-side state. The SVG canvas is
//! server-rendered as the SSR skeleton; `flow-editor.js` hydrates it
//! with drag + save behaviour. The JSON textarea stays in the same
//! page as a power-user fallback toggled via the canvas toolbar.

use leptos::prelude::*;

use geonosis_flow::FlowDefinition;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::breadcrumb::Crumb;
use crate::leptos_ui::components::flow_canvas::{FlowCanvas, FlowCanvasState};
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;
use crate::leptos_ui::components::widgets::{Alert, AlertKind, Badge, BadgeKind, EmptyState};

#[derive(Clone, Debug)]
pub struct FlowRow {
    pub alias: String,
    pub display_name: String,
    pub version: i32,
    pub node_count: usize,
}

#[component]
pub fn FlowsPage(realm_slug: String, rows: Vec<FlowRow>, ctx: PageContext) -> impl IntoView {
    let ctx = ctx
        .with_title("Flows")
        .with_section("flows")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::current("Flows"),
        ]);
    let is_empty = rows.is_empty();
    view! {
        <Page context=ctx>
            <PageHeader
                title="Authentication flows".into()
                subtitle=Some("Step-graph DSL for browser, direct-grant, registration, reset and client-auth flows.".into())
            />
            {if is_empty {
                view! {
                    <EmptyState title="No flows defined".into()
                        description="Realms ship with built-in browser/direct-grant flows; none have been customised yet.".into()/>
                }.into_any()
            } else {
                view! {
                    <ListTable headers=vec!["Alias", "Display name", "Version", "Nodes", "Actions"]>
                        {rows.into_iter().map(|r| {
                            let href = format!("/admin/realms/{realm_slug}/flows/{}", r.alias);
                            view! {
                                <tr>
                                    <td data-label="Alias"><a href=href.clone()><code>{r.alias}</code></a></td>
                                    <td data-label="Display name">{r.display_name}</td>
                                    <td data-label="Version"><Badge label=format!("v{}", r.version) kind=BadgeKind::Info/></td>
                                    <td data-label="Nodes">{r.node_count.to_string()}</td>
                                    <td data-label="Actions" class="gn-table__actions">
                                        <a class="gn-btn gn-btn--sm" href=href>"Edit"</a>
                                    </td>
                                </tr>
                            }
                        }).collect_view()}
                    </ListTable>
                }.into_any()
            }}
        </Page>
    }
}

#[component]
pub fn FlowEditPage(
    realm_slug: String,
    alias: String,
    flow: Option<FlowDefinition>,
    json: String,
    ctx: PageContext,
    #[prop(optional)] error: Option<String>,
) -> impl IntoView {
    let ctx = ctx
        .with_title(format!("Flow · {alias}"))
        .with_section("flows")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::link("Flows", format!("/admin/realms/{realm_slug}/flows")),
            Crumb::current(alias.clone()),
        ]);
    let post = format!("/admin/realms/{realm_slug}/flows/{alias}");
    let canvas_state = flow.as_ref().map(FlowCanvasState::from_definition);
    let canvas_realm = realm_slug.clone();
    let canvas_alias = alias.clone();
    let canvas_json = json.clone();
    view! {
        <Page context=ctx>
            <PageHeader
                title=format!("Edit flow: {alias}")
                subtitle=Some("Visual editor with JSON fallback. Save validates server-side before persisting.".into())
            />
            {error.map(|e| view! { <Alert message=format!("Validation error: {e}") kind=AlertKind::Danger/> })}
            {canvas_state.map(|state| view! {
                <FlowCanvas
                    realm_slug=canvas_realm
                    alias=canvas_alias
                    state=state
                    flow_json=canvas_json
                />
            })}
            <form id="gn-flow-json-form" method="post" action=post class="gn-flow-json gn-form">
                <label class="gn-field">
                    <span class="gn-field__label">"Flow definition (JSON)"</span>
                    <textarea
                        id="gn-flow-json-textarea"
                        name="definition"
                        rows="24"
                        cols="120"
                        class="gn-textarea gn-textarea--code"
                    >{json}</textarea>
                </label>
                <div class="gn-action-bar">
                    <button type="submit" class="gn-btn gn-btn--primary">"Save JSON"</button>
                </div>
            </form>
            <script src="/static/elk.min.js" defer></script>
            <script src="/static/flow-viewport.js" defer></script>
            <script src="/static/flow-layout.js" defer></script>
            <script src="/static/flow-crud.js" defer></script>
            <script src="/static/flow-panels.js" defer></script>
            <script src="/static/flow-dryrun.js" defer></script>
            <script src="/static/flow-editor.js" defer></script>
        </Page>
    }
}
