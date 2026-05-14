//! `/admin-next/realms/:slug/flows` — flow list + per-alias edit.
//!
//! v0.1 ships the SSR skeleton from `docs/08-admin-ui.md` §"Flow editor
//! (special case)" *plus* the hand-rolled SVG flow editor canvas
//! (roadmap A6). The canvas is the primary editor; the textarea-based
//! JSON view stays in the same page as a power-user fallback toggled
//! via the canvas toolbar. Both paths flow through the same
//! `<form method="post">` so server-side validation runs once on save.
//!
//! What's deliberately deferred to v0.1.x (documented in the canvas
//! component module-doc): node creation/deletion from the canvas,
//! edge creation by drag, per-edge guard editing. Operators perform
//! those mutations in the JSON view today; the canvas covers the
//! "reposition + visually inspect" workflow that operators need most
//! frequently.

use leptos::prelude::*;

use geonosis_flow::FlowDefinition;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::flow_canvas::{FlowCanvas, FlowCanvasState};
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

/// Detail page: SSR-renders the hand-rolled SVG canvas and the JSON
/// textarea side-by-side; the canvas toolbar toggles the active view.
/// The canvas is interactive once `/static/flow-editor.js` hydrates;
/// before hydration both views are usable (JSON via form submit) so
/// the page degrades gracefully with JS disabled.
#[component]
pub fn FlowEditPage(
    realm_slug: String,
    alias: String,
    flow: Option<FlowDefinition>,
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
    let canvas_state = flow.as_ref().map(FlowCanvasState::from_definition);
    let canvas_realm = realm_slug.clone();
    let canvas_alias = alias.clone();
    let canvas_json = json.clone();
    view! {
        <Page context=ctx>
            <PageHeader
                title="Edit flow"
                back_href=back
                subtitle="Visual editor with JSON fallback. Save validates server-side before persisting."
            />
            <p class="gn-meta">"Alias: " <code>{alias_display}</code></p>
            {error.map(|e| view! {
                <p class="gn-error" role="alert">"Validation error: " <code>{e}</code></p>
            })}
            {canvas_state.map(|state| view! {
                <FlowCanvas
                    realm_slug=canvas_realm
                    alias=canvas_alias
                    state=state
                    flow_json=canvas_json
                />
            })}
            <form id="gn-flow-json-form" method="post" action=post class="gn-flow-json">
                <label class="gn-field">
                    <span class="gn-field__label">"Flow definition (JSON)"</span>
                    <textarea
                        id="gn-flow-json-textarea"
                        name="definition"
                        rows="24"
                        cols="120"
                        class="gn-textarea gn-textarea--mono"
                    >{json}</textarea>
                </label>
                <button type="submit" class="gn-btn">"Save JSON"</button>
            </form>
            <script src="/static/flow-editor.js" defer></script>
        </Page>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use geonosis_core::id::{FlowId, NodeId, RealmId};
    use geonosis_flow::{
        Edge, EdgeCondition, FlowNode, NodeKind, NodeLayout, Requirement, StartNode, SuccessNode,
    };

    fn def() -> FlowDefinition {
        let start_id = NodeId::new();
        let success_id = NodeId::new();
        FlowDefinition {
            realm_id: RealmId::new(),
            id: FlowId::new(),
            alias: "browser".into(),
            display_name: "Browser".into(),
            version: 1,
            start: start_id,
            nodes: vec![
                FlowNode {
                    id: start_id,
                    display_name: "Start".into(),
                    kind: NodeKind::Start(StartNode::default()),
                    requirement: Requirement::Required,
                    config: serde_json::Value::Null,
                    layout: Some(NodeLayout { x: 100.0, y: 60.0 }),
                },
                FlowNode {
                    id: success_id,
                    display_name: "Success".into(),
                    kind: NodeKind::Success(SuccessNode::default()),
                    requirement: Requirement::Required,
                    config: serde_json::Value::Null,
                    layout: Some(NodeLayout { x: 400.0, y: 200.0 }),
                },
            ],
            edges: vec![Edge {
                from: start_id,
                to: success_id,
                on: EdgeCondition::Otherwise,
                guard: Default::default(),
            }],
        }
    }

    fn render_to_string<F, V>(view_fn: F) -> String
    where
        F: FnOnce() -> V,
        V: RenderHtml + Send + 'static,
    {
        let owner = Owner::new();
        owner.with(|| view_fn().to_html())
    }

    #[test]
    fn flow_edit_page_renders_canvas_mount() {
        let flow = def();
        let json = serde_json::to_string_pretty(&flow).unwrap();
        let html = render_to_string(move || {
            view! {
                <FlowEditPage
                    realm_slug="acme".to_string()
                    alias="browser".to_string()
                    flow=Some(flow)
                    json=json
                />
            }
        });
        // Canvas mount root + interactive scaffolding.
        assert!(html.contains("id=\"gn-flow-canvas\""), "canvas mount missing");
        assert!(html.contains("data-save-action=\"/admin-next/realms/acme/flows/browser\""));
        assert!(html.contains("data-flow-node=\"true\""), "node group missing");
        assert!(html.contains("data-flow-edge=\"true\""), "edge group missing");
        assert!(html.contains("data-flow-action=\"save\""), "save button missing");
        // SVG payload rendered server-side.
        assert!(html.contains("<svg"));
        assert!(html.contains("viewBox=\"0 0 960 560\""));
        // JSON view still present as fallback.
        assert!(html.contains("id=\"gn-flow-json-form\""));
        assert!(html.contains("name=\"definition\""));
        // Hydrator script tag wired up.
        assert!(html.contains("/static/flow-editor.js"));
    }

    #[test]
    fn flow_edit_page_renders_initial_state_payload() {
        // The hydrator needs the full flow JSON inline so it can patch
        // node.layout client-side and POST without a second GET.
        let flow = def();
        let json = serde_json::to_string(&flow).unwrap();
        let html = render_to_string(move || {
            view! {
                <FlowEditPage
                    realm_slug="acme".to_string()
                    alias="browser".to_string()
                    flow=Some(flow)
                    json=json
                />
            }
        });
        assert!(html.contains("data-flow-initial=\"true\""), "initial state script missing");
        // Embedded JSON should appear inside the page (escaped is fine —
        // the hydrator reads textContent, not innerHTML).
        assert!(html.contains("\"alias\""));
    }

    #[test]
    fn flow_edit_page_renders_without_flow_definition() {
        // If storage returned a definition that fails to parse upstream,
        // the page must still render the JSON fallback so the operator
        // can fix it.
        let html = render_to_string(|| {
            view! {
                <FlowEditPage
                    realm_slug="acme".to_string()
                    alias="browser".to_string()
                    flow=None
                    json="{\"broken\":true}".to_string()
                />
            }
        });
        assert!(!html.contains("data-flow-node=\"true\""));
        assert!(html.contains("id=\"gn-flow-json-form\""));
    }
}
