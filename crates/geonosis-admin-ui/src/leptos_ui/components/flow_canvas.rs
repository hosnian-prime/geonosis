//! Hand-rolled SVG flow editor canvas (v0.1 MVP — roadmap item A6).
//!
//! Per `docs/08-admin-ui.md` §"Flow editor (special case)", the flow
//! editor is the only admin surface that requires extensive client-side
//! state. The Leptos component below produces the **server-rendered SVG
//! tree** that the operator's browser then makes interactive via a
//! small hand-rolled vanilla-JS module (`/static/flow-editor.js`). The
//! split keeps the heavy graph-editor library Geonosis explicitly
//! refuses out of the dependency tree while still respecting the
//! "canvas as island" contract: SSR draws the initial state from the
//! stored `FlowDefinition`, the JS module attaches drag handlers and
//! a "Save" round-trip that POSTs the mutated JSON back to the
//! existing form endpoint.
//!
//! v0.1 scope (intentional):
//!
//! - **Ships**: render existing nodes at their stored `node.layout`
//!   coordinates (deterministic grid fallback if absent); render edges
//!   as Bezier curves between nodes; drag nodes to reposition; "Save"
//!   button persists the mutated graph (JSON form-POST to the existing
//!   `/admin-next/realms/:slug/flows/:alias` handler); Canvas/JSON view
//!   toggle so the JSON textarea remains the fallback for power users.
//! - **Deliberately left for v0.1.x**: node creation/deletion (operators
//!   can still author new nodes in JSON view), edge creation by drag,
//!   per-edge guard / `on:` condition UI, dry-run integration, undo,
//!   minimap.
//!
//! The JSON path stays the source of truth: every save goes through the
//! existing server-side validator + compiler, so the canvas can never
//! land a malformed flow in storage.

use leptos::prelude::*;

use geonosis_flow::{Edge, FlowDefinition, FlowNode, NodeLayout};

/// Canvas viewBox dimensions (logical pixels). Picked to match the
/// historical Maud preview canvas so the visual rhythm doesn't shift
/// when an operator switches between the two admin surfaces.
const VIEW_W: f32 = 960.0;
const VIEW_H: f32 = 560.0;

/// Per-node SVG box dimensions.
const BOX_W: f32 = 168.0;
const BOX_H: f32 = 56.0;

/// Layout state ready to be serialized into the SVG tree. Separated
/// from `FlowDefinition` so the canvas component can take a stable,
/// SSR-pure view that's trivial to test independently from storage.
#[derive(Debug, Clone)]
pub struct FlowCanvasState {
    pub nodes: Vec<FlowCanvasNode>,
    pub edges: Vec<FlowCanvasEdge>,
}

#[derive(Debug, Clone)]
pub struct FlowCanvasNode {
    /// Stable identifier — the source-of-truth `NodeId.to_string()`.
    /// The vanilla-JS hydrator uses this to look up the underlying
    /// node when patching coordinates back into the JSON DSL.
    pub id: String,
    pub display_name: String,
    pub kind_label: String,
    pub requirement_label: String,
    pub x: f32,
    pub y: f32,
}

#[derive(Debug, Clone)]
pub struct FlowCanvasEdge {
    pub from: String,
    pub to: String,
    pub on_label: String,
}

impl FlowCanvasState {
    /// Build the canvas state from a stored `FlowDefinition`.
    ///
    /// Nodes without a persisted layout receive a deterministic grid
    /// position so the canvas always renders something legible. The
    /// grid traversal order is `FlowDefinition.nodes`'s declaration
    /// order, which mirrors what the JSON textarea would show.
    pub fn from_definition(def: &FlowDefinition) -> Self {
        let nodes = def
            .nodes
            .iter()
            .enumerate()
            .map(|(ix, n)| {
                let (x, y) = match n.layout {
                    Some(NodeLayout { x, y }) => (x, y),
                    None => grid_position(ix, def.nodes.len()),
                };
                FlowCanvasNode {
                    id: n.id.to_string(),
                    display_name: display_name_or_fallback(n),
                    kind_label: node_kind_label(n).to_string(),
                    requirement_label: format!("{:?}", n.requirement).to_lowercase(),
                    x,
                    y,
                }
            })
            .collect();
        let edges = def
            .edges
            .iter()
            .map(|e| FlowCanvasEdge {
                from: e.from.to_string(),
                to: e.to.to_string(),
                on_label: edge_on_label(e).to_string(),
            })
            .collect();
        Self { nodes, edges }
    }
}

fn display_name_or_fallback(n: &FlowNode) -> String {
    if !n.display_name.is_empty() {
        n.display_name.clone()
    } else {
        node_kind_label(n).to_string()
    }
}

fn node_kind_label(n: &FlowNode) -> &'static str {
    use geonosis_flow::NodeKind::*;
    match n.kind {
        Start(_) => "start",
        Render { .. } => "render",
        Authenticator { .. } => "authenticator",
        Broker { .. } => "broker",
        Switch { .. } => "switch",
        SubFlow { .. } => "sub-flow",
        Action { .. } => "action",
        Success(_) => "success",
        Failure { .. } => "failure",
    }
}

fn edge_on_label(e: &Edge) -> &'static str {
    use geonosis_flow::EdgeCondition::*;
    match e.on {
        Otherwise => "otherwise",
        Success => "success",
        Failure => "failure",
        Status(_) => "status",
    }
}

/// Deterministic grid layout for a node at index `ix` in a graph of
/// `total` nodes. Keeps unit tests stable.
fn grid_position(ix: usize, total: usize) -> (f32, f32) {
    let cols = ((total as f32).sqrt().ceil() as usize).max(1);
    let col = ix % cols;
    let row = ix / cols;
    let step_x = (VIEW_W - BOX_W) / (cols.max(1) as f32 + 1.0);
    let x = step_x * (col as f32 + 1.0);
    let y = 60.0 + (row as f32) * (BOX_H + 56.0);
    (x, y)
}

/// SSR render of the flow canvas. Produces the static SVG skeleton
/// the operator's browser hydrates with drag + save behaviour. The
/// `data-*` attributes form the stable contract between this server
/// tree and `flow-editor.js`.
///
/// `realm_slug` + `alias` are baked into the wrapper so the hydrator
/// can `fetch()` (or rather `form-POST`) without needing a separate
/// configuration channel; they are not surfaced to the user.
#[component]
pub fn FlowCanvas(
    realm_slug: String,
    alias: String,
    state: FlowCanvasState,
    /// The full JSON DSL — embedded once so the hydrator can mutate
    /// it client-side and POST the mutated copy on save without a
    /// second round-trip to the server.
    flow_json: String,
) -> impl IntoView {
    let view_box = format!("0 0 {VIEW_W} {VIEW_H}");
    let save_action = format!("/admin-next/realms/{realm_slug}/flows/{alias}");

    let nodes = state.nodes.clone();
    let edges = state.edges.clone();
    let node_index: std::collections::HashMap<String, FlowCanvasNode> =
        nodes.iter().map(|n| (n.id.clone(), n.clone())).collect();

    view! {
        <div
            id="gn-flow-canvas"
            class="gn-flow-canvas"
            data-realm=realm_slug.clone()
            data-alias=alias.clone()
            data-view-w=VIEW_W.to_string()
            data-view-h=VIEW_H.to_string()
            data-box-w=BOX_W.to_string()
            data-box-h=BOX_H.to_string()
            data-save-action=save_action.clone()
        >
            <div class="gn-flow-toolbar" role="toolbar" aria-label="Flow editor toolbar">
                <button type="button" class="gn-btn gn-flow-toolbar__btn" data-flow-view="canvas" aria-pressed="true">
                    "Canvas"
                </button>
                <button type="button" class="gn-btn gn-flow-toolbar__btn" data-flow-view="json" aria-pressed="false">
                    "JSON"
                </button>
                <span class="gn-flow-toolbar__sep" aria-hidden="true"></span>
                <button type="button" class="gn-btn gn-btn--primary" data-flow-action="save">
                    "Save"
                </button>
                <span class="gn-flow-toolbar__status" data-flow-status role="status" aria-live="polite"></span>
            </div>
            <svg
                class="gn-flow-canvas__svg"
                xmlns="http://www.w3.org/2000/svg"
                viewBox=view_box
                preserveAspectRatio="xMidYMid meet"
                role="img"
                aria-label="Flow graph"
            >
                <defs>
                    <marker
                        id="gn-flow-arrow"
                        viewBox="0 0 10 10"
                        refX="10"
                        refY="5"
                        markerWidth="8"
                        markerHeight="8"
                        orient="auto-start-reverse"
                    >
                        <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--gn-color-accent, #4f8cff)"/>
                    </marker>
                </defs>
                <g class="gn-flow-canvas__edges" data-flow-layer="edges">
                    {edges.into_iter().map(|e| {
                        let from = node_index.get(&e.from);
                        let to = node_index.get(&e.to);
                        let (path, midx, midy) = edge_path_for(from, to);
                        let from_id = e.from.clone();
                        let to_id = e.to.clone();
                        let label = e.on_label.clone();
                        view! {
                            <g class="gn-flow-edge"
                               data-flow-edge="true"
                               data-from=from_id
                               data-to=to_id>
                                <path
                                    class="gn-flow-edge__path"
                                    d=path
                                    fill="none"
                                    stroke="var(--gn-color-accent, #4f8cff)"
                                    stroke-width="2"
                                    marker-end="url(#gn-flow-arrow)"
                                />
                                <text
                                    class="gn-flow-edge__label"
                                    x=midx.to_string()
                                    y=midy.to_string()
                                    text-anchor="middle"
                                    font-size="11"
                                    fill="var(--gn-color-fg-muted, #8a93a6)"
                                >
                                    {label}
                                </text>
                            </g>
                        }
                    }).collect_view()}
                </g>
                <g class="gn-flow-canvas__nodes" data-flow-layer="nodes">
                    {nodes.into_iter().map(|n| {
                        let cx = (n.x + BOX_W / 2.0).to_string();
                        let title_y = (n.y + 22.0).to_string();
                        let meta_y = (n.y + 40.0).to_string();
                        let kind = n.kind_label.clone();
                        view! {
                            <g
                                class="gn-flow-node"
                                data-flow-node="true"
                                data-node-id=n.id.clone()
                                data-kind=kind.clone()
                                transform=format!("translate({}, {})", n.x, n.y)
                                tabindex="0"
                                role="group"
                                aria-label=format!("{} ({})", n.display_name, kind)
                            >
                                <rect
                                    class="gn-flow-node__bg"
                                    x="0"
                                    y="0"
                                    width=BOX_W.to_string()
                                    height=BOX_H.to_string()
                                    rx="10"
                                    fill="var(--gn-color-surface-2, #161a22)"
                                    stroke="var(--gn-color-border, #2a2f3b)"
                                    stroke-width="1.5"
                                />
                                <text
                                    class="gn-flow-node__title"
                                    x=cx.clone()
                                    y=title_y
                                    text-anchor="middle"
                                    font-size="13"
                                    font-weight="600"
                                    fill="var(--gn-color-fg, #f5f5f7)"
                                >
                                    {n.display_name.clone()}
                                </text>
                                <text
                                    class="gn-flow-node__meta"
                                    x=cx
                                    y=meta_y
                                    text-anchor="middle"
                                    font-size="11"
                                    fill="var(--gn-color-fg-muted, #8a93a6)"
                                >
                                    {format!("{} · {}", kind, n.requirement_label)}
                                </text>
                            </g>
                        }
                    }).collect_view()}
                </g>
            </svg>
            <noscript>
                <p class="gn-flow-canvas__noscript">
                    "Interactive canvas requires JavaScript. Switch to the JSON view below to edit."
                </p>
            </noscript>
            <script
                type="application/json"
                data-flow-initial="true"
            >
                {flow_json}
            </script>
            <p class="gn-flow-canvas__note">
                "Drag nodes to reposition. Use the JSON view for node creation, edge rewires, and per-edge guards (v0.1.x)."
            </p>
        </div>
    }
}

/// Compute the cubic Bezier path between two node boxes plus the
/// midpoint coordinates used to place the edge condition label.
///
/// Returns a fall-back vertical mid-screen line when either endpoint
/// is missing from the layout — this only happens for malformed
/// graphs that wouldn't have compiled, but the canvas still has to
/// render *something* so the operator can find the bad edge.
fn edge_path_for(from: Option<&FlowCanvasNode>, to: Option<&FlowCanvasNode>) -> (String, f32, f32) {
    let (fx, fy) = match from {
        Some(n) => (n.x + BOX_W / 2.0, n.y + BOX_H),
        None => (VIEW_W / 2.0, VIEW_H * 0.25),
    };
    let (tx, ty) = match to {
        Some(n) => (n.x + BOX_W / 2.0, n.y),
        None => (VIEW_W / 2.0, VIEW_H * 0.75),
    };
    let mid_y = (fy + ty) / 2.0;
    let path = format!(
        "M {fx:.1} {fy:.1} C {fx:.1} {my:.1}, {tx:.1} {my:.1}, {tx:.1} {ty:.1}",
        fx = fx,
        fy = fy,
        tx = tx,
        ty = ty,
        my = mid_y,
    );
    let midx = (fx + tx) / 2.0;
    (path, midx, mid_y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use geonosis_core::id::{FlowId, NodeId, RealmId};
    use geonosis_flow::{
        Edge, EdgeCondition, FlowNode, NodeKind, Requirement, StartNode, SuccessNode,
    };

    fn sample_definition() -> FlowDefinition {
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

    #[test]
    fn flow_canvas_state_preserves_stored_layout() {
        let def = sample_definition();
        let state = FlowCanvasState::from_definition(&def);
        assert_eq!(state.nodes.len(), 2);
        assert_eq!(state.edges.len(), 1);
        assert_eq!(state.nodes[0].x, 100.0);
        assert_eq!(state.nodes[0].y, 60.0);
        assert_eq!(state.nodes[1].x, 400.0);
        assert_eq!(state.nodes[1].y, 200.0);
        assert_eq!(state.nodes[0].kind_label, "start");
        assert_eq!(state.nodes[1].kind_label, "success");
        assert_eq!(state.nodes[0].requirement_label, "required");
    }

    #[test]
    fn flow_canvas_state_grid_falls_back_when_layout_missing() {
        let mut def = sample_definition();
        for n in &mut def.nodes {
            n.layout = None;
        }
        let state = FlowCanvasState::from_definition(&def);
        // Deterministic grid: same total + index must yield same coords.
        assert_eq!(state.nodes.len(), 2);
        let (x0, y0) = grid_position(0, 2);
        let (x1, y1) = grid_position(1, 2);
        assert_eq!(state.nodes[0].x, x0);
        assert_eq!(state.nodes[0].y, y0);
        assert_eq!(state.nodes[1].x, x1);
        assert_eq!(state.nodes[1].y, y1);
    }

    /// Required by the task brief: confirm the FlowDefinition survives
    /// a full round-trip through canvas-state preview (layout reads)
    /// + the JSON serializer the canvas hydrator POSTs back.
    #[test]
    fn flow_def_round_trips_through_canvas_state() {
        let def = sample_definition();
        // Take the same path the SSR canvas takes.
        let state = FlowCanvasState::from_definition(&def);
        // Now mutate the layout the way a drag would.
        let mut mutated = def.clone();
        mutated.nodes[0].layout = Some(NodeLayout { x: 220.0, y: 90.0 });
        mutated.nodes[1].layout = Some(NodeLayout { x: 520.0, y: 240.0 });
        let json = serde_json::to_string(&mutated).expect("serialize");
        let back: FlowDefinition = serde_json::from_str(&json).expect("deserialize");
        // Same graph identity preserved.
        assert_eq!(back.alias, def.alias);
        assert_eq!(back.version, def.version);
        assert_eq!(back.nodes.len(), def.nodes.len());
        assert_eq!(back.edges.len(), def.edges.len());
        // Layout values survived the round trip.
        assert_eq!(back.nodes[0].layout.unwrap().x, 220.0);
        assert_eq!(back.nodes[0].layout.unwrap().y, 90.0);
        assert_eq!(back.nodes[1].layout.unwrap().x, 520.0);
        assert_eq!(back.nodes[1].layout.unwrap().y, 240.0);
        // Canvas-state derived from the original is preserved too.
        assert_eq!(state.nodes[0].id, def.nodes[0].id.to_string());
    }

    #[test]
    fn node_layout_serde_round_trip() {
        let l = NodeLayout { x: 12.5, y: -3.0 };
        let j = serde_json::to_string(&l).unwrap();
        assert!(j.contains("\"x\":12.5"));
        assert!(j.contains("\"y\":-3"));
        let back: NodeLayout = serde_json::from_str(&j).unwrap();
        assert_eq!(back, l);
    }

    #[test]
    fn flow_node_without_layout_serializes_without_field() {
        // Backwards compatibility: pre-canvas flows must serialize
        // without an empty `layout` key polluting their JSON.
        let n = FlowNode {
            id: NodeId::new(),
            display_name: "x".into(),
            kind: NodeKind::Start(StartNode::default()),
            requirement: Requirement::Required,
            config: serde_json::Value::Null,
            layout: None,
        };
        let j = serde_json::to_value(&n).unwrap();
        assert!(
            j.get("layout").is_none(),
            "absent layout should not serialize"
        );
    }

    #[test]
    fn edge_path_geometry_is_finite() {
        let from = FlowCanvasNode {
            id: "a".into(),
            display_name: "A".into(),
            kind_label: "start".into(),
            requirement_label: "required".into(),
            x: 100.0,
            y: 60.0,
        };
        let to = FlowCanvasNode {
            id: "b".into(),
            display_name: "B".into(),
            kind_label: "success".into(),
            requirement_label: "required".into(),
            x: 400.0,
            y: 200.0,
        };
        let (path, mx, my) = edge_path_for(Some(&from), Some(&to));
        assert!(path.starts_with("M "));
        assert!(path.contains(" C "));
        assert!(mx.is_finite());
        assert!(my.is_finite());
    }
}
