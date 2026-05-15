//! SVG flow editor canvas with ELK.js layout integration.
//!
//! The Leptos component below produces the **server-rendered SVG skeleton**
//! that the operator's browser hydrates via modular vanilla-JS modules:
//!
//! - `flow-editor.js`   — orchestrator
//! - `flow-viewport.js` — zoom / pan / minimap
//! - `flow-layout.js`   — ELK graph layout
//! - `flow-crud.js`     — node / edge CRUD
//! - `flow-panels.js`   — configuration side panel
//! - `flow-dryrun.js`   — dry-run integration
//!
//! The JSON path stays the source of truth: every save goes through the
//! existing server-side validator + compiler, so the canvas can never
//! land a malformed flow in storage.

use leptos::prelude::*;

use geonosis_flow::{Edge, FlowDefinition, FlowNode, NodeLayout};

/// Canvas viewBox dimensions (logical pixels).
const VIEW_W: f32 = 1920.0;
const VIEW_H: f32 = 1080.0;

/// Per-node SVG box dimensions.
const BOX_W: f32 = 180.0;
const BOX_H: f32 = 64.0;

/// Port circle radius.
const PORT_R: f32 = 6.0;

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
    let y = 80.0 + (row as f32) * (BOX_H + 80.0);
    (x, y)
}

#[component]
pub fn FlowCanvas(
    realm_slug: String,
    alias: String,
    state: FlowCanvasState,
    flow_json: String,
) -> impl IntoView {
    let view_box = format!("0 0 {VIEW_W} {VIEW_H}");
    let save_action = format!("/admin/realms/{realm_slug}/flows/{alias}");
    let dry_run_action = format!("/admin/v1/realms/{realm_slug}/flows/{alias}/dry-run");

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
            data-port-r=PORT_R.to_string()
            data-save-action=save_action.clone()
            data-dryrun-action=dry_run_action.clone()
        >
            // --- Toolbar ---------------------------------------------------
            <div class="gn-flow-toolbar" role="toolbar" aria-label="Flow editor toolbar">
                <button type="button" class="gn-btn gn-btn--sm gn-flow-toolbar__btn" data-flow-view="canvas" aria-pressed="true">
                    "Canvas"
                </button>
                <button type="button" class="gn-btn gn-btn--sm gn-flow-toolbar__btn" data-flow-view="json" aria-pressed="false">
                    "JSON"
                </button>

                <span class="gn-flow-toolbar__divider" aria-hidden="true"></span>

                // Node creation dropdown
                <div class="gn-flow-add-wrap" style="position:relative">
                    <button type="button" class="gn-btn gn-btn--sm" data-flow-action="add-node">
                        "+ Node"
                    </button>
                    <div class="gn-flow-node-menu" hidden data-flow-node-menu>
                        <button type="button" class="gn-flow-node-menu__item" data-node-kind="start">"Start"</button>
                        <button type="button" class="gn-flow-node-menu__item" data-node-kind="render">"Render"</button>
                        <button type="button" class="gn-flow-node-menu__item" data-node-kind="authenticator">"Authenticator"</button>
                        <button type="button" class="gn-flow-node-menu__item" data-node-kind="broker">"Broker"</button>
                        <button type="button" class="gn-flow-node-menu__item" data-node-kind="switch">"Switch"</button>
                        <button type="button" class="gn-flow-node-menu__item" data-node-kind="sub-flow">"Sub-flow"</button>
                        <button type="button" class="gn-flow-node-menu__item" data-node-kind="action">"Action"</button>
                        <button type="button" class="gn-flow-node-menu__item" data-node-kind="success">"Success"</button>
                        <button type="button" class="gn-flow-node-menu__item" data-node-kind="failure">"Failure"</button>
                    </div>
                </div>

                <button type="button" class="gn-btn gn-btn--sm" data-flow-action="auto-layout">
                    "Auto Layout"
                </button>
                <button type="button" class="gn-btn gn-btn--sm gn-flow-toolbar__btn" data-flow-action="dry-run" aria-pressed="false">
                    "Dry Run"
                </button>

                <span class="gn-flow-toolbar__divider" aria-hidden="true"></span>

                // Zoom controls
                <div class="gn-flow-zoom">
                    <button type="button" class="gn-btn gn-btn--sm gn-flow-zoom__btn" data-flow-action="zoom-in" aria-label="Zoom in">"+"</button>
                    <button type="button" class="gn-btn gn-btn--sm gn-flow-zoom__btn" data-flow-action="zoom-out" aria-label="Zoom out">"\u{2212}"</button>
                    <button type="button" class="gn-btn gn-btn--sm gn-flow-zoom__btn" data-flow-action="zoom-fit" aria-label="Fit to view">"Fit"</button>
                </div>

                <span class="gn-flow-toolbar__sep" aria-hidden="true"></span>

                <button type="button" class="gn-btn gn-btn--primary gn-btn--sm" data-flow-action="save">
                    "Save"
                </button>
                <span class="gn-flow-toolbar__status" data-flow-status role="status" aria-live="polite"></span>
            </div>

            // --- Dry-run panel (hidden by default) ----------------------
            <div id="gn-flow-dryrun" class="gn-flow-dryrun" hidden></div>

            // --- SVG canvas -----------------------------------------------
            <div class="gn-flow-canvas__viewport">
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
                            <path d="M 0 0 L 10 5 L 0 10 z"/>
                        </marker>
                    </defs>
                    // Viewport wrapper — zoom/pan transforms this group
                    <g data-flow-viewport="true">
                        <g class="gn-flow-canvas__edges" data-flow-layer="edges">
                            {edges.into_iter().map(|e| {
                                let from = node_index.get(&e.from);
                                let to = node_index.get(&e.to);
                                let (path, midx, _midy, label_y) = edge_path_for(from, to);
                                let hit_path = path.clone();
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
                                            marker-end="url(#gn-flow-arrow)"
                                        />
                                        // Invisible wider hit-target for click
                                        <path
                                            class="gn-flow-edge__hit"
                                            d=hit_path
                                        />
                                        <text
                                            class="gn-flow-edge__label"
                                            x=midx.to_string()
                                            y=label_y.to_string()
                                            text-anchor="middle"
                                            dominant-baseline="central"
                                        >
                                            {label}
                                        </text>
                                    </g>
                                }
                            }).collect_view()}
                        </g>
                        <g class="gn-flow-canvas__nodes" data-flow-layer="nodes">
                            {nodes.into_iter().map(|n| {
                                let cx = BOX_W / 2.0;
                                let title_y = BOX_H * 0.38;
                                let meta_y = BOX_H * 0.70;
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
                                        />
                                        <text
                                            class="gn-flow-node__title"
                                            x=cx.to_string()
                                            y=title_y.to_string()
                                            text-anchor="middle"
                                            dominant-baseline="central"
                                        >
                                            {n.display_name.clone()}
                                        </text>
                                        <text
                                            class="gn-flow-node__meta"
                                            x=cx.to_string()
                                            y=meta_y.to_string()
                                            text-anchor="middle"
                                            dominant-baseline="central"
                                        >
                                            {format!("{} \u{00b7} {}", kind, n.requirement_label)}
                                        </text>
                                        // Input port (top center)
                                        <circle
                                            class="gn-flow-port gn-flow-port--in"
                                            cx=cx.to_string()
                                            cy="0"
                                            r=PORT_R.to_string()
                                            data-port="in"
                                        />
                                        // Output port (bottom center)
                                        <circle
                                            class="gn-flow-port gn-flow-port--out"
                                            cx=cx.to_string()
                                            cy=BOX_H.to_string()
                                            r=PORT_R.to_string()
                                            data-port="out"
                                        />
                                    </g>
                                }
                            }).collect_view()}
                        </g>
                    </g>
                </svg>
                // Minimap canvas
                <canvas id="gn-flow-minimap" class="gn-flow-minimap" width="200" height="140"></canvas>
            </div>

            // --- Configuration side panel (hidden by default) -----------
            <div id="gn-flow-panel" class="gn-flow-panel" hidden></div>

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
        </div>
    }
}

/// Compute the cubic Bezier path between two node boxes plus the
/// midpoint coordinates used to place the edge condition label.
fn edge_path_for(from: Option<&FlowCanvasNode>, to: Option<&FlowCanvasNode>) -> (String, f32, f32, f32) {
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
    let label_y = mid_y - 14.0;
    (path, midx, mid_y, label_y)
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
        assert_eq!(state.nodes.len(), 2);
        let (x0, y0) = grid_position(0, 2);
        let (x1, y1) = grid_position(1, 2);
        assert_eq!(state.nodes[0].x, x0);
        assert_eq!(state.nodes[0].y, y0);
        assert_eq!(state.nodes[1].x, x1);
        assert_eq!(state.nodes[1].y, y1);
    }

    #[test]
    fn flow_def_round_trips_through_canvas_state() {
        let def = sample_definition();
        let state = FlowCanvasState::from_definition(&def);
        let mut mutated = def.clone();
        mutated.nodes[0].layout = Some(NodeLayout { x: 220.0, y: 90.0 });
        mutated.nodes[1].layout = Some(NodeLayout { x: 520.0, y: 240.0 });
        let json = serde_json::to_string(&mutated).expect("serialize");
        let back: FlowDefinition = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.alias, def.alias);
        assert_eq!(back.version, def.version);
        assert_eq!(back.nodes.len(), def.nodes.len());
        assert_eq!(back.edges.len(), def.edges.len());
        assert_eq!(back.nodes[0].layout.unwrap().x, 220.0);
        assert_eq!(back.nodes[0].layout.unwrap().y, 90.0);
        assert_eq!(back.nodes[1].layout.unwrap().x, 520.0);
        assert_eq!(back.nodes[1].layout.unwrap().y, 240.0);
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
        let (path, mx, my, ly) = edge_path_for(Some(&from), Some(&to));
        assert!(path.starts_with("M "));
        assert!(path.contains(" C "));
        assert!(mx.is_finite());
        assert!(my.is_finite());
        assert!(ly < my, "label should be above curve midpoint");
    }
}
