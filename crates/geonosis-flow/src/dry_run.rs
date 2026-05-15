//! Admin "dry-run" — walk a flow against a synthetic context without
//! producing side effects.
//!
//! Per `docs/06-auth-flows.md` §"Visual flow editor" the admin UI must
//! offer **dry-run with synthetic context** so an operator can ask
//! *"given a user with these claims, which nodes would fire?"* before
//! letting the change reach production traffic.
//!
//! Design constraints that pin this module to v0.1:
//! - **Pure.** No I/O, no clocks, no audit emit, no WASM SPI invocation.
//!   The dry-run never calls the authenticator dispatcher; it assumes a
//!   default outcome per node (overridable via `expected_outcomes`) so
//!   the trace stays deterministic.
//! - **Same guard semantics as the executor.** Branch selection reuses
//!   `CompiledFlow::next_with_guard` so dry-run + production make the
//!   same edge decisions for a given `FlowContext`.
//! - **Bounded.** Cycles are not legal in the v0.1 flow graph, but a
//!   defensive iteration cap keeps a malformed flow from looping
//!   forever inside the admin endpoint. The cap mirrors the executor's
//!   own per-step loop budget.
//!
//! The shape of `DryRunReport` is deliberately small — `steps`,
//! `terminal`, optional `reason`. Operators consume it via the admin
//! REST surface; richer "what variables would have changed" telemetry
//! belongs in v0.1.x once we have a real claim-projection pipeline.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use geonosis_core::id::NodeId;

use crate::compile::{compile, CompileError, CompiledFlow};
use crate::dsl::{EdgeCondition, FlowDefinition, NodeKind};
use crate::state::FlowContext;

/// Iteration budget for the dry-run walker. Compiled flows are
/// acyclic in v0.1 (the compiler rejects cycles that do not exit via
/// a `SubFlow`), so this only fires on a pathologically-large but
/// linear graph or a future flow that re-enters via a SubFlow.
const MAX_STEPS: usize = 256;

/// Per-node "what would the authenticator return" override. Defaults
/// to `Success` when the caller does not pin a value — the most
/// common ask is *"assume the user authenticates; tell me which
/// branches I'd take after that."*
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ExpectedOutcome {
    #[default]
    Success,
    Failure,
    Skip,
}

impl ExpectedOutcome {
    fn as_edge_condition(self) -> EdgeCondition {
        match self {
            ExpectedOutcome::Success => EdgeCondition::Success,
            ExpectedOutcome::Failure => EdgeCondition::Failure,
            // Skipped authenticators advance via the Otherwise edge in
            // the production executor; mirror that here.
            ExpectedOutcome::Skip => EdgeCondition::Otherwise,
        }
    }
}

/// One node's appearance in the dry-run trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunStep {
    pub node_id: NodeId,
    /// Kebab-case label matching the node `kind` discriminator (see
    /// [`NodeKind`]) — `start`, `authenticator`, `success`, etc.
    pub kind: String,
    pub decision: Decision,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    /// The node fired (or would fire). Forward progress made.
    Taken,
    /// The node could not be advanced — no eligible outbound edge,
    /// or the caller pinned an outcome with no matching edge.
    Skipped,
}

/// Final state the walker stopped in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TerminalState {
    /// Reached a `Success` terminal node.
    Success,
    /// Reached a `Failure` terminal node.
    Failure,
    /// Stopped before a terminal — a guard blocked the last edge, the
    /// iteration budget tripped, or the graph hit a dead end.
    Incomplete,
}

/// What the dry-run produced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunReport {
    pub steps: Vec<DryRunStep>,
    pub terminal: TerminalState,
    /// Human-readable explanation when `terminal == Incomplete`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Error)]
pub enum DryRunError {
    #[error("flow failed to compile: {0}")]
    Compile(#[from] CompileError),
}

/// Convenience: compile + run in one call. Used by the admin handler
/// which receives a `FlowDefinition` straight from storage.
pub fn dry_run(
    flow: &FlowDefinition,
    context: &FlowContext,
    expected_outcomes: &HashMap<NodeId, ExpectedOutcome>,
) -> Result<DryRunReport, DryRunError> {
    let compiled = compile(flow.clone())?;
    Ok(dry_run_compiled(&compiled, context, expected_outcomes))
}

/// Walk a pre-compiled flow. Pure: same `(flow, context, expected)`
/// always produces the same `DryRunReport`.
pub fn dry_run_compiled(
    flow: &CompiledFlow,
    context: &FlowContext,
    expected_outcomes: &HashMap<NodeId, ExpectedOutcome>,
) -> DryRunReport {
    let mut steps = Vec::new();
    let mut current = flow.definition.start;

    for _ in 0..MAX_STEPS {
        let node = flow.node(current);
        let kind_label = node_kind_label(&node.kind).to_string();

        match &node.kind {
            NodeKind::Success(_) => {
                steps.push(DryRunStep {
                    node_id: node.id,
                    kind: kind_label,
                    decision: Decision::Taken,
                    reason: "reached success terminal".into(),
                });
                return DryRunReport {
                    steps,
                    terminal: TerminalState::Success,
                    reason: None,
                };
            }
            NodeKind::Failure { reason } => {
                steps.push(DryRunStep {
                    node_id: node.id,
                    kind: kind_label,
                    decision: Decision::Taken,
                    reason: format!("reached failure terminal: {reason}"),
                });
                return DryRunReport {
                    steps,
                    terminal: TerminalState::Failure,
                    reason: None,
                };
            }
            _ => {}
        }

        // Pick the edge condition this node would emit. Render /
        // Broker pause in the executor; for dry-run we collapse them
        // to a synthetic Success (the operator is asking *"what
        // happens after the form is posted?"*). Switch resolves
        // against its literal `condition` label, matching the
        // executor's behavior at `executor.rs::Switch`.
        let (preferred, outcome_label) = match (&node.kind, expected_outcomes.get(&node.id)) {
            (NodeKind::Switch { condition }, _) => (
                EdgeCondition::Status(condition.clone()),
                format!("switch on `{condition}`"),
            ),
            (NodeKind::Authenticator { provider_urn }, Some(o)) => (
                o.as_edge_condition(),
                format!("authenticator `{provider_urn}` — pinned {o:?}"),
            ),
            (NodeKind::Authenticator { provider_urn }, None) => (
                EdgeCondition::Success,
                format!("authenticator `{provider_urn}` — assumed Success"),
            ),
            (NodeKind::Broker { idp_alias }, Some(o)) => (
                o.as_edge_condition(),
                format!("broker `{idp_alias}` — pinned {o:?}"),
            ),
            (NodeKind::Broker { idp_alias }, None) => (
                EdgeCondition::Success,
                format!("broker `{idp_alias}` — assumed Success"),
            ),
            (NodeKind::Render { template }, _) => (
                EdgeCondition::Success,
                format!("render `{template}` — synthetic submit"),
            ),
            // Start / Action / SubFlow advance unconditionally via the
            // default outbound edge.
            (NodeKind::Start(_), _) => (EdgeCondition::Otherwise, "start node".into()),
            (NodeKind::Action { action }, _) => {
                (EdgeCondition::Otherwise, format!("action `{action}`"))
            }
            (NodeKind::SubFlow { flow_alias }, _) => {
                (EdgeCondition::Otherwise, format!("sub-flow `{flow_alias}`"))
            }
            // Terminal nodes were handled above; this arm is unreachable
            // but the borrow checker doesn't know that.
            (NodeKind::Success(_) | NodeKind::Failure { .. }, _) => {
                unreachable!("terminal nodes handled before edge selection")
            }
        };

        // `next_with_guard` matches the executor's edge-selection rule
        // exactly: prefer the explicit `on` match, fall back to a
        // guard-passing `Otherwise`, return `None` if neither
        // matches.
        let next = flow
            .next_with_guard(node.id, &preferred, context)
            .or_else(|| flow.next_with_guard(node.id, &EdgeCondition::Otherwise, context));

        match next {
            Some(target) => {
                steps.push(DryRunStep {
                    node_id: node.id,
                    kind: kind_label,
                    decision: Decision::Taken,
                    reason: outcome_label,
                });
                current = target;
            }
            None => {
                let reason = format!(
                    "no outbound edge from `{}` matches condition `{:?}` with current context",
                    node.id, preferred
                );
                steps.push(DryRunStep {
                    node_id: node.id,
                    kind: kind_label,
                    decision: Decision::Skipped,
                    reason: reason.clone(),
                });
                return DryRunReport {
                    steps,
                    terminal: TerminalState::Incomplete,
                    reason: Some(reason),
                };
            }
        }
    }

    DryRunReport {
        steps,
        terminal: TerminalState::Incomplete,
        reason: Some(format!(
            "walker exceeded {MAX_STEPS} steps without reaching a terminal"
        )),
    }
}

fn node_kind_label(kind: &NodeKind) -> &'static str {
    match kind {
        NodeKind::Start(_) => "start",
        NodeKind::Render { .. } => "render",
        NodeKind::Authenticator { .. } => "authenticator",
        NodeKind::Broker { .. } => "broker",
        NodeKind::Switch { .. } => "switch",
        NodeKind::SubFlow { .. } => "sub-flow",
        NodeKind::Action { .. } => "action",
        NodeKind::Success(_) => "success",
        NodeKind::Failure { .. } => "failure",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::Value;

    use super::*;
    use crate::dsl::{
        Edge, EdgeCondition, FlowDefinition, FlowNode, NodeKind, Requirement, StartNode,
        SuccessNode,
    };
    use geonosis_core::id::{FlowId, RealmId};

    fn node(kind: NodeKind) -> FlowNode {
        FlowNode {
            id: NodeId::new(),
            display_name: String::new(),
            kind,
            requirement: Requirement::Required,
            config: serde_json::Value::Null,
            layout: None,
        }
    }

    fn empty_ctx() -> FlowContext {
        FlowContext::default()
    }

    /// Trivial Start → Success flow runs straight through with
    /// `terminal == Success`.
    #[test]
    fn dry_run_minimum_flow_reaches_success() {
        let start = node(NodeKind::Start(StartNode::default()));
        let success = node(NodeKind::Success(SuccessNode::default()));
        let def = FlowDefinition {
            realm_id: RealmId::new(),
            id: FlowId::new(),
            alias: "x".into(),
            display_name: "X".into(),
            version: 1,
            start: start.id,
            edges: vec![Edge {
                from: start.id,
                to: success.id,
                on: EdgeCondition::Otherwise,
                guard: Default::default(),
            }],
            nodes: vec![start, success],
        };

        let report = dry_run(&def, &empty_ctx(), &HashMap::new()).expect("dry-run ok");
        assert_eq!(report.terminal, TerminalState::Success);
        assert_eq!(report.steps.len(), 2);
        assert_eq!(report.steps[0].kind, "start");
        assert_eq!(report.steps[0].decision, Decision::Taken);
        assert_eq!(report.steps[1].kind, "success");
        assert_eq!(report.steps[1].decision, Decision::Taken);
    }

    /// A two-branch flow: one guard matches the synthetic context,
    /// the other does not. Only the matching path appears in `steps`.
    #[test]
    fn dry_run_branches_along_matching_guard_only() {
        // start --[guard: username=alice]--> success_alice
        //   `--[Otherwise]------------------> failure
        let start = node(NodeKind::Start(StartNode::default()));
        let success_alice = node(NodeKind::Success(SuccessNode::default()));
        let failure = node(NodeKind::Failure {
            reason: "not alice".into(),
        });

        let mut guard_alice = BTreeMap::new();
        guard_alice.insert("context.username".into(), Value::String("alice".into()));

        let def = FlowDefinition {
            realm_id: RealmId::new(),
            id: FlowId::new(),
            alias: "branchy".into(),
            display_name: "Branchy".into(),
            version: 1,
            start: start.id,
            edges: vec![
                Edge {
                    from: start.id,
                    to: success_alice.id,
                    on: EdgeCondition::Otherwise,
                    guard: guard_alice,
                },
                Edge {
                    from: start.id,
                    to: failure.id,
                    on: EdgeCondition::Otherwise,
                    guard: BTreeMap::new(),
                },
            ],
            nodes: vec![start, success_alice.clone(), failure.clone()],
        };

        // Context with username=alice → matching guard → success branch.
        let ctx_alice = FlowContext {
            username: Some("alice".into()),
            ..FlowContext::default()
        };
        let report = dry_run(&def, &ctx_alice, &HashMap::new()).expect("dry-run ok");
        assert_eq!(report.terminal, TerminalState::Success);
        // Last step must be the alice-branch success node — NOT the failure node.
        let last = report.steps.last().unwrap();
        assert_eq!(last.node_id, success_alice.id);

        // Context without username → guard fails → falls through to
        // the unguarded second Otherwise edge → failure terminal.
        let report = dry_run(&def, &empty_ctx(), &HashMap::new()).expect("dry-run ok");
        assert_eq!(report.terminal, TerminalState::Failure);
        let last = report.steps.last().unwrap();
        assert_eq!(last.node_id, failure.id);
    }

    /// When the start node has only one outbound edge and its guard
    /// does not match the synthetic context, the walker stops with
    /// `Incomplete` — there is no edge to take.
    #[test]
    fn dry_run_unmet_guard_at_start_yields_incomplete() {
        let start = node(NodeKind::Start(StartNode::default()));
        let success = node(NodeKind::Success(SuccessNode::default()));

        // Guard that the empty context cannot satisfy.
        let mut guard = BTreeMap::new();
        guard.insert("context.username".into(), Value::String("padme".into()));

        let def = FlowDefinition {
            realm_id: RealmId::new(),
            id: FlowId::new(),
            alias: "stuck".into(),
            display_name: "Stuck".into(),
            version: 1,
            start: start.id,
            edges: vec![Edge {
                from: start.id,
                to: success.id,
                on: EdgeCondition::Otherwise,
                guard,
            }],
            nodes: vec![start.clone(), success],
        };

        let report = dry_run(&def, &empty_ctx(), &HashMap::new()).expect("dry-run ok");
        assert_eq!(report.terminal, TerminalState::Incomplete);
        assert!(report.reason.is_some(), "incomplete should carry a reason");
        // The start node should appear once with Skipped decision.
        assert_eq!(report.steps.len(), 1);
        assert_eq!(report.steps[0].decision, Decision::Skipped);
        assert_eq!(report.steps[0].node_id, start.id);
    }

    /// Pinning an authenticator outcome to `Failure` routes through
    /// the Failure edge — used by the admin UI to ask
    /// "what happens when the password check fails for this user?"
    #[test]
    fn dry_run_honors_pinned_authenticator_outcome() {
        let start = node(NodeKind::Start(StartNode::default()));
        let password = node(NodeKind::Authenticator {
            provider_urn: "builtin:authn:password".into(),
        });
        let success = node(NodeKind::Success(SuccessNode::default()));
        let failure = node(NodeKind::Failure {
            reason: "bad credentials".into(),
        });

        let def = FlowDefinition {
            realm_id: RealmId::new(),
            id: FlowId::new(),
            alias: "pinned".into(),
            display_name: "Pinned".into(),
            version: 1,
            start: start.id,
            edges: vec![
                Edge {
                    from: start.id,
                    to: password.id,
                    on: EdgeCondition::Otherwise,
                    guard: Default::default(),
                },
                Edge {
                    from: password.id,
                    to: success.id,
                    on: EdgeCondition::Success,
                    guard: Default::default(),
                },
                Edge {
                    from: password.id,
                    to: failure.id,
                    on: EdgeCondition::Failure,
                    guard: Default::default(),
                },
            ],
            nodes: vec![start, password.clone(), success.clone(), failure.clone()],
        };

        // Default: authenticator assumed Success → reach success.
        let report = dry_run(&def, &empty_ctx(), &HashMap::new()).expect("dry-run ok");
        assert_eq!(report.terminal, TerminalState::Success);
        assert_eq!(report.steps.last().unwrap().node_id, success.id);

        // Pinned Failure → reach failure terminal.
        let mut pins = HashMap::new();
        pins.insert(password.id, ExpectedOutcome::Failure);
        let report = dry_run(&def, &empty_ctx(), &pins).expect("dry-run ok");
        assert_eq!(report.terminal, TerminalState::Failure);
        assert_eq!(report.steps.last().unwrap().node_id, failure.id);
    }

    /// The report serializes to a stable JSON shape — guards against
    /// renaming a public field without updating the admin contract.
    #[test]
    fn dry_run_report_json_shape_is_stable() {
        let start = node(NodeKind::Start(StartNode::default()));
        let success = node(NodeKind::Success(SuccessNode::default()));
        let def = FlowDefinition {
            realm_id: RealmId::new(),
            id: FlowId::new(),
            alias: "json".into(),
            display_name: "Json".into(),
            version: 1,
            start: start.id,
            edges: vec![Edge {
                from: start.id,
                to: success.id,
                on: EdgeCondition::Otherwise,
                guard: Default::default(),
            }],
            nodes: vec![start, success],
        };
        let report = dry_run(&def, &empty_ctx(), &HashMap::new()).expect("dry-run ok");
        let json = serde_json::to_value(&report).unwrap();
        assert!(json.get("steps").is_some());
        assert_eq!(json["terminal"], serde_json::json!("success"));
        let steps = json["steps"].as_array().unwrap();
        assert!(!steps.is_empty());
        assert!(steps[0].get("node_id").is_some());
        assert!(steps[0].get("decision").is_some());
        assert_eq!(steps[0]["decision"], serde_json::json!("taken"));
    }

    /// Builtin `browser` flow walks to Success when the cookie SSO
    /// authenticator is assumed to succeed (the default).
    #[test]
    fn dry_run_browser_builtin_reaches_success() {
        let realm = RealmId::new();
        let def = crate::builtin::browser(realm);
        let report = dry_run(&def, &empty_ctx(), &HashMap::new()).expect("dry-run ok");
        assert_eq!(report.terminal, TerminalState::Success);
        // Every step must have a non-empty `kind`.
        assert!(report.steps.iter().all(|s| !s.kind.is_empty()));
    }
}
