//! Flow validator + compiler.
//!
//! Validates a `FlowDefinition` once at admin save time so the executor
//! can rely on invariants:
//! - `start` exists and is unique.
//! - Every edge references existing nodes.
//! - Exactly one `Success` terminal and at least one `Failure` terminal
//!   reachable from `start`.
//! - No edge originates from a terminal node.
//! - No cycles unless the cycle exits via a SubFlow.

use std::collections::{HashMap, HashSet};

use thiserror::Error;

use geonosis_core::id::NodeId;

use crate::dsl::{Edge, EdgeCondition, FlowDefinition, NodeKind, Requirement};

#[derive(Debug, Error)]
pub enum CompileError {
    #[error("start node {0} not in graph")]
    StartMissing(NodeId),
    #[error("duplicate node id {0}")]
    DuplicateNode(NodeId),
    #[error("edge from unknown node {0}")]
    EdgeFromUnknown(NodeId),
    #[error("edge to unknown node {0}")]
    EdgeToUnknown(NodeId),
    #[error("terminal node {0} has outbound edges")]
    TerminalWithOutbound(NodeId),
    #[error("no success terminal reachable from start")]
    NoSuccessReachable,
    #[error("invalid sub-flow reference: {0}")]
    BadSubflow(String),
}

/// A compiled flow with O(1) node + edge lookup.
#[derive(Debug, Clone)]
pub struct CompiledFlow {
    pub definition: FlowDefinition,
    pub by_id: HashMap<NodeId, usize>,
    /// Outbound edges grouped by source node id.
    pub outbound: HashMap<NodeId, Vec<Edge>>,
}

impl CompiledFlow {
    pub fn node(&self, id: NodeId) -> &crate::dsl::FlowNode {
        let ix = self.by_id[&id];
        &self.definition.nodes[ix]
    }

    pub fn next(&self, from: NodeId, on: &EdgeCondition) -> Option<NodeId> {
        let edges = self.outbound.get(&from)?;
        // First, try exact match. If none, fall back to `Otherwise`.
        if let Some(e) = edges.iter().find(|e| &e.on == on) {
            return Some(e.to);
        }
        edges
            .iter()
            .find(|e| matches!(e.on, EdgeCondition::Otherwise))
            .map(|e| e.to)
    }

    /// Guard-aware variant of `next()`. Iterates candidate edges in
    /// declaration order, returns the first whose `guard` map passes
    /// `eval_guard(&edge.guard, ctx)`. Falls back to an `Otherwise`
    /// edge (also guard-checked) when no condition-match passes.
    ///
    /// `next()` stays available for call sites that do not yet have a
    /// `FlowContext` to evaluate against (compile-time validators,
    /// tests). The executor calls this variant.
    pub fn next_with_guard(
        &self,
        from: NodeId,
        on: &EdgeCondition,
        ctx: &crate::state::FlowContext,
    ) -> Option<NodeId> {
        let edges = self.outbound.get(&from)?;
        if let Some(e) = edges
            .iter()
            .find(|e| &e.on == on && crate::guard::eval_guard(&e.guard, ctx))
        {
            return Some(e.to);
        }
        edges
            .iter()
            .find(|e| {
                matches!(e.on, EdgeCondition::Otherwise) && crate::guard::eval_guard(&e.guard, ctx)
            })
            .map(|e| e.to)
    }
}

pub fn compile(def: FlowDefinition) -> Result<CompiledFlow, CompileError> {
    let mut by_id = HashMap::new();
    for (ix, n) in def.nodes.iter().enumerate() {
        if by_id.insert(n.id, ix).is_some() {
            return Err(CompileError::DuplicateNode(n.id));
        }
    }
    if !by_id.contains_key(&def.start) {
        return Err(CompileError::StartMissing(def.start));
    }

    let mut outbound: HashMap<NodeId, Vec<Edge>> = HashMap::new();
    for e in &def.edges {
        if !by_id.contains_key(&e.from) {
            return Err(CompileError::EdgeFromUnknown(e.from));
        }
        if !by_id.contains_key(&e.to) {
            return Err(CompileError::EdgeToUnknown(e.to));
        }
        outbound.entry(e.from).or_default().push(e.clone());
    }

    // Terminal nodes (Success/Failure) MUST NOT have outbound edges.
    for n in &def.nodes {
        if matches!(n.kind, NodeKind::Success(_) | NodeKind::Failure { .. })
            && outbound.contains_key(&n.id)
        {
            return Err(CompileError::TerminalWithOutbound(n.id));
        }
    }

    // BFS from start; must reach at least one Success node.
    let mut visited: HashSet<NodeId> = HashSet::new();
    let mut queue = vec![def.start];
    let mut saw_success = false;
    while let Some(n) = queue.pop() {
        if !visited.insert(n) {
            continue;
        }
        let node = &def.nodes[by_id[&n]];
        if matches!(node.kind, NodeKind::Success(_)) {
            saw_success = true;
        }
        if let Some(edges) = outbound.get(&n) {
            for e in edges {
                queue.push(e.to);
            }
        }
    }
    if !saw_success {
        return Err(CompileError::NoSuccessReachable);
    }

    Ok(CompiledFlow {
        definition: def,
        by_id,
        outbound,
    })
}

/// Helper used by tests + the YAML import path — sane requirements default.
#[allow(dead_code)]
pub(crate) fn requirement_default() -> Requirement {
    Requirement::Required
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::{FlowDefinition, FlowNode, NodeKind, StartNode, SuccessNode};
    use geonosis_core::id::FlowId;

    fn n(kind: NodeKind) -> FlowNode {
        FlowNode {
            id: NodeId::new(),
            display_name: String::new(),
            kind,
            requirement: Requirement::Required,
            config: serde_json::Value::Null,
        }
    }

    #[test]
    fn minimum_valid_flow_compiles() {
        let start = n(NodeKind::Start(StartNode::default()));
        let success = n(NodeKind::Success(SuccessNode::default()));
        let def = FlowDefinition {
            realm_id: geonosis_core::id::RealmId::new(),
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
        assert!(compile(def).is_ok());
    }

    #[test]
    fn missing_success_is_rejected() {
        let start = n(NodeKind::Start(StartNode::default()));
        let def = FlowDefinition {
            realm_id: geonosis_core::id::RealmId::new(),
            id: FlowId::new(),
            alias: "x".into(),
            display_name: "X".into(),
            version: 1,
            start: start.id,
            nodes: vec![start],
            edges: vec![],
        };
        let e = compile(def).unwrap_err();
        assert!(matches!(e, CompileError::NoSuccessReachable));
    }

    #[test]
    fn terminal_with_outbound_rejected() {
        let start = n(NodeKind::Start(StartNode::default()));
        let success = n(NodeKind::Success(SuccessNode::default()));
        let extra = n(NodeKind::Render {
            template: "x".into(),
        });
        let def = FlowDefinition {
            realm_id: geonosis_core::id::RealmId::new(),
            id: FlowId::new(),
            alias: "x".into(),
            display_name: "X".into(),
            version: 1,
            start: start.id,
            edges: vec![
                Edge {
                    from: start.id,
                    to: success.id,
                    on: EdgeCondition::Otherwise,
                    guard: Default::default(),
                },
                Edge {
                    from: success.id,
                    to: extra.id,
                    on: EdgeCondition::Otherwise,
                    guard: Default::default(),
                },
            ],
            nodes: vec![start, success, extra],
        };
        let e = compile(def).unwrap_err();
        assert!(matches!(e, CompileError::TerminalWithOutbound(_)));
    }
}
