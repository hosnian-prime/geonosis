//! Flow DSL types — round-trip JSON / YAML serializable.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use geonosis_core::id::{FlowId, NodeId, RealmId};

/// The persisted, version-snapshotted form of a flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowDefinition {
    pub id: FlowId,
    pub realm_id: RealmId,
    pub alias: String,
    pub display_name: String,
    pub version: i32,
    pub start: NodeId,
    pub nodes: Vec<FlowNode>,
    pub edges: Vec<Edge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowNode {
    pub id: NodeId,
    pub display_name: String,
    pub kind: NodeKind,
    pub requirement: Requirement,
    /// Per-node config (validator selection, render template name, sub-flow alias, …).
    #[serde(default)]
    pub config: serde_json::Value,
    /// Optional canvas layout hint persisted by the visual flow editor.
    ///
    /// The runtime executor ignores this field entirely — it is admin-UI
    /// metadata. Absent on flows authored before the editor existed; the
    /// canvas falls back to a deterministic grid layout when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout: Option<NodeLayout>,
}

/// Editor-only canvas coordinates for a node. Coordinates are in the
/// canvas viewBox (logical pixels); the canvas component is responsible
/// for clamping into the visible area.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct NodeLayout {
    pub x: f32,
    pub y: f32,
}

/// What a node does.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum NodeKind {
    Start(StartNode),
    Render { template: String },
    Authenticator { provider_urn: String },
    Broker { idp_alias: String },
    Switch { condition: String },
    SubFlow { flow_alias: String },
    Action { action: String },
    Success(SuccessNode),
    Failure { reason: String },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StartNode {
    /// Optional preconditions evaluated by the executor before entering
    /// the first downstream node.
    pub require_session: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SuccessNode {
    /// Optional ACR value to emit on token claims.
    pub acr: Option<String>,
    /// Set if the success terminal forces step-up to a stronger authn level.
    pub step_up_required: bool,
}

/// Per-step requirement (Keycloak-equivalent semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Requirement {
    /// MUST succeed.
    Required,
    /// MAY succeed; failure proceeds.
    Optional,
    /// At least one Alternative in a peer set must succeed.
    Alternative,
    /// Skipped.
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    #[serde(default)]
    pub on: EdgeCondition,
    #[serde(default)]
    pub guard: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum EdgeCondition {
    /// Default outbound — taken when no other condition matches.
    #[default]
    Otherwise,
    /// Taken when the previous node returned Success.
    Success,
    /// Taken when the previous node returned Failure.
    Failure,
    /// Taken when the previous node returned the named status code.
    Status(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_definition_roundtrips_through_json() {
        let f = FlowDefinition {
            realm_id: geonosis_core::id::RealmId::new(),
            id: FlowId::new(),
            alias: "browser".into(),
            display_name: "Browser".into(),
            version: 1,
            start: NodeId::new(),
            nodes: vec![],
            edges: vec![],
        };
        let s = serde_json::to_string(&f).unwrap();
        let back: FlowDefinition = serde_json::from_str(&s).unwrap();
        assert_eq!(back.alias, "browser");
        assert_eq!(back.version, 1);
    }

    #[test]
    fn node_kind_serializes_with_discriminator() {
        let n = NodeKind::Authenticator {
            provider_urn: "builtin:authn:password".into(),
        };
        let j = serde_json::to_value(&n).unwrap();
        assert_eq!(j.get("kind").and_then(|v| v.as_str()), Some("authenticator"));
        assert_eq!(j.get("provider_urn").and_then(|v| v.as_str()), Some("builtin:authn:password"));
    }

    #[test]
    fn requirement_kebab_case() {
        assert_eq!(
            serde_json::to_string(&Requirement::Alternative).unwrap(),
            "\"alternative\""
        );
    }
}
