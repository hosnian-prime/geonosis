//! In-progress flow state.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use geonosis_core::id::{FlowId, FlowStateId, NodeId, RealmId};

/// One row of audit history kept on `FlowState`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowHistoryEntry {
    pub node: NodeId,
    pub at: DateTime<Utc>,
    /// Outcome label written by the executor (`success` / `failure` /
    /// `redirect` / `render`).
    pub outcome: String,
}

/// CSRF token bound to a `FlowState`. Re-issued on every render to prevent
/// replay. We do not use the session-level CSRF for flow steps.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CsrfToken(pub String);

/// Per-flow context: stash of values gathered across steps. Cleared on
/// terminal Success/Failure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowContext {
    /// Resolved username, when known.
    pub username: Option<String>,
    /// The user_id when found (string form for round-trip simplicity).
    pub user_id: Option<String>,
    /// Client this flow runs under. Populated by the OAuth /authorize
    /// handler when constructing the FlowState; authenticators need
    /// this to build their `AuthnContext`. String form so the JSON
    /// shape round-trips without typed dependencies on the flow side.
    pub client_id: Option<String>,
    /// AMR collected so far (e.g. `["pwd"]`, then `["pwd","otp"]` after MFA).
    pub amr: Vec<String>,
    /// Authentication-strength bumps (when each step asserts a level).
    pub authn_level: i32,
    /// Per-step config-derived locals (form errors, last attempted username).
    pub locals: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowState {
    pub id: FlowStateId,
    pub realm_id: RealmId,
    pub flow_id: FlowId,
    pub flow_version: i32,
    pub current_node: NodeId,
    pub history: Vec<FlowHistoryEntry>,
    pub context: FlowContext,
    pub started_at: DateTime<Utc>,
    pub last_activity_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub csrf_token: CsrfToken,
}

impl FlowState {
    pub fn fresh(
        realm: RealmId,
        flow_id: FlowId,
        flow_version: i32,
        start: NodeId,
        ttl: std::time::Duration,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: FlowStateId::new(),
            realm_id: realm,
            flow_id,
            flow_version,
            current_node: start,
            history: vec![],
            context: FlowContext::default(),
            started_at: now,
            last_activity_at: now,
            expires_at: now + chrono::Duration::from_std(ttl).unwrap_or_default(),
            csrf_token: CsrfToken(geonosis_core::id::CodeId::new_random().0),
        }
    }
}
