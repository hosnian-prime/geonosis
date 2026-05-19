//! Audit emit helpers for protocol handlers (OIDC, OAuth, SAML).
//!
//! Mirrors `geonosis-admin-ui/src/audit_emit.rs` but uses `AppState`
//! instead of `AdminState`. Fire-and-forget: `Publisher` dispatches on
//! a background task so audit never blocks the request path.

use geonosis_audit::{Actor, AuditEvent, Target};
use geonosis_core::id::EventId;
use geonosis_core::{RealmId, UserId};

use crate::state::AppState;

/// Emit a protocol-layer audit event with a user actor.
pub fn emit_user(
    state: &AppState,
    realm_id: RealmId,
    user_id: UserId,
    action: &str,
    target: Option<Target>,
    detail: serde_json::Value,
) {
    state.audit.publish(AuditEvent {
        id: EventId::new(),
        realm_id,
        occurred_at: chrono::Utc::now(),
        actor: Actor::User {
            id: user_id,
            ip: None,
        },
        action: action.to_string(),
        target,
        detail,
    });
}

/// Emit a protocol-layer audit event with the system actor (e.g.
/// client-credentials grant where no user is involved).
pub fn emit_system(
    state: &AppState,
    realm_id: RealmId,
    action: &str,
    target: Option<Target>,
    detail: serde_json::Value,
) {
    state.audit.publish(AuditEvent {
        id: EventId::new(),
        realm_id,
        occurred_at: chrono::Utc::now(),
        actor: Actor::System,
        action: action.to_string(),
        target,
        detail,
    });
}

/// Emit a protocol-layer audit event with a client actor.
pub fn emit_client(
    state: &AppState,
    realm_id: RealmId,
    client_id: geonosis_core::id::ClientId,
    action: &str,
    target: Option<Target>,
    detail: serde_json::Value,
) {
    state.audit.publish(AuditEvent {
        id: EventId::new(),
        realm_id,
        occurred_at: chrono::Utc::now(),
        actor: Actor::Client { id: client_id },
        action: action.to_string(),
        target,
        detail,
    });
}
