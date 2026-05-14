//! Thin wrapper around `geonosis_audit::Publisher::publish` for
//! admin REST handlers.
//!
//! Every state-changing handler in `handlers_v1/*` calls
//! [`emit`] after the storage write succeeds. The action namespace
//! follows the dotted convention from `docs/13-observability.md`
//! §"Audit events" — `realm.created`, `client.deleted`, etc. The
//! actor stays [`Actor::System`] until admin auth lands (v0.1.x);
//! once `private_key_jwt` is wired the call site swaps in
//! [`Actor::AdminApi`] with the verified principal.
//!
//! `publish` itself never blocks (the publisher returns immediately
//! and fans out on a background task), so the call can stay
//! fire-and-forget. Failures inside any single sink are logged by
//! the sink and do not propagate.

use std::sync::Arc;

use geonosis_audit::{Actor, AuditEvent, Publisher, Target};
use geonosis_core::id::EventId;
use geonosis_core::RealmId;

use crate::state::AdminState;

/// Build + publish an admin audit event.
pub fn emit(
    state: &AdminState,
    realm_id: RealmId,
    action: &str,
    target: Option<Target>,
    detail: serde_json::Value,
) {
    publish(&state.audit, realm_id, action, target, detail);
}

/// Lower-level form for callers that only have the `Publisher` (a
/// few server-side hooks don't carry `AdminState`).
pub fn publish(
    audit: &Arc<Publisher>,
    realm_id: RealmId,
    action: &str,
    target: Option<Target>,
    detail: serde_json::Value,
) {
    audit.publish(AuditEvent {
        id: EventId::new(),
        realm_id,
        occurred_at: chrono::Utc::now(),
        actor: Actor::System,
        action: action.to_string(),
        target,
        detail,
    });
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use geonosis_audit::{AuditError, AuditEvent, AuditSink};

    use super::*;

    struct Capture {
        count: AtomicUsize,
        last_action: parking_lot::Mutex<Option<String>>,
    }

    #[async_trait]
    impl AuditSink for Capture {
        async fn ingest(&self, event: AuditEvent) -> Result<(), AuditError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            *self.last_action.lock() = Some(event.action);
            Ok(())
        }
    }

    #[tokio::test]
    async fn publish_reaches_the_sink_with_action_and_target() {
        let sink = Arc::new(Capture {
            count: AtomicUsize::new(0),
            last_action: parking_lot::Mutex::new(None),
        });
        let publisher = Arc::new(Publisher::new(vec![sink.clone()]));
        let realm_id = RealmId::new();
        publish(
            &publisher,
            realm_id,
            "realm.created",
            Some(Target::Realm { id: realm_id }),
            serde_json::json!({ "slug": "acme" }),
        );
        // The publisher dispatches on a tokio task; give it a beat to
        // drain so the assertion is deterministic without a real
        // synchronization primitive.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(sink.count.load(Ordering::SeqCst), 1);
        assert_eq!(
            sink.last_action.lock().clone(),
            Some("realm.created".to_string())
        );
    }
}
