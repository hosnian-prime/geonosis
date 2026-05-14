//! Audit event taxonomy + sink fan-out.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;

use geonosis_core::id::{ClientId, EventId, FlowId, KeyId, RealmId, SessionId, UserId};

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(feature = "webhook")]
pub mod webhook;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: EventId,
    pub realm_id: RealmId,
    pub occurred_at: DateTime<Utc>,
    pub actor: Actor,
    pub action: String,
    pub target: Option<Target>,
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Actor {
    User { id: UserId, ip: Option<IpAddr> },
    Client { id: ClientId },
    System,
    AdminApi { user_id: UserId, ip: IpAddr },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Target {
    User { id: UserId },
    Client { id: ClientId },
    Realm { id: RealmId },
    Flow { id: FlowId },
    Key { id: KeyId },
    Session { id: SessionId },
    Other { entity: String, id: String },
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("sink dropped")]
    SinkDropped,
    #[error("backend: {0}")]
    Backend(String),
}

/// Pluggable sink. v0.1: `Postgres` (in-process trait method) + `Webhook`
/// (tokio task). Additional sinks (Kafka, CloudWatch) land in v0.2.
#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn ingest(&self, event: AuditEvent) -> Result<(), AuditError>;
}

/// Fan-out audit publisher. Producers call `publish`; the publisher
/// dispatches to all sinks concurrently. Failures are logged, not
/// returned — audit must never block the request critical path.
pub struct Publisher {
    sinks: Vec<Arc<dyn AuditSink>>,
    tx: mpsc::UnboundedSender<AuditEvent>,
}

impl Publisher {
    pub fn new(sinks: Vec<Arc<dyn AuditSink>>) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<AuditEvent>();
        let sinks_c = sinks.clone();
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                for s in &sinks_c {
                    if let Err(e) = s.ingest(ev.clone()).await {
                        tracing::warn!(error = %e, "audit sink ingest failed");
                    }
                }
            }
        });
        Self { sinks, tx }
    }

    pub fn publish(&self, event: AuditEvent) {
        if let Err(e) = self.tx.send(event) {
            tracing::warn!(error = %e, "audit publish dropped (channel closed)");
        }
    }

    pub fn sink_count(&self) -> usize {
        self.sinks.len()
    }
}

/// Action taxonomy. Use dotted namespaces to keep filtering cheap.
pub mod action {
    pub const LOGIN_SUCCESS: &str = "login.success";
    pub const LOGIN_FAILURE: &str = "login.failure";
    pub const LOGOUT_LOCAL: &str = "logout.local";
    pub const LOGOUT_FRONTCHANNEL: &str = "logout.frontchannel";
    pub const LOGOUT_BACKCHANNEL: &str = "logout.backchannel";

    pub const TOKEN_ISSUED: &str = "token.issued";
    pub const TOKEN_REFRESHED: &str = "token.refreshed";
    pub const TOKEN_REUSE: &str = "token.reuse";
    pub const TOKEN_REVOKED: &str = "token.revoked";
    pub const TOKEN_INTROSPECT: &str = "token.introspect";

    pub const CONSENT_GRANTED: &str = "consent.granted";
    pub const CONSENT_DENIED: &str = "consent.denied";
    pub const CONSENT_REVOKED: &str = "consent.revoked";

    pub const USER_CREATED: &str = "user.created";
    pub const USER_UPDATED: &str = "user.updated";
    pub const USER_DELETED: &str = "user.deleted";

    pub const CLIENT_CREATED: &str = "client.created";
    pub const FLOW_UPDATED: &str = "flow.updated";
    pub const KEY_ROTATED: &str = "key.rotated";

    pub const AGENT_CREATED: &str = "agent.created";
    pub const AGENT_REVOKED: &str = "agent.revoked";

    pub const SAML_ASSERTION_ISSUED: &str = "saml.assertion-issued";
    pub const BROKER_LOGIN: &str = "broker.login";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counter(AtomicUsize);

    #[async_trait]
    impl AuditSink for Counter {
        async fn ingest(&self, _event: AuditEvent) -> Result<(), AuditError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn publisher_fans_out_to_every_sink() {
        let a = Arc::new(Counter(AtomicUsize::new(0)));
        let b = Arc::new(Counter(AtomicUsize::new(0)));
        let pub_ = Publisher::new(vec![a.clone(), b.clone()]);
        for _ in 0..3 {
            pub_.publish(AuditEvent {
                id: EventId::new(),
                realm_id: RealmId::new(),
                occurred_at: Utc::now(),
                actor: Actor::System,
                action: action::TOKEN_ISSUED.into(),
                target: None,
                detail: serde_json::json!({}),
            });
        }
        // Let the background task drain.
        for _ in 0..20 {
            tokio::task::yield_now().await;
            if a.0.load(Ordering::SeqCst) == 3 && b.0.load(Ordering::SeqCst) == 3 {
                break;
            }
        }
        assert_eq!(a.0.load(Ordering::SeqCst), 3);
        assert_eq!(b.0.load(Ordering::SeqCst), 3);
    }
}
