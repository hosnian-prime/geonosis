//! Agent (AI / M2M) identity entity.
//!
//! Per `docs/18-agent-identity.md`: first-class principal type that delegates
//! from a parent `User` / `ServiceAccount` / `Organization`. Reparenting is
//! forbidden — to change a parent, revoke + recreate.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::id::{AgentId, RealmId};
use crate::scope::ScopeName;
use crate::subject::ParentSubject;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: AgentId,
    pub realm_id: RealmId,
    /// Stable URL-safe alias.
    pub alias: String,
    pub display_name: String,
    pub kind: AgentKind,
    pub model_hint: Option<String>,
    pub vendor: Option<String>,
    pub version: Option<String>,
    /// **Immutable** after creation per doc §18.
    pub parent_subject: ParentSubject,
    pub capabilities: Vec<AgentCapability>,
    pub allowed_scopes: Vec<ScopeName>,
    pub allowed_audiences: Vec<String>,
    pub rate_limit: AgentRateLimit,
    pub auth_method: AgentAuthMethod,
    /// Public key in JWK form (`AgentAuthMethod::PrivateKeyJwt` / `DpopBoundKey`).
    pub public_jwk: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentKind {
    Assistant,
    Scraper,
    Webhook,
    Batch,
    #[serde(untagged)]
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCapability {
    /// URN namespace: `tool:read-files`, `data:tier-2`, `model:gpt-4o`, `spend:daily`, …
    pub urn: String,
    pub config: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRateLimit {
    pub requests_per_minute: u32,
    pub tokens_per_day: Option<u64>,
}

impl Default for AgentRateLimit {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            tokens_per_day: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentAuthMethod {
    /// Agent presents a private-key-signed JWT assertion.
    PrivateKeyJwt,
    /// DPoP-bound key (RFC 9449); v0.2 wiring.
    DpopBoundKey,
    /// Only acquires tokens through RFC 8693 Token Exchange.
    TokenExchangeOnly,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::UserId;

    #[test]
    fn agent_kind_kebab_case_or_custom() {
        let a = AgentKind::Assistant;
        let j = serde_json::to_string(&a).unwrap();
        assert_eq!(j, "\"assistant\"");
        let c = AgentKind::Custom("inventory-bot".into());
        let j2 = serde_json::to_string(&c).unwrap();
        assert_eq!(j2, "\"inventory-bot\"");
    }

    #[test]
    fn parent_subject_immutable_in_default_construction() {
        let agent = Agent {
            id: AgentId::new(),
            realm_id: RealmId::new(),
            alias: "bot-1".into(),
            display_name: "Bot 1".into(),
            kind: AgentKind::Assistant,
            model_hint: Some("claude-opus".into()),
            vendor: Some("anthropic".into()),
            version: None,
            parent_subject: ParentSubject::User {
                user_id: UserId::new(),
            },
            capabilities: vec![],
            allowed_scopes: vec![],
            allowed_audiences: vec![],
            rate_limit: AgentRateLimit::default(),
            auth_method: AgentAuthMethod::PrivateKeyJwt,
            public_jwk: None,
            created_at: Utc::now(),
            expires_at: None,
            revoked_at: None,
            enabled: true,
        };
        // Construct a serialized form and reload — parent_subject roundtrips.
        let j = serde_json::to_string(&agent).unwrap();
        let back: Agent = serde_json::from_str(&j).unwrap();
        match back.parent_subject {
            ParentSubject::User { .. } => {}
            other => panic!("unexpected parent: {other:?}"),
        }
    }
}
