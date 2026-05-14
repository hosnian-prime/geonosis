//! Built-in `risk-score` authenticator — returns a discrete risk
//! decision for downstream `Switch` nodes to route on.
//!
//! v0.1 ships the **discrete-decision API** only — the heuristic /
//! anomaly engine (velocity, geo, device fingerprint) lands in v0.3
//! per `docs/14-roadmap.md`. v0.1 sources its decision from:
//! 1. The node config's `force` value, if present (test/dev override).
//! 2. The user's `risk:level` attribute, if set.
//! 3. A default of `RiskDecision::Low`.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;

use geonosis_core::attribute::AttributeValue;

use crate::context::AuthnContext;
use crate::traits::{AuthnError, AuthnInput, AuthnOutput, Authenticator, FailureKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskDecision {
    Low,
    Medium,
    High,
}

impl RiskDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            _ => None,
        }
    }
}

pub struct RiskScoreAuthenticator {
    /// Set in node config (`force: "high"`) for testing or admin override.
    pub force: Option<RiskDecision>,
    /// When `true`, a `High` decision returns `Failure(HighRisk)` so the
    /// flow can short-circuit. When `false`, the authenticator always
    /// succeeds and the surrounding `Switch` node decides routing via
    /// `context.locals["risk:decision"]`.
    pub block_high: bool,
}

impl RiskScoreAuthenticator {
    pub fn new() -> Self {
        Self {
            force: None,
            block_high: false,
        }
    }

    pub fn with_force(mut self, d: RiskDecision) -> Self {
        self.force = Some(d);
        self
    }

    pub fn block_on_high(mut self, b: bool) -> Self {
        self.block_high = b;
        self
    }
}

impl Default for RiskScoreAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Authenticator for RiskScoreAuthenticator {
    fn provider_id(&self) -> &'static str {
        "builtin:authn:risk-score"
    }

    async fn process(
        &self,
        ctx: &mut AuthnContext,
        _input: AuthnInput,
    ) -> Result<AuthnOutput, AuthnError> {
        let decision = if let Some(d) = self.force {
            d
        } else if let Some(uid) = ctx.user_id {
            let user = ctx
                .storage
                .get_user(ctx.realm_id, uid)
                .await
                .map_err(|e| AuthnError::Storage(e.to_string()))?;
            user.attributes
                .get("risk:level")
                .and_then(|v| match v {
                    AttributeValue::String(s) => RiskDecision::parse(s),
                    _ => None,
                })
                .unwrap_or(RiskDecision::Low)
        } else {
            RiskDecision::Low
        };

        ctx.locals
            .insert("risk:decision".into(), json!(decision.as_str()));

        if self.block_high && decision == RiskDecision::High {
            return Ok(AuthnOutput::Failure(FailureKind::HighRisk));
        }
        Ok(AuthnOutput::Success {
            credentials_satisfied: vec![],
            amr: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::sync::Arc;

    use geonosis_core::{
        AccessTokenType, ClientAuthMethod, ClientId, ClientKind, ConsentPolicy, FlowBinding,
        GrantPolicy, PersonName, RealmId, User, UserId,
    };
    use geonosis_storage::{MemoryStorage, Storage};

    async fn fixture(level: Option<&str>) -> AuthnContext {
        let realm = RealmId::new();
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let mut u = User {
            id: UserId::new(),
            realm_id: realm,
            username: "ada".into(),
            email: None,
            email_verified: false,
            name: Some(PersonName::default()),
            credentials: vec![],
            federation: None,
            attributes: Default::default(),
            required_actions: vec![],
            required_flow: None,
            organizations: vec![],
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        if let Some(l) = level {
            u.attributes
                .insert("risk:level".into(), AttributeValue::String(l.into()));
        }
        let uid = u.id;
        storage.create_user(u).await.unwrap();
        AuthnContext {
            realm_id: realm,
            client: Arc::new(geonosis_core::Client {
                id: ClientId::new(),
                realm_id: realm,
                client_id: "c".into(),
                display_name: None,
                kind: ClientKind::Public,
                grants: GrantPolicy::public_app(),
                auth_method: ClientAuthMethod::None,
                flow_binding: FlowBinding::default(),
                default_scopes: vec![],
                optional_scopes: vec![],
                redirect_uris: vec![],
                post_logout_redirect_uris: vec![],
                web_origins: vec![],
                access_token_type: AccessTokenType::Jwt,
                consent: ConsentPolicy::default(),
                access_token_lifespan: None,
                refresh_token_lifespan: None,
                access_token_signing_alg: None,
                front_channel_logout_enabled: false,
                backchannel_logout_url: None,
                client_authentication_keys: vec![],
                pairwise_sub_algorithm: None,
                enabled: true,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }),
            storage,
            realm_hash_key: [0u8; 32],
            user_id: Some(uid),
            session_id: None,
            amr: vec![],
            locals: Default::default(),
            now: Utc::now(),
        }
    }

    #[tokio::test]
    async fn defaults_to_low_and_stamps_locals() {
        let mut ctx = fixture(None).await;
        RiskScoreAuthenticator::new().process(&mut ctx, AuthnInput::Init).await.unwrap();
        assert_eq!(ctx.locals.get("risk:decision").unwrap(), &json!("low"));
    }

    #[tokio::test]
    async fn user_attribute_overrides_default() {
        let mut ctx = fixture(Some("medium")).await;
        RiskScoreAuthenticator::new().process(&mut ctx, AuthnInput::Init).await.unwrap();
        assert_eq!(ctx.locals.get("risk:decision").unwrap(), &json!("medium"));
    }

    #[tokio::test]
    async fn force_param_takes_precedence() {
        let mut ctx = fixture(Some("low")).await;
        RiskScoreAuthenticator::new()
            .with_force(RiskDecision::High)
            .process(&mut ctx, AuthnInput::Init)
            .await
            .unwrap();
        assert_eq!(ctx.locals.get("risk:decision").unwrap(), &json!("high"));
    }

    #[tokio::test]
    async fn block_high_returns_failure_high_risk() {
        let mut ctx = fixture(None).await;
        let out = RiskScoreAuthenticator::new()
            .with_force(RiskDecision::High)
            .block_on_high(true)
            .process(&mut ctx, AuthnInput::Init)
            .await
            .unwrap();
        assert!(matches!(out, AuthnOutput::Failure(FailureKind::HighRisk)));
    }
}
