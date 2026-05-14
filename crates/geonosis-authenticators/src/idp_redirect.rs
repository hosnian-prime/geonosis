//! Built-in `idp-redirect` authenticator — begins a broker-step.
//!
//! Per `docs/06-auth-flows.md`: starts a `broker-step` (the actual
//! brokering lives in `geonosis-broker` + `Flow::Broker` node). v0.1
//! returns `Continue { render }` pointing to the broker redirect page,
//! which the executor recognises and translates into a 302 to the IdP
//! authorize endpoint.
//!
//! Real broker dispatch (OIDC RP / SAML SP runtime) lands with the
//! broker-runtime PR. v0.1 carries the **node-level contract** and a
//! deterministic locals shape (`idp_alias`, `return_uri`).

use async_trait::async_trait;
use serde_json::json;

use crate::context::AuthnContext;
use crate::traits::{
    AuthnError, AuthnInput, AuthnOutput, Authenticator, FailureKind, RenderInstruction,
};

pub struct IdpRedirectAuthenticator {
    pub idp_alias: String,
}

impl IdpRedirectAuthenticator {
    pub fn new(idp_alias: impl Into<String>) -> Self {
        Self {
            idp_alias: idp_alias.into(),
        }
    }
}

#[async_trait]
impl Authenticator for IdpRedirectAuthenticator {
    fn provider_id(&self) -> &'static str {
        "builtin:authn:idp-redirect"
    }

    async fn process(
        &self,
        ctx: &mut AuthnContext,
        _input: AuthnInput,
    ) -> Result<AuthnOutput, AuthnError> {
        if self.idp_alias.is_empty() {
            return Ok(AuthnOutput::Failure(FailureKind::BrokerError(
                "idp alias unconfigured".into(),
            )));
        }
        ctx.locals.insert("idp_alias".into(), json!(self.idp_alias));
        Ok(AuthnOutput::Continue {
            render: RenderInstruction::new("login/idp-redirect.html")
                .with("idp_alias", json!(self.idp_alias)),
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
        GrantPolicy, RealmId,
    };
    use geonosis_storage::{MemoryStorage, Storage};

    async fn fixture() -> AuthnContext {
        let realm = RealmId::new();
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
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
            user_id: None,
            session_id: None,
            amr: vec![],
            locals: Default::default(),
            now: Utc::now(),
        }
    }

    #[tokio::test]
    async fn renders_redirect_template_with_alias() {
        let mut ctx = fixture().await;
        let out = IdpRedirectAuthenticator::new("google")
            .process(&mut ctx, AuthnInput::Init)
            .await
            .unwrap();
        match out {
            AuthnOutput::Continue { render } => {
                assert_eq!(render.template, "login/idp-redirect.html");
                assert_eq!(render.locals.get("idp_alias"), Some(&json!("google")));
            }
            other => panic!("expected Continue, got {other:?}"),
        }
        assert_eq!(ctx.locals.get("idp_alias"), Some(&json!("google")));
    }

    #[tokio::test]
    async fn empty_alias_returns_broker_error() {
        let mut ctx = fixture().await;
        let out = IdpRedirectAuthenticator::new("")
            .process(&mut ctx, AuthnInput::Init)
            .await
            .unwrap();
        assert!(matches!(out, AuthnOutput::Failure(FailureKind::BrokerError(_))));
    }
}
