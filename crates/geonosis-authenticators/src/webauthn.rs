//! Built-in `webauthn` authenticator — assertion-as-step (v0.1).
//!
//! Per `docs/14-roadmap.md` v0.1 scope:
//! > webauthn (assertion-as-step; full passkey lifecycle v0.2)
//!
//! Concretely v0.1 ships:
//! - A `Continue { render }` that prompts the browser to fetch a
//!   challenge from `/login-actions/webauthn/challenge` (handler lands
//!   with the broader login-actions surface).
//! - A `Submit` arm that accepts the navigator-emitted
//!   `clientDataJSON` + `authenticatorData` + `signature` + `userHandle`
//!   blob and looks up the matching enrolled credential.
//! - **Signature verification stubbed**: full WebAuthn signature
//!   verification needs the `webauthn-rs` family of crates (deferred
//!   to v0.1.x to keep the dependency surface auditable). v0.1 records
//!   the assertion shape and returns `Failure(RequiresEnrollment)` when
//!   no credential is enrolled; otherwise `Failure(InvalidCredential)`
//!   with a `webauthn:assertion` local set so the deferring runtime
//!   path is unambiguous.

use async_trait::async_trait;
use serde_json::json;

use geonosis_core::{Amr, CredentialKind};

use crate::context::AuthnContext;
use crate::traits::{
    Authenticator, AuthnError, AuthnInput, AuthnOutput, FailureKind, RenderInstruction,
};

#[derive(Default)]
pub struct WebauthnAuthenticator {
    /// If `true`, the authenticator returns `Success` once it sees the
    /// submitted assertion blob (for end-to-end test scaffolding only).
    /// Production deployments leave this `false` until the
    /// signature-verification module lands.
    pub trust_unverified_assertions: bool,
}

#[async_trait]
impl Authenticator for WebauthnAuthenticator {
    fn provider_id(&self) -> &'static str {
        "builtin:authn:webauthn"
    }

    async fn process(
        &self,
        ctx: &mut AuthnContext,
        input: AuthnInput,
    ) -> Result<AuthnOutput, AuthnError> {
        match input {
            AuthnInput::Init | AuthnInput::Resume => Ok(AuthnOutput::Continue {
                render: RenderInstruction::new("login/webauthn-assert.html"),
            }),
            AuthnInput::Submit(form) => {
                let user_id = ctx
                    .user_id
                    .ok_or_else(|| AuthnError::Invalid("webauthn requires resolved user".into()))?;
                let assertion = form
                    .get("assertion")
                    .cloned()
                    .ok_or_else(|| AuthnError::Invalid("missing assertion".into()))?;

                let user = ctx
                    .storage
                    .get_user(ctx.realm_id, user_id)
                    .await
                    .map_err(|e| AuthnError::Storage(e.to_string()))?;
                let has_credential = user.attributes.contains_key("webauthn:credentials");
                if !has_credential {
                    return Ok(AuthnOutput::Failure(FailureKind::RequiresEnrollment));
                }
                ctx.locals
                    .insert("webauthn:assertion".into(), json!(assertion));

                if !self.trust_unverified_assertions {
                    // Defer verification — the runtime path lights up once
                    // the `webauthn-rs` integration lands (v0.1.x).
                    return Ok(AuthnOutput::Failure(FailureKind::Other(
                        "webauthn signature verification deferred to v0.1.x".into(),
                    )));
                }

                ctx.record_amr(Amr::Wbn);
                Ok(AuthnOutput::Success {
                    credentials_satisfied: vec![CredentialKind::Webauthn],
                    amr: vec![Amr::Wbn],
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::sync::Arc;

    use geonosis_core::attribute::AttributeValue;
    use geonosis_core::{
        AccessTokenType, ClientAuthMethod, ClientId, ClientKind, ConsentPolicy, FlowBinding,
        GrantPolicy, PersonName, RealmId, User, UserId,
    };
    use geonosis_storage::{MemoryStorage, Storage};

    async fn fixture(enrolled: bool) -> (AuthnContext, UserId) {
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
            failed_attempts: 0,
            locked_until: None,
            last_failed_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        if enrolled {
            u.attributes.insert(
                "webauthn:credentials".into(),
                AttributeValue::Strings(vec!["cred-id-1".into()]),
            );
        }
        let uid = u.id;
        storage.create_user(u).await.unwrap();
        let ctx = AuthnContext {
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
                saml_sp_config: None,
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
            brute_force: geonosis_core::realm::BruteForcePolicy::default(),
        };
        (ctx, uid)
    }

    #[tokio::test]
    async fn init_renders_assertion_prompt() {
        let (mut ctx, _) = fixture(true).await;
        let out = WebauthnAuthenticator::default()
            .process(&mut ctx, AuthnInput::Init)
            .await
            .unwrap();
        match out {
            AuthnOutput::Continue { render } => {
                assert_eq!(render.template, "login/webauthn-assert.html");
            }
            other => panic!("expected Continue, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unenrolled_user_signals_requires_enrollment() {
        let (mut ctx, _) = fixture(false).await;
        let mut form = std::collections::BTreeMap::new();
        form.insert("assertion".into(), "blob".into());
        let out = WebauthnAuthenticator::default()
            .process(&mut ctx, AuthnInput::Submit(form))
            .await
            .unwrap();
        assert!(matches!(
            out,
            AuthnOutput::Failure(FailureKind::RequiresEnrollment)
        ));
    }

    #[tokio::test]
    async fn unverified_path_returns_deferred_failure() {
        let (mut ctx, _) = fixture(true).await;
        let mut form = std::collections::BTreeMap::new();
        form.insert("assertion".into(), "blob".into());
        let out = WebauthnAuthenticator::default()
            .process(&mut ctx, AuthnInput::Submit(form))
            .await
            .unwrap();
        match out {
            AuthnOutput::Failure(FailureKind::Other(msg)) => {
                assert!(msg.contains("webauthn"));
            }
            other => panic!("expected deferred-failure, got {other:?}"),
        }
        // The assertion blob is stashed so the audit trail can show it.
        assert!(ctx.locals.contains_key("webauthn:assertion"));
    }

    #[tokio::test]
    async fn trust_flag_succeeds_for_test_scaffolding() {
        let (mut ctx, _) = fixture(true).await;
        let mut form = std::collections::BTreeMap::new();
        form.insert("assertion".into(), "blob".into());
        let out = WebauthnAuthenticator {
            trust_unverified_assertions: true,
        }
        .process(&mut ctx, AuthnInput::Submit(form))
        .await
        .unwrap();
        assert!(matches!(out, AuthnOutput::Success { .. }));
        assert!(ctx.amr.contains(&Amr::Wbn));
    }
}
