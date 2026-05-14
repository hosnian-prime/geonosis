//! Built-in `require-action` authenticator — gates the flow on the
//! user's pending `required_actions` set.
//!
//! When the resolved user carries one or more required actions, the
//! authenticator emits a `Continue { render }` pointing the executor at
//! the corresponding subflow template (e.g. `login/required-action/
//! update-password.html`). On `Submit` it removes the matching action
//! from the user record.

use async_trait::async_trait;
use serde_json::json;

use geonosis_core::{Amr, CredentialKind, RequiredAction};

use crate::context::AuthnContext;
use crate::traits::{
    AuthnError, AuthnInput, AuthnOutput, Authenticator, FailureKind, RenderInstruction,
};

pub struct RequireActionAuthenticator;

#[async_trait]
impl Authenticator for RequireActionAuthenticator {
    fn provider_id(&self) -> &'static str {
        "builtin:authn:require-action"
    }

    async fn process(
        &self,
        ctx: &mut AuthnContext,
        input: AuthnInput,
    ) -> Result<AuthnOutput, AuthnError> {
        let user_id = match ctx.user_id {
            Some(id) => id,
            None => return Ok(AuthnOutput::Skip),
        };

        let mut user = ctx
            .storage
            .get_user(ctx.realm_id, user_id)
            .await
            .map_err(|e| AuthnError::Storage(e.to_string()))?;

        let pending = match user.required_actions.first().cloned() {
            Some(a) => a,
            None => return Ok(AuthnOutput::Skip),
        };
        let action_key = action_key(&pending);

        match input {
            AuthnInput::Init | AuthnInput::Resume => Ok(AuthnOutput::Continue {
                render: RenderInstruction::new(format!("login/required-action/{action_key}.html"))
                    .with("action", json!(action_key)),
            }),
            AuthnInput::Submit(form) => {
                // The flow node templates submit `action=ack` after the user
                // completes the required step (UI handles the actual data
                // exchange). v0.1 records the acknowledgment.
                let ack = form.get("action").map(String::as_str) == Some("ack");
                if !ack {
                    return Ok(AuthnOutput::Failure(FailureKind::Other(
                        "required action not acknowledged".into(),
                    )));
                }
                user.required_actions.retain(|a| a != &pending);
                ctx.storage
                    .update_user(user)
                    .await
                    .map_err(|e| AuthnError::Storage(e.to_string()))?;

                // Required actions aren't an authentication factor; they
                // gate the flow. AMR is unchanged.
                let _ = ctx; // silence unused-mut suggestion when AMR not touched
                Ok(AuthnOutput::Success {
                    credentials_satisfied: vec![],
                    amr: vec![],
                })
            }
        }
    }
}

fn action_key(a: &RequiredAction) -> String {
    match a {
        RequiredAction::UpdatePassword => "update-password".into(),
        RequiredAction::ConfigureOtp => "configure-otp".into(),
        RequiredAction::ConfigureWebauthn => "configure-webauthn".into(),
        RequiredAction::VerifyEmail => "verify-email".into(),
        RequiredAction::UpdateProfile => "update-profile".into(),
        RequiredAction::AcceptTerms => "accept-terms".into(),
        RequiredAction::DeleteAccount => "delete-account".into(),
        RequiredAction::Custom(s) => s.clone(),
    }
}

// Quiet unused imports for `Amr` / `CredentialKind` which the trait file
// re-exports for completeness.
#[allow(dead_code)]
fn _silence(_: Amr, _: CredentialKind) {}

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

    async fn fixture(actions: Vec<RequiredAction>) -> (AuthnContext, UserId) {
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
        u.required_actions = actions;
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
    async fn no_actions_skips() {
        let (mut ctx, _) = fixture(vec![]).await;
        let out = RequireActionAuthenticator
            .process(&mut ctx, AuthnInput::Init)
            .await
            .unwrap();
        assert!(matches!(out, AuthnOutput::Skip));
    }

    #[tokio::test]
    async fn first_action_renders_subflow_template() {
        let (mut ctx, _) = fixture(vec![RequiredAction::VerifyEmail]).await;
        let out = RequireActionAuthenticator
            .process(&mut ctx, AuthnInput::Init)
            .await
            .unwrap();
        match out {
            AuthnOutput::Continue { render } => {
                assert_eq!(render.template, "login/required-action/verify-email.html");
            }
            other => panic!("expected Continue, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ack_removes_pending_action() {
        let (mut ctx, uid) = fixture(vec![RequiredAction::UpdatePassword, RequiredAction::VerifyEmail]).await;
        let mut form = std::collections::BTreeMap::new();
        form.insert("action".into(), "ack".into());
        let out = RequireActionAuthenticator
            .process(&mut ctx, AuthnInput::Submit(form))
            .await
            .unwrap();
        assert!(matches!(out, AuthnOutput::Success { .. }));
        let u = ctx.storage.get_user(ctx.realm_id, uid).await.unwrap();
        // The first action (`UpdatePassword`) was consumed.
        assert_eq!(u.required_actions, vec![RequiredAction::VerifyEmail]);
    }

    #[tokio::test]
    async fn missing_user_skips_silently() {
        let (mut ctx, _) = fixture(vec![]).await;
        ctx.user_id = None;
        let out = RequireActionAuthenticator
            .process(&mut ctx, AuthnInput::Init)
            .await
            .unwrap();
        assert!(matches!(out, AuthnOutput::Skip));
    }
}
