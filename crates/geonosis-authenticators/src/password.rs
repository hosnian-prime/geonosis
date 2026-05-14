//! Built-in `password` authenticator.

use async_trait::async_trait;

use geonosis_core::{Amr, CredentialKind};
use geonosis_crypto::verify_password;

use crate::brute_force::{check_locked, record_failure, record_success, BruteForceError};
use crate::context::AuthnContext;
use crate::traits::{
    AuthnError, AuthnInput, AuthnOutput, Authenticator, FailureKind, RenderInstruction,
};

/// `builtin:authn:password` — verifies username + password against the
/// realm's local user storage (Argon2id PHC hash, constant-time).
pub struct PasswordAuthenticator;

#[async_trait]
impl Authenticator for PasswordAuthenticator {
    fn provider_id(&self) -> &'static str {
        "builtin:authn:password"
    }

    async fn process(
        &self,
        ctx: &mut AuthnContext,
        input: AuthnInput,
    ) -> Result<AuthnOutput, AuthnError> {
        let fields = match input {
            AuthnInput::Submit(m) => m,
            _ => {
                return Ok(AuthnOutput::Continue {
                    render: RenderInstruction::new("login/password.html"),
                });
            }
        };

        let username = fields
            .get("username")
            .cloned()
            .ok_or_else(|| AuthnError::Invalid("missing username".into()))?;
        let password = fields
            .get("password")
            .cloned()
            .ok_or_else(|| AuthnError::Invalid("missing password".into()))?;

        let user = match ctx
            .storage
            .get_user_by_username(ctx.realm_id, &username)
            .await
        {
            Ok(u) if u.enabled => u,
            Ok(_) => return Ok(AuthnOutput::Failure(FailureKind::UserDisabled)),
            Err(_) => return Ok(AuthnOutput::Failure(FailureKind::InvalidCredential)),
        };

        // Brute-force pre-flight. If the account is locked, refuse
        // before doing the (expensive) Argon2id verify.
        if let Err(BruteForceError::Locked { .. }) =
            check_locked(&*ctx.storage, ctx.realm_id, user.id, ctx.now).await
        {
            return Ok(AuthnOutput::Failure(FailureKind::Locked));
        }

        let phc = match ctx.storage.get_password_hash(ctx.realm_id, user.id).await {
            Ok(h) => h,
            Err(_) => return Ok(AuthnOutput::Failure(FailureKind::InvalidCredential)),
        };

        match verify_password(&password, &phc) {
            Ok(true) => {
                let _ = record_success(&*ctx.storage, ctx.realm_id, user.id).await;
                ctx.user_id = Some(user.id);
                ctx.record_amr(Amr::Pwd);
                Ok(AuthnOutput::Success {
                    credentials_satisfied: vec![CredentialKind::Password],
                    amr: vec![Amr::Pwd],
                })
            }
            Ok(false) => {
                // Increment counter; if this push us past the threshold,
                // the next pre-flight will see `Locked`.
                let _ = record_failure(
                    &*ctx.storage,
                    ctx.realm_id,
                    user.id,
                    &ctx.brute_force,
                    ctx.now,
                )
                .await;
                Ok(AuthnOutput::Failure(FailureKind::InvalidCredential))
            }
            Err(e) => Err(AuthnError::Crypto(e.to_string())),
        }
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
    use geonosis_crypto::hash_password;
    use geonosis_storage::{MemoryStorage, Storage};

    fn user(realm: RealmId, username: &str) -> User {
        User {
            id: UserId::new(),
            realm_id: realm,
            username: username.into(),
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
        }
    }

    fn client(realm: RealmId) -> Client {
        geonosis_core::Client {
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
        }
    }

    use geonosis_core::Client;

    async fn fixture() -> (AuthnContext, UserId) {
        let realm = RealmId::new();
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let u = user(realm, "ada");
        let uid = u.id;
        storage.create_user(u).await.unwrap();
        let h = hash_password("hunter2-XXX").unwrap();
        storage.store_password_hash(realm, uid, h).await.unwrap();
        let ctx = AuthnContext {
            realm_id: realm,
            client: Arc::new(client(realm)),
            storage,
            realm_hash_key: [1u8; 32],
            user_id: None,
            session_id: None,
            amr: vec![],
            locals: Default::default(),
            now: Utc::now(),
            brute_force: geonosis_core::realm::BruteForcePolicy::default(),
        };
        (ctx, uid)
    }

    #[tokio::test]
    async fn init_renders_password_template() {
        let (mut ctx, _) = fixture().await;
        let out = PasswordAuthenticator.process(&mut ctx, AuthnInput::Init).await.unwrap();
        match out {
            AuthnOutput::Continue { render } => {
                assert_eq!(render.template, "login/password.html");
            }
            other => panic!("expected Continue, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn correct_credentials_succeed() {
        let (mut ctx, uid) = fixture().await;
        let mut form = std::collections::BTreeMap::new();
        form.insert("username".into(), "ada".into());
        form.insert("password".into(), "hunter2-XXX".into());
        let out = PasswordAuthenticator
            .process(&mut ctx, AuthnInput::Submit(form))
            .await
            .unwrap();
        match out {
            AuthnOutput::Success { amr, credentials_satisfied } => {
                assert_eq!(amr, vec![Amr::Pwd]);
                assert_eq!(credentials_satisfied, vec![CredentialKind::Password]);
            }
            other => panic!("expected Success, got {other:?}"),
        }
        assert_eq!(ctx.user_id, Some(uid));
        assert!(ctx.amr.contains(&Amr::Pwd));
    }

    #[tokio::test]
    async fn wrong_password_fails_with_invalid_credential() {
        let (mut ctx, _) = fixture().await;
        let mut form = std::collections::BTreeMap::new();
        form.insert("username".into(), "ada".into());
        form.insert("password".into(), "WRONG".into());
        let out = PasswordAuthenticator
            .process(&mut ctx, AuthnInput::Submit(form))
            .await
            .unwrap();
        assert!(matches!(out, AuthnOutput::Failure(FailureKind::InvalidCredential)));
        assert!(ctx.user_id.is_none(), "ctx user must not be set on failure");
    }

    #[tokio::test]
    async fn unknown_username_fails_with_invalid_credential() {
        let (mut ctx, _) = fixture().await;
        let mut form = std::collections::BTreeMap::new();
        form.insert("username".into(), "ghost".into());
        form.insert("password".into(), "anything".into());
        let out = PasswordAuthenticator
            .process(&mut ctx, AuthnInput::Submit(form))
            .await
            .unwrap();
        // Same `InvalidCredential` failure → no username-enumeration leak.
        assert!(matches!(out, AuthnOutput::Failure(FailureKind::InvalidCredential)));
    }

    #[tokio::test]
    async fn missing_password_field_errors_invalid() {
        let (mut ctx, _) = fixture().await;
        let mut form = std::collections::BTreeMap::new();
        form.insert("username".into(), "ada".into());
        let err = PasswordAuthenticator
            .process(&mut ctx, AuthnInput::Submit(form))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthnError::Invalid(_)));
    }
}
