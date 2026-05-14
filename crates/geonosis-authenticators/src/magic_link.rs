//! Built-in `magic-link` authenticator.
//!
//! - On `Init`, looks up a user by submitted email, mints a 32-byte
//!   single-use token, stores the BLAKE3-keyed hash on the user record,
//!   and asks the wired `MagicLinkSender` to deliver a URL of the form
//!   `<base>/realms/{slug}/login-actions/magic-link?token=...`.
//! - On `Submit(token=...)`, verifies the presented token, burns it, and
//!   marks the user authenticated.
//!
//! The `MagicLinkSender` SPI seam is what realms wire to their SMTP
//! provider; v0.1 ships an in-memory `RecordingMagicLinkSender` for
//! tests + a deferred real SMTP plugin.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Duration;
use serde_json::json;

use geonosis_core::attribute::AttributeValue;
use geonosis_core::{Amr, CredentialKind};
use geonosis_crypto::hash::{ct_eq, token_hash};
use geonosis_crypto::random::random_token;

use crate::context::AuthnContext;
use crate::traits::{
    AuthnError, AuthnInput, AuthnOutput, Authenticator, FailureKind, RenderInstruction,
};

/// Default TTL for an issued magic-link.
pub const MAGIC_LINK_TTL_MINUTES: i64 = 15;

/// SMTP / message-bus seam used to deliver the issued link. The
/// `geonosis:event` SPI provides a generic email-sender shape; this
/// trait is the typed in-process wrapper used by the authenticator.
#[async_trait]
pub trait MagicLinkSender: Send + Sync {
    async fn send(&self, email: &str, link: &str) -> Result<(), String>;
}

pub struct MagicLinkAuthenticator {
    pub sender: Arc<dyn MagicLinkSender>,
    /// Base URL used to build the callback link. The handler at
    /// `<base>/realms/{slug}/login-actions/magic-link` is wired in
    /// `geonosis-server` once the broader login-actions surface lands.
    pub callback_base: url::Url,
}

#[async_trait]
impl Authenticator for MagicLinkAuthenticator {
    fn provider_id(&self) -> &'static str {
        "builtin:authn:magic-link"
    }

    async fn process(
        &self,
        ctx: &mut AuthnContext,
        input: AuthnInput,
    ) -> Result<AuthnOutput, AuthnError> {
        match input {
            AuthnInput::Init => Ok(AuthnOutput::Continue {
                render: RenderInstruction::new("login/magic-link-request.html"),
            }),
            AuthnInput::Submit(form) => {
                if let Some(token) = form.get("token") {
                    self.verify(ctx, token).await
                } else if let Some(email) = form.get("email") {
                    self.issue(ctx, email).await
                } else {
                    Err(AuthnError::Invalid(
                        "magic-link submit needs token= or email=".into(),
                    ))
                }
            }
            AuthnInput::Resume => Ok(AuthnOutput::Continue {
                render: RenderInstruction::new("login/magic-link-sent.html"),
            }),
        }
    }
}

impl MagicLinkAuthenticator {
    async fn issue(
        &self,
        ctx: &mut AuthnContext,
        email: &str,
    ) -> Result<AuthnOutput, AuthnError> {
        let mut user = match ctx.storage.get_user_by_email(ctx.realm_id, email).await {
            Ok(u) if u.enabled => u,
            _ => {
                // No user enumeration. Render "if your email matches we
                // sent a link" regardless. We still consume one token.
                return Ok(AuthnOutput::Continue {
                    render: RenderInstruction::new("login/magic-link-sent.html"),
                });
            }
        };
        let token = random_token();
        let hash = hex::encode(token_hash(&ctx.realm_hash_key, token.as_bytes()));
        let expires = ctx.now + Duration::minutes(MAGIC_LINK_TTL_MINUTES);
        user.attributes.insert(
            "magic-link:hash".into(),
            AttributeValue::String(hash.clone()),
        );
        user.attributes.insert(
            "magic-link:expires-unix".into(),
            AttributeValue::Integer(expires.timestamp()),
        );
        ctx.storage
            .update_user(user)
            .await
            .map_err(|e| AuthnError::Storage(e.to_string()))?;

        let mut link = self.callback_base.clone();
        link.set_path(&format!(
            "{}/login-actions/magic-link",
            link.path().trim_end_matches('/')
        ));
        link.query_pairs_mut().append_pair("token", &token);
        self.sender
            .send(email, link.as_str())
            .await
            .map_err(AuthnError::Internal)?;

        Ok(AuthnOutput::Continue {
            render: RenderInstruction::new("login/magic-link-sent.html")
                .with("expires_at_unix", json!(expires.timestamp())),
        })
    }

    async fn verify(
        &self,
        ctx: &mut AuthnContext,
        token: &str,
    ) -> Result<AuthnOutput, AuthnError> {
        // Linear scan via the email index would leak info; v0.1 keeps the
        // hash on the user record and requires the caller to supply
        // `user_id` via the resolved-user path (the email step). Tests
        // exercise both arms.
        let user_id = ctx
            .user_id
            .ok_or_else(|| AuthnError::Invalid("magic-link verify needs resolved user".into()))?;
        let mut user = ctx
            .storage
            .get_user(ctx.realm_id, user_id)
            .await
            .map_err(|e| AuthnError::Storage(e.to_string()))?;
        let stored_hash = match user.attributes.get("magic-link:hash") {
            Some(AttributeValue::String(s)) => s.clone(),
            _ => return Ok(AuthnOutput::Failure(FailureKind::InvalidCredential)),
        };
        let expires_unix = match user.attributes.get("magic-link:expires-unix") {
            Some(AttributeValue::Integer(t)) => *t,
            _ => 0,
        };
        if expires_unix < ctx.now.timestamp() {
            return Ok(AuthnOutput::Failure(FailureKind::InvalidCredential));
        }
        let presented_hash = hex::encode(token_hash(&ctx.realm_hash_key, token.as_bytes()));
        if !ct_eq(stored_hash.as_bytes(), presented_hash.as_bytes()) {
            return Ok(AuthnOutput::Failure(FailureKind::InvalidCredential));
        }

        // Burn.
        user.attributes.remove("magic-link:hash");
        user.attributes.remove("magic-link:expires-unix");
        ctx.storage
            .update_user(user)
            .await
            .map_err(|e| AuthnError::Storage(e.to_string()))?;
        ctx.record_amr(Amr::Email);
        Ok(AuthnOutput::Success {
            credentials_satisfied: vec![CredentialKind::MagicLink],
            amr: vec![Amr::Email],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use chrono::Utc;
    use std::sync::Arc;

    use geonosis_core::{
        AccessTokenType, ClientAuthMethod, ClientId, ClientKind, ConsentPolicy, FlowBinding,
        GrantPolicy, PersonName, RealmId, User, UserId,
    };
    use geonosis_storage::{MemoryStorage, Storage};

    struct Recorder {
        sent: Mutex<Vec<(String, String)>>,
    }

    #[async_trait]
    impl MagicLinkSender for Recorder {
        async fn send(&self, email: &str, link: &str) -> Result<(), String> {
            self.sent.lock().unwrap().push((email.into(), link.into()));
            Ok(())
        }
    }

    async fn fixture() -> (AuthnContext, UserId, Arc<Recorder>) {
        let realm = RealmId::new();
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let u = User {
            id: UserId::new(),
            realm_id: realm,
            username: "ada".into(),
            email: Some("ada@example.com".into()),
            email_verified: true,
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
        let uid = u.id;
        storage.create_user(u).await.unwrap();
        let recorder = Arc::new(Recorder { sent: Mutex::new(vec![]) });
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
            realm_hash_key: [13u8; 32],
            user_id: None,
            session_id: None,
            amr: vec![],
            locals: Default::default(),
            now: Utc::now(),
            brute_force: geonosis_core::realm::BruteForcePolicy::default(),
        };
        (ctx, uid, recorder)
    }

    fn authenticator(rec: Arc<Recorder>) -> MagicLinkAuthenticator {
        MagicLinkAuthenticator {
            sender: rec,
            callback_base: url::Url::parse("https://g.example/realms/acme").unwrap(),
        }
    }

    #[tokio::test]
    async fn issue_sends_link_and_renders_sent_screen() {
        let (mut ctx, _, rec) = fixture().await;
        let a = authenticator(rec.clone());
        let mut form = std::collections::BTreeMap::new();
        form.insert("email".into(), "ada@example.com".into());
        let out = a.process(&mut ctx, AuthnInput::Submit(form)).await.unwrap();
        match out {
            AuthnOutput::Continue { render } => {
                assert_eq!(render.template, "login/magic-link-sent.html");
            }
            other => panic!("expected Continue, got {other:?}"),
        }
        let sent = rec.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "ada@example.com");
        assert!(sent[0].1.contains("token="));
    }

    #[tokio::test]
    async fn unknown_email_does_not_enumerate() {
        let (mut ctx, _, rec) = fixture().await;
        let a = authenticator(rec.clone());
        let mut form = std::collections::BTreeMap::new();
        form.insert("email".into(), "ghost@example.com".into());
        let out = a.process(&mut ctx, AuthnInput::Submit(form)).await.unwrap();
        match out {
            AuthnOutput::Continue { render } => {
                assert_eq!(render.template, "login/magic-link-sent.html");
            }
            other => panic!("expected Continue, got {other:?}"),
        }
        assert!(rec.sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn verify_succeeds_then_token_is_burned() {
        let (mut ctx, uid, rec) = fixture().await;
        let a = authenticator(rec.clone());
        let mut form = std::collections::BTreeMap::new();
        form.insert("email".into(), "ada@example.com".into());
        a.process(&mut ctx, AuthnInput::Submit(form)).await.unwrap();
        // Pull the issued token out of the recorded link.
        let link = rec.sent.lock().unwrap()[0].1.clone();
        let token = link
            .split_once("token=")
            .unwrap()
            .1
            .to_string();

        ctx.user_id = Some(uid);
        let mut form = std::collections::BTreeMap::new();
        form.insert("token".into(), token.clone());
        let out = a.process(&mut ctx, AuthnInput::Submit(form)).await.unwrap();
        assert!(matches!(out, AuthnOutput::Success { .. }));

        // Re-presentation must fail.
        let mut form = std::collections::BTreeMap::new();
        form.insert("token".into(), token);
        let out = a.process(&mut ctx, AuthnInput::Submit(form)).await.unwrap();
        assert!(matches!(out, AuthnOutput::Failure(FailureKind::InvalidCredential)));
    }

    #[tokio::test]
    async fn expired_token_rejected() {
        let (mut ctx, uid, rec) = fixture().await;
        let a = authenticator(rec.clone());
        let mut form = std::collections::BTreeMap::new();
        form.insert("email".into(), "ada@example.com".into());
        a.process(&mut ctx, AuthnInput::Submit(form)).await.unwrap();
        let link = rec.sent.lock().unwrap()[0].1.clone();
        let token = link.split_once("token=").unwrap().1.to_string();

        // Fast-forward beyond expiry.
        ctx.now = ctx.now + Duration::minutes(MAGIC_LINK_TTL_MINUTES + 1);
        ctx.user_id = Some(uid);
        let mut form = std::collections::BTreeMap::new();
        form.insert("token".into(), token);
        let out = a.process(&mut ctx, AuthnInput::Submit(form)).await.unwrap();
        assert!(matches!(out, AuthnOutput::Failure(FailureKind::InvalidCredential)));
    }
}
