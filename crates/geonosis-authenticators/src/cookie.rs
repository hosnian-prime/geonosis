//! Built-in `cookie` authenticator — short-circuit a flow when the
//! request carries an existing valid SSO session.

use async_trait::async_trait;

use geonosis_core::{Amr, CredentialKind};

use crate::context::AuthnContext;
use crate::traits::{AuthnError, AuthnInput, AuthnOutput, Authenticator};

pub struct CookieAuthenticator;

#[async_trait]
impl Authenticator for CookieAuthenticator {
    fn provider_id(&self) -> &'static str {
        "builtin:authn:cookie"
    }

    async fn process(
        &self,
        ctx: &mut AuthnContext,
        _input: AuthnInput,
    ) -> Result<AuthnOutput, AuthnError> {
        let sid = match &ctx.session_id {
            Some(s) => s.clone(),
            None => return Ok(AuthnOutput::Skip),
        };
        let session = match ctx.storage.get_session(&sid).await {
            Ok(s) => s,
            Err(_) => return Ok(AuthnOutput::Skip),
        };
        if session.realm_id != ctx.realm_id {
            return Ok(AuthnOutput::Skip);
        }
        if session.expires_at < ctx.now {
            return Ok(AuthnOutput::Skip);
        }
        ctx.user_id = Some(session.user_id);
        // Cookie re-use doesn't add a fresh AMR — it carries whatever
        // AMR the originating login asserted. v0.1 records `pwd` as a
        // safe lower bound; v0.2 plumbs the originating AMR through.
        ctx.record_amr(Amr::Pwd);
        Ok(AuthnOutput::Success {
            credentials_satisfied: vec![CredentialKind::Password],
            amr: vec![Amr::Pwd],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use std::sync::Arc;

    use geonosis_core::{
        AccessTokenType, AuthnLevel, ClientAuthMethod, ClientId, ClientKind, ConsentPolicy,
        FlowBinding, GrantPolicy, RealmId, Session, SessionId, UserId,
    };
    use geonosis_storage::{MemoryStorage, Storage};

    async fn fixture(session_alive: bool) -> AuthnContext {
        let realm = RealmId::new();
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let sid = SessionId::new_random();
        let now = Utc::now();
        let session = Session {
            id: sid.clone(),
            realm_id: realm,
            user_id: UserId::new(),
            authn_level: AuthnLevel::Single,
            idp_alias: None,
            started_at: now,
            last_seen_at: now,
            expires_at: if session_alive {
                now + Duration::hours(1)
            } else {
                now - Duration::hours(1)
            },
            clients: vec![],
        };
        storage.create_session(session).await.unwrap();
        let client = geonosis_core::Client {
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
            created_at: now,
            updated_at: now,
        };
        AuthnContext {
            realm_id: realm,
            client: Arc::new(client),
            storage,
            realm_hash_key: [0u8; 32],
            user_id: None,
            session_id: Some(sid),
            amr: vec![],
            locals: Default::default(),
            now,
            brute_force: geonosis_core::realm::BruteForcePolicy::default(),
        }
    }

    #[tokio::test]
    async fn alive_session_succeeds() {
        let mut ctx = fixture(true).await;
        let out = CookieAuthenticator.process(&mut ctx, AuthnInput::Init).await.unwrap();
        assert!(matches!(out, AuthnOutput::Success { .. }));
        assert!(ctx.user_id.is_some());
    }

    #[tokio::test]
    async fn no_cookie_skips() {
        let mut ctx = fixture(true).await;
        ctx.session_id = None;
        let out = CookieAuthenticator.process(&mut ctx, AuthnInput::Init).await.unwrap();
        assert!(matches!(out, AuthnOutput::Skip));
    }

    #[tokio::test]
    async fn expired_session_skips() {
        let mut ctx = fixture(false).await;
        let out = CookieAuthenticator.process(&mut ctx, AuthnInput::Init).await.unwrap();
        assert!(matches!(out, AuthnOutput::Skip));
    }
}
