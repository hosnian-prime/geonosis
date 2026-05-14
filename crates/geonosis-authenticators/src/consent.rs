//! Built-in `consent` authenticator — the OAuth consent screen.
//!
//! - First invocation renders the consent template with the requested
//!   scopes (locals: `client_name`, `scopes_to_grant`).
//! - On submit, persists/extends the `ConsentGrant` for `(user, client)`.
//! - If the user has already granted a superset of the requested scopes,
//!   the authenticator returns `Skip` so the flow advances without UI.

use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;
use std::collections::BTreeSet;

use geonosis_core::scope::parse_scope_string;
use geonosis_core::{Amr, ConsentGrantId, CredentialKind};
use geonosis_storage::ConsentGrant;

use crate::context::AuthnContext;
use crate::traits::{
    AuthnError, AuthnInput, AuthnOutput, Authenticator, FailureKind, RenderInstruction,
};

pub struct ConsentAuthenticator;

#[async_trait]
impl Authenticator for ConsentAuthenticator {
    fn provider_id(&self) -> &'static str {
        "builtin:authn:consent"
    }

    async fn process(
        &self,
        ctx: &mut AuthnContext,
        input: AuthnInput,
    ) -> Result<AuthnOutput, AuthnError> {
        let user_id = ctx
            .user_id
            .ok_or_else(|| AuthnError::Invalid("consent requires resolved user".into()))?;

        // Requested scopes come from the locals `requested_scopes` (space-
        // separated) so the executor can wire them up generically.
        let requested = ctx
            .locals
            .get("requested_scopes")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default();
        let requested_set: BTreeSet<String> = parse_scope_string(&requested)
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.as_str().to_string())
            .collect();

        // Look up any existing grant.
        let existing = ctx
            .storage
            .get_consent_grant(ctx.realm_id, user_id, ctx.client.id)
            .await
            .ok();
        let already: BTreeSet<String> = existing
            .as_ref()
            .map(|g| g.scopes.iter().map(|s| s.as_str().to_string()).collect())
            .unwrap_or_default();

        if requested_set.is_subset(&already) && !requested_set.is_empty() {
            // Existing grant covers the request — skip the screen.
            return Ok(AuthnOutput::Skip);
        }
        let missing: Vec<String> = requested_set.difference(&already).cloned().collect();

        match input {
            AuthnInput::Init | AuthnInput::Resume => Ok(AuthnOutput::Continue {
                render: RenderInstruction::new("login/consent.html")
                    .with(
                        "client_name",
                        json!(ctx
                            .client
                            .display_name
                            .clone()
                            .unwrap_or_else(|| ctx.client.client_id.clone())),
                    )
                    .with("scopes_to_grant", json!(missing)),
            }),
            AuthnInput::Submit(form) => {
                let action = form.get("action").map(String::as_str).unwrap_or("deny");
                if action != "approve" {
                    return Ok(AuthnOutput::Failure(FailureKind::ConsentDenied));
                }
                let mut union: BTreeSet<String> = already.clone();
                union.extend(requested_set.iter().cloned());
                let scopes = union
                    .into_iter()
                    .filter_map(|s| geonosis_core::ScopeName::new(s).ok())
                    .collect();
                let now = ctx.now;
                let grant = ConsentGrant {
                    id: existing.as_ref().map(|g| g.id).unwrap_or_else(ConsentGrantId::new),
                    realm_id: ctx.realm_id,
                    user_id,
                    client_id: ctx.client.id,
                    scopes,
                    granted_at: existing.as_ref().map(|g| g.granted_at).unwrap_or(now),
                    updated_at: Utc::now(),
                };
                ctx.storage
                    .save_consent_grant(grant)
                    .await
                    .map_err(|e| AuthnError::Storage(e.to_string()))?;
                Ok(AuthnOutput::Success {
                    credentials_satisfied: vec![CredentialKind::Password], // consent isn't a credential — placeholder
                    amr: vec![],
                })
            }
        }
    }
}

// Suppress AMR push (consent is not an authentication factor).
impl ConsentAuthenticator {
    /// Convenience marker — consent doesn't add an AMR; the `Success`
    /// arm above intentionally returns an empty vec.
    #[allow(dead_code)]
    fn amr_contribution() -> Vec<Amr> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use geonosis_core::{
        AccessTokenType, ClientAuthMethod, ClientId, ClientKind, ConsentPolicy, FlowBinding,
        GrantPolicy, PersonName, RealmId, User, UserId,
    };
    use geonosis_storage::{MemoryStorage, Storage};

    async fn fixture(initial_grant: Option<Vec<&str>>) -> (AuthnContext, UserId) {
        let realm = RealmId::new();
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let u = User {
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
        let uid = u.id;
        storage.create_user(u).await.unwrap();
        let client = geonosis_core::Client {
            id: ClientId::new(),
            realm_id: realm,
            client_id: "spa".into(),
            display_name: Some("My SPA".into()),
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
        };
        let cid = client.id;
        if let Some(scopes) = initial_grant {
            let grant = ConsentGrant {
                id: ConsentGrantId::new(),
                realm_id: realm,
                user_id: uid,
                client_id: cid,
                scopes: scopes
                    .iter()
                    .filter_map(|s| geonosis_core::ScopeName::new(*s).ok())
                    .collect(),
                granted_at: Utc::now(),
                updated_at: Utc::now(),
            };
            storage.save_consent_grant(grant).await.unwrap();
        }
        let ctx = AuthnContext {
            realm_id: realm,
            client: Arc::new(client),
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
    async fn first_visit_renders_consent_screen() {
        let (mut ctx, _) = fixture(None).await;
        ctx.locals.insert("requested_scopes".into(), json!("openid profile email"));
        let out = ConsentAuthenticator.process(&mut ctx, AuthnInput::Init).await.unwrap();
        match out {
            AuthnOutput::Continue { render } => {
                assert_eq!(render.template, "login/consent.html");
                let scopes = render.locals.get("scopes_to_grant").unwrap();
                let scopes: Vec<String> = serde_json::from_value(scopes.clone()).unwrap();
                assert!(scopes.contains(&"openid".to_string()));
            }
            other => panic!("expected Continue, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn approve_persists_grant_and_returns_success() {
        let (mut ctx, uid) = fixture(None).await;
        ctx.locals.insert("requested_scopes".into(), json!("openid profile"));
        let mut form = std::collections::BTreeMap::new();
        form.insert("action".into(), "approve".into());
        let out = ConsentAuthenticator
            .process(&mut ctx, AuthnInput::Submit(form))
            .await
            .unwrap();
        assert!(matches!(out, AuthnOutput::Success { .. }));
        let g = ctx
            .storage
            .get_consent_grant(ctx.realm_id, uid, ctx.client.id)
            .await
            .unwrap();
        let names: Vec<String> = g.scopes.iter().map(|s| s.as_str().to_string()).collect();
        assert!(names.contains(&"openid".to_string()));
        assert!(names.contains(&"profile".to_string()));
    }

    #[tokio::test]
    async fn deny_returns_consent_denied() {
        let (mut ctx, _) = fixture(None).await;
        ctx.locals.insert("requested_scopes".into(), json!("openid"));
        let mut form = std::collections::BTreeMap::new();
        form.insert("action".into(), "deny".into());
        let out = ConsentAuthenticator
            .process(&mut ctx, AuthnInput::Submit(form))
            .await
            .unwrap();
        assert!(matches!(out, AuthnOutput::Failure(FailureKind::ConsentDenied)));
    }

    #[tokio::test]
    async fn existing_grant_covering_request_skips_screen() {
        let (mut ctx, _) = fixture(Some(vec!["openid", "profile", "email"])).await;
        ctx.locals.insert("requested_scopes".into(), json!("openid profile"));
        let out = ConsentAuthenticator.process(&mut ctx, AuthnInput::Init).await.unwrap();
        assert!(matches!(out, AuthnOutput::Skip));
    }
}
