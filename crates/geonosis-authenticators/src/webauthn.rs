//! Built-in `webauthn` authenticator — assertion verification (v0.1).
//!
//! Per `docs/14-roadmap.md` v0.1 scope:
//! > webauthn (assertion-as-step; full passkey lifecycle v0.2)
//!
//! v0.1 ships assertion verification using the existing crypto
//! primitives (ES256/RS256/EdDSA). The registration ceremony lands
//! in v0.2 — for now credentials are pre-provisioned via admin API.

use async_trait::async_trait;
use serde_json::json;

use geonosis_core::{Amr, CredentialKind};
use geonosis_crypto::webauthn::{self, AssertionParams, StoredCredential, WebauthnError};

use crate::context::AuthnContext;
use crate::traits::{
    Authenticator, AuthnError, AuthnInput, AuthnOutput, FailureKind, RenderInstruction,
};

/// Browser assertion blob sent by `navigator.credentials.get()`.
#[derive(serde::Deserialize)]
struct AssertionBlob {
    /// Base64url-encoded clientDataJSON.
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    /// Base64url-encoded authenticatorData.
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    /// Base64url-encoded signature.
    signature: String,
    /// Base64url-encoded credential ID.
    #[serde(rename = "credentialId", default)]
    credential_id: Option<String>,
}

/// WebAuthn authenticator. Reads `rp_id`, `origin`, and
/// `user_verification` from the realm's `WebauthnPolicy` at runtime
/// via `AuthnContext.storage.get_realm()`. No hardcoded defaults for
/// production-critical security parameters.
#[derive(Default)]
pub struct WebauthnAuthenticator;

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
            AuthnInput::Init | AuthnInput::Resume => {
                // Generate a random challenge and stash it for
                // verification when the browser submits.
                let challenge = geonosis_crypto::random::random_token();
                ctx.locals
                    .insert("webauthn:challenge".into(), json!(challenge));
                Ok(AuthnOutput::Continue {
                    render: RenderInstruction::new("login/webauthn-assert.html"),
                })
            }
            AuthnInput::Submit(form) => {
                let user_id = ctx
                    .user_id
                    .ok_or_else(|| AuthnError::Invalid("webauthn requires resolved user".into()))?;
                let assertion_json = form
                    .get("assertion")
                    .cloned()
                    .ok_or_else(|| AuthnError::Invalid("missing assertion".into()))?;

                // Load user + enrolled credentials.
                let user = ctx
                    .storage
                    .get_user(ctx.realm_id, user_id)
                    .await
                    .map_err(|e| AuthnError::Storage(e.to_string()))?;
                let creds_attr = user
                    .attributes
                    .get("webauthn:credentials")
                    .and_then(|v| v.as_str());
                let Some(creds_json) = creds_attr else {
                    return Ok(AuthnOutput::Failure(FailureKind::RequiresEnrollment));
                };

                // Parse stored credentials.
                let credentials: Vec<StoredCredential> = serde_json::from_str(creds_json)
                    .map_err(|e| AuthnError::Invalid(format!("bad stored credentials: {e}")))?;
                if credentials.is_empty() {
                    return Ok(AuthnOutput::Failure(FailureKind::RequiresEnrollment));
                }

                // Resolve realm config for RP ID and origin.
                let realm = ctx
                    .storage
                    .get_realm(ctx.realm_id)
                    .await
                    .map_err(|e| AuthnError::Storage(e.to_string()))?;
                let rp_id = realm
                    .webauthn_policy
                    .relying_party_id
                    .clone()
                    .unwrap_or_else(|| realm.slug.clone());
                let origin = realm
                    .frontend_url
                    .as_ref()
                    .map(|u| u.to_string().trim_end_matches('/').to_string())
                    .unwrap_or_else(|| format!("https://{rp_id}"));
                let require_uv = realm.webauthn_policy.user_verification == "required";

                // Parse the browser assertion blob.
                let blob: AssertionBlob = serde_json::from_str(&assertion_json)
                    .map_err(|e| AuthnError::Invalid(format!("bad assertion: {e}")))?;
                let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
                use base64::Engine;
                let cdj = b64
                    .decode(&blob.client_data_json)
                    .map_err(|e| AuthnError::Invalid(format!("clientDataJSON b64: {e}")))?;
                let auth_data = b64
                    .decode(&blob.authenticator_data)
                    .map_err(|e| AuthnError::Invalid(format!("authenticatorData b64: {e}")))?;
                let sig = b64
                    .decode(&blob.signature)
                    .map_err(|e| AuthnError::Invalid(format!("signature b64: {e}")))?;

                // Consume the challenge (single-use to prevent replay).
                let expected_challenge = ctx
                    .locals
                    .remove("webauthn:challenge")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| {
                        AuthnError::Invalid("no webauthn challenge in session".into())
                    })?;

                // Find the matching credential. Try credential_id from
                // the blob first; fall back to trying all enrolled creds.
                let matching_cred = if let Some(ref cid) = blob.credential_id {
                    credentials.iter().find(|c| c.credential_id == *cid)
                } else {
                    None
                };

                // If no credential_id match, try all enrolled credentials.
                let result = if let Some(cred) = matching_cred {
                    webauthn::verify_assertion(&AssertionParams {
                        client_data_json: &cdj,
                        authenticator_data: &auth_data,
                        signature: &sig,
                        expected_challenge: &expected_challenge,
                        expected_origin: &origin,
                        rp_id: &rp_id,
                        credential: cred,
                        require_user_verification: require_uv,
                    })
                } else {
                    // Try each credential until one succeeds.
                    let mut last_err = WebauthnError::Malformed("no credentials".into());
                    let mut found = None;
                    for cred in &credentials {
                        match webauthn::verify_assertion(&AssertionParams {
                            client_data_json: &cdj,
                            authenticator_data: &auth_data,
                            signature: &sig,
                            expected_challenge: &expected_challenge,
                            expected_origin: &origin,
                            rp_id: &rp_id,
                            credential: cred,
                            require_user_verification: require_uv,
                        }) {
                            Ok(v) => {
                                found = Some(v);
                                break;
                            }
                            Err(e) => last_err = e,
                        }
                    }
                    found.ok_or(last_err)
                };

                match result {
                    Ok(verified) => {
                        // Update sign count on the stored credential.
                        let mut updated_creds = credentials;
                        if let Some(c) = updated_creds
                            .iter_mut()
                            .find(|c| c.credential_id == verified.credential_id)
                        {
                            c.sign_count = verified.new_sign_count;
                        }
                        if let Ok(json_str) = serde_json::to_string(&updated_creds) {
                            let mut updated_user = user.clone();
                            updated_user.attributes.insert(
                                "webauthn:credentials".into(),
                                geonosis_core::AttributeValue::String(json_str),
                            );
                            if let Err(e) = ctx.storage.update_user(updated_user).await {
                                tracing::warn!(
                                    error = %e,
                                    "webauthn sign count update failed; cloning detection degraded",
                                );
                            }
                        }

                        ctx.record_amr(Amr::Wbn);
                        Ok(AuthnOutput::Success {
                            credentials_satisfied: vec![CredentialKind::Webauthn],
                            amr: vec![Amr::Wbn],
                        })
                    }
                    Err(e) => {
                        ctx.locals
                            .insert("webauthn:error".into(), json!(e.to_string()));
                        Ok(AuthnOutput::Failure(FailureKind::InvalidCredential))
                    }
                }
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
            // Create a real ES256 credential for testing.
            use p256::ecdsa::SigningKey;
            let sk = SigningKey::random(&mut rand::thread_rng());
            let vk = sk.verifying_key();
            let point = vk.to_encoded_point(false);
            use base64::Engine;
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let cred = StoredCredential {
                credential_id: "test-cred-1".into(),
                cose_alg: -7, // ES256
                public_key_b64: b64.encode(point.as_bytes()),
                sign_count: 0,
            };
            let creds_json = serde_json::to_string(&vec![cred]).unwrap();
            u.attributes.insert(
                "webauthn:credentials".into(),
                AttributeValue::String(creds_json),
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
    async fn init_renders_assertion_prompt_and_sets_challenge() {
        let (mut ctx, _) = fixture(true).await;
        let out = WebauthnAuthenticator
            .process(&mut ctx, AuthnInput::Init)
            .await
            .unwrap();
        match out {
            AuthnOutput::Continue { render } => {
                assert_eq!(render.template, "login/webauthn-assert.html");
            }
            other => panic!("expected Continue, got {other:?}"),
        }
        assert!(ctx.locals.contains_key("webauthn:challenge"));
    }

    #[tokio::test]
    async fn unenrolled_user_signals_requires_enrollment() {
        let (mut ctx, _) = fixture(false).await;
        // Set challenge first (Init would do this).
        ctx.locals.insert("webauthn:challenge".into(), json!("ch"));
        let mut form = std::collections::BTreeMap::new();
        form.insert(
            "assertion".into(),
            r#"{"clientDataJSON":"","authenticatorData":"","signature":""}"#.into(),
        );
        let out = WebauthnAuthenticator
            .process(&mut ctx, AuthnInput::Submit(form))
            .await
            .unwrap();
        assert!(matches!(
            out,
            AuthnOutput::Failure(FailureKind::RequiresEnrollment)
        ));
    }
}
