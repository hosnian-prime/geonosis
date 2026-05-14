//! Built-in `recovery-code` authenticator.
//!
//! Recovery codes are 12-character single-use strings (e.g.
//! `XXXX-XXXX-XXXX`). Generated once at MFA enrollment, hashed before
//! storage. Verification consumes one — the code is removed from the
//! stored set on success.

use async_trait::async_trait;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use geonosis_core::attribute::AttributeValue;
use geonosis_core::{Amr, CredentialKind};
use geonosis_crypto::hash::{ct_eq, token_hash};

use crate::context::AuthnContext;
use crate::traits::{
    AuthnError, AuthnInput, AuthnOutput, Authenticator, FailureKind, RenderInstruction,
};

/// `builtin:authn:recovery-code`.
pub struct RecoveryCodeAuthenticator;

#[async_trait]
impl Authenticator for RecoveryCodeAuthenticator {
    fn provider_id(&self) -> &'static str {
        "builtin:authn:recovery-code"
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
                    render: RenderInstruction::new("login/recovery-code.html"),
                });
            }
        };

        let user_id = ctx
            .user_id
            .ok_or_else(|| AuthnError::Invalid("recovery-code requires resolved user".into()))?;
        let presented = fields
            .get("code")
            .cloned()
            .ok_or_else(|| AuthnError::Invalid("missing code".into()))?;

        let mut user = ctx
            .storage
            .get_user(ctx.realm_id, user_id)
            .await
            .map_err(|e| AuthnError::Storage(e.to_string()))?;
        let stored_hashes: Vec<String> = user
            .attributes
            .get("recovery-codes:hashes")
            .and_then(|v| match v {
                AttributeValue::Strings(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap_or_default();
        if stored_hashes.is_empty() {
            return Ok(AuthnOutput::Failure(FailureKind::RequiresEnrollment));
        }

        let presented_hash = code_hash(&presented, &ctx.realm_hash_key);
        let mut hit: Option<usize> = None;
        for (i, h) in stored_hashes.iter().enumerate() {
            if ct_eq(h.as_bytes(), presented_hash.as_bytes()) {
                hit = Some(i);
                break;
            }
        }

        let ix = match hit {
            Some(i) => i,
            None => return Ok(AuthnOutput::Failure(FailureKind::InvalidCredential)),
        };

        // Burn the code.
        let mut remaining = stored_hashes;
        remaining.remove(ix);
        user.attributes.insert(
            "recovery-codes:hashes".into(),
            AttributeValue::Strings(remaining),
        );
        ctx.storage
            .update_user(user)
            .await
            .map_err(|e| AuthnError::Storage(e.to_string()))?;

        ctx.record_amr(Amr::Otp);
        Ok(AuthnOutput::Success {
            credentials_satisfied: vec![CredentialKind::RecoveryCode],
            amr: vec![Amr::Otp],
        })
    }
}

/// Generate `n` random recovery codes. The caller hashes each code before
/// persisting and shows the plaintext set to the user **once**.
pub fn generate_recovery_codes(n: usize) -> Vec<String> {
    (0..n).map(|_| generate_one()).collect()
}

fn generate_one() -> String {
    const ALPHA: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let mut bytes = [0u8; 12];
    OsRng.fill_bytes(&mut bytes);
    let chars: Vec<char> = bytes
        .iter()
        .map(|b| ALPHA[(*b as usize) % ALPHA.len()] as char)
        .collect();
    format!(
        "{}{}{}{}-{}{}{}{}-{}{}{}{}",
        chars[0], chars[1], chars[2], chars[3],
        chars[4], chars[5], chars[6], chars[7],
        chars[8], chars[9], chars[10], chars[11],
    )
}

/// Public helper for enrollment paths.
pub fn code_hash(code: &str, key: &[u8; 32]) -> String {
    hex::encode(token_hash(key, code.as_bytes()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCodeBundle {
    /// Plaintext codes (returned to the user exactly once).
    pub codes: Vec<String>,
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

    fn user(realm: RealmId) -> User {
        User {
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
        }
    }

    async fn fixture(codes: &[&str], key: [u8; 32]) -> (AuthnContext, UserId) {
        let realm = RealmId::new();
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let mut u = user(realm);
        let hashes: Vec<String> = codes.iter().map(|c| code_hash(c, &key)).collect();
        u.attributes
            .insert("recovery-codes:hashes".into(), AttributeValue::Strings(hashes));
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
                enabled: true,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }),
            storage,
            realm_hash_key: key,
            user_id: Some(uid),
            session_id: None,
            amr: vec![],
            locals: Default::default(),
            now: Utc::now(),
        };
        (ctx, uid)
    }

    #[test]
    fn generated_codes_have_dashed_form() {
        let codes = generate_recovery_codes(3);
        assert_eq!(codes.len(), 3);
        for c in &codes {
            assert_eq!(c.len(), 14);
            assert_eq!(c.as_bytes()[4], b'-');
            assert_eq!(c.as_bytes()[9], b'-');
            // No confusables.
            for ch in c.chars() {
                assert!(!matches!(ch, 'I' | 'O' | '0' | '1' | 'L'));
            }
        }
    }

    #[tokio::test]
    async fn valid_code_succeeds_and_is_consumed() {
        let key = [9u8; 32];
        let (mut ctx, uid) = fixture(&["AAAA-BBBB-CCCC", "DDDD-EEEE-FFFF"], key).await;
        let mut form = std::collections::BTreeMap::new();
        form.insert("code".into(), "AAAA-BBBB-CCCC".into());
        let out = RecoveryCodeAuthenticator
            .process(&mut ctx, AuthnInput::Submit(form))
            .await
            .unwrap();
        match out {
            AuthnOutput::Success { credentials_satisfied, .. } => {
                assert_eq!(credentials_satisfied, vec![CredentialKind::RecoveryCode]);
            }
            other => panic!("expected Success, got {other:?}"),
        }
        // Consumed: re-presenting must fail.
        let u = ctx.storage.get_user(ctx.realm_id, uid).await.unwrap();
        let remaining = match u.attributes.get("recovery-codes:hashes") {
            Some(AttributeValue::Strings(v)) => v.clone(),
            _ => vec![],
        };
        assert_eq!(remaining.len(), 1);

        let mut form = std::collections::BTreeMap::new();
        form.insert("code".into(), "AAAA-BBBB-CCCC".into());
        let out = RecoveryCodeAuthenticator
            .process(&mut ctx, AuthnInput::Submit(form))
            .await
            .unwrap();
        assert!(matches!(out, AuthnOutput::Failure(FailureKind::InvalidCredential)));
    }

    #[tokio::test]
    async fn missing_enrollment_signals_requires_enrollment() {
        let (mut ctx, _) = fixture(&[], [0u8; 32]).await;
        let mut form = std::collections::BTreeMap::new();
        form.insert("code".into(), "WHATEVER".into());
        let out = RecoveryCodeAuthenticator
            .process(&mut ctx, AuthnInput::Submit(form))
            .await
            .unwrap();
        assert!(matches!(out, AuthnOutput::Failure(FailureKind::RequiresEnrollment)));
    }
}
