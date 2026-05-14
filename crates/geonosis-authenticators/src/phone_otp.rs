//! Built-in `phone-otp` authenticator — sends a TOTP-style numeric code
//! over SMS via the wired `SmsSender` SPI seam.
//!
//! Per `docs/06-auth-flows.md`:
//! > SMS one-time password — relies on a SMS-sender SPI plugin
//! > (`geonosis:event` listener with `kind=sms`); v0.1 ships the
//! > contract and a reference Twilio plugin behind `spi-twilio`.
//!
//! This authenticator carries the contract + the code-issue / verify
//! logic. The actual Twilio plugin lives behind `spi-twilio`; v0.1
//! ships a `RecordingSmsSender` for tests.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Duration;
use rand::rngs::OsRng;
use rand::RngCore;

use geonosis_core::attribute::AttributeValue;
use geonosis_core::{Amr, CredentialKind};
use geonosis_crypto::hash::{ct_eq, token_hash};

use crate::context::AuthnContext;
use crate::traits::{
    AuthnError, AuthnInput, AuthnOutput, Authenticator, FailureKind, RenderInstruction,
};

/// TTL of a single SMS code.
pub const PHONE_OTP_TTL_MINUTES: i64 = 5;

#[async_trait]
pub trait SmsSender: Send + Sync {
    async fn send(&self, msisdn: &str, body: &str) -> Result<(), String>;
}

pub struct PhoneOtpAuthenticator {
    pub sender: Arc<dyn SmsSender>,
    /// Number of digits in the OTP. v0.1 default: 6.
    pub digits: u32,
}

impl PhoneOtpAuthenticator {
    pub fn new(sender: Arc<dyn SmsSender>) -> Self {
        Self { sender, digits: 6 }
    }
}

#[async_trait]
impl Authenticator for PhoneOtpAuthenticator {
    fn provider_id(&self) -> &'static str {
        "builtin:authn:phone-otp"
    }

    async fn process(
        &self,
        ctx: &mut AuthnContext,
        input: AuthnInput,
    ) -> Result<AuthnOutput, AuthnError> {
        match input {
            AuthnInput::Init => Ok(AuthnOutput::Continue {
                render: RenderInstruction::new("login/phone-otp.html"),
            }),
            AuthnInput::Resume => Ok(AuthnOutput::Continue {
                render: RenderInstruction::new("login/phone-otp.html"),
            }),
            AuthnInput::Submit(form) => {
                if let Some(code) = form.get("code") {
                    self.verify(ctx, code).await
                } else {
                    self.issue(ctx).await
                }
            }
        }
    }
}

impl PhoneOtpAuthenticator {
    async fn issue(&self, ctx: &mut AuthnContext) -> Result<AuthnOutput, AuthnError> {
        let user_id = ctx
            .user_id
            .ok_or_else(|| AuthnError::Invalid("phone-otp requires resolved user".into()))?;
        let mut user = ctx
            .storage
            .get_user(ctx.realm_id, user_id)
            .await
            .map_err(|e| AuthnError::Storage(e.to_string()))?;
        let msisdn = user
            .attributes
            .get("phone:msisdn")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthnError::Invalid("user has no phone number enrolled".into()))?
            .to_string();

        let code = random_digits(self.digits);
        let hash = hex::encode(token_hash(&ctx.realm_hash_key, code.as_bytes()));
        let expires = ctx.now + Duration::minutes(PHONE_OTP_TTL_MINUTES);
        user.attributes
            .insert("phone-otp:hash".into(), AttributeValue::String(hash));
        user.attributes.insert(
            "phone-otp:expires-unix".into(),
            AttributeValue::Integer(expires.timestamp()),
        );
        ctx.storage
            .update_user(user)
            .await
            .map_err(|e| AuthnError::Storage(e.to_string()))?;

        self.sender
            .send(&msisdn, &format!("Your verification code: {code}"))
            .await
            .map_err(AuthnError::Internal)?;

        Ok(AuthnOutput::Continue {
            render: RenderInstruction::new("login/phone-otp-sent.html"),
        })
    }

    async fn verify(
        &self,
        ctx: &mut AuthnContext,
        code: &str,
    ) -> Result<AuthnOutput, AuthnError> {
        let user_id = ctx
            .user_id
            .ok_or_else(|| AuthnError::Invalid("phone-otp verify requires resolved user".into()))?;
        let mut user = ctx
            .storage
            .get_user(ctx.realm_id, user_id)
            .await
            .map_err(|e| AuthnError::Storage(e.to_string()))?;
        let stored = match user.attributes.get("phone-otp:hash") {
            Some(AttributeValue::String(s)) => s.clone(),
            _ => return Ok(AuthnOutput::Failure(FailureKind::InvalidCredential)),
        };
        let expires = match user.attributes.get("phone-otp:expires-unix") {
            Some(AttributeValue::Integer(t)) => *t,
            _ => 0,
        };
        if expires < ctx.now.timestamp() {
            return Ok(AuthnOutput::Failure(FailureKind::InvalidCredential));
        }
        let presented = hex::encode(token_hash(&ctx.realm_hash_key, code.trim().as_bytes()));
        if !ct_eq(stored.as_bytes(), presented.as_bytes()) {
            return Ok(AuthnOutput::Failure(FailureKind::InvalidCredential));
        }
        user.attributes.remove("phone-otp:hash");
        user.attributes.remove("phone-otp:expires-unix");
        ctx.storage
            .update_user(user)
            .await
            .map_err(|e| AuthnError::Storage(e.to_string()))?;
        ctx.record_amr(Amr::Sms);
        Ok(AuthnOutput::Success {
            credentials_satisfied: vec![CredentialKind::Otp],
            amr: vec![Amr::Sms],
        })
    }
}

fn random_digits(n: u32) -> String {
    let mut out = String::with_capacity(n as usize);
    let mut buf = [0u8; 8];
    OsRng.fill_bytes(&mut buf);
    let mut v = u64::from_le_bytes(buf);
    for _ in 0..n {
        out.push(char::from(b'0' + (v % 10) as u8));
        v /= 10;
    }
    out
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

    struct RecorderSms {
        sent: Mutex<Vec<(String, String)>>,
    }

    #[async_trait]
    impl SmsSender for RecorderSms {
        async fn send(&self, m: &str, b: &str) -> Result<(), String> {
            self.sent.lock().unwrap().push((m.into(), b.into()));
            Ok(())
        }
    }

    async fn fixture(phone: Option<&str>) -> (AuthnContext, UserId, Arc<RecorderSms>) {
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
        if let Some(p) = phone {
            u.attributes
                .insert("phone:msisdn".into(), AttributeValue::String(p.into()));
        }
        let uid = u.id;
        storage.create_user(u).await.unwrap();
        let rec = Arc::new(RecorderSms { sent: Mutex::new(vec![]) });
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
            realm_hash_key: [21u8; 32],
            user_id: Some(uid),
            session_id: None,
            amr: vec![],
            locals: Default::default(),
            now: Utc::now(),
            brute_force: geonosis_core::realm::BruteForcePolicy::default(),
        };
        (ctx, uid, rec)
    }

    #[tokio::test]
    async fn issue_sends_sms_with_code() {
        let (mut ctx, _uid, rec) = fixture(Some("+15551234567")).await;
        let a = PhoneOtpAuthenticator::new(rec.clone());
        let form = std::collections::BTreeMap::new();
        let out = a.process(&mut ctx, AuthnInput::Submit(form)).await.unwrap();
        assert!(matches!(out, AuthnOutput::Continue { .. }));
        let sent = rec.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "+15551234567");
        assert!(sent[0].1.contains("Your verification code:"));
    }

    #[tokio::test]
    async fn verify_succeeds_with_correct_code() {
        let (mut ctx, _uid, rec) = fixture(Some("+15551234567")).await;
        let a = PhoneOtpAuthenticator::new(rec.clone());
        let form = std::collections::BTreeMap::new();
        a.process(&mut ctx, AuthnInput::Submit(form)).await.unwrap();
        let body = rec.sent.lock().unwrap()[0].1.clone();
        // Last 6 chars of the body are the code.
        let code = body.split_whitespace().last().unwrap().to_string();

        let mut form = std::collections::BTreeMap::new();
        form.insert("code".into(), code);
        let out = a.process(&mut ctx, AuthnInput::Submit(form)).await.unwrap();
        assert!(matches!(out, AuthnOutput::Success { .. }));
        assert!(ctx.amr.contains(&Amr::Sms));
    }

    #[tokio::test]
    async fn verify_wrong_code_invalid_credential() {
        let (mut ctx, _uid, rec) = fixture(Some("+15551234567")).await;
        let a = PhoneOtpAuthenticator::new(rec.clone());
        let form = std::collections::BTreeMap::new();
        a.process(&mut ctx, AuthnInput::Submit(form)).await.unwrap();
        let mut form = std::collections::BTreeMap::new();
        form.insert("code".into(), "000000".into());
        let out = a.process(&mut ctx, AuthnInput::Submit(form)).await.unwrap();
        assert!(matches!(out, AuthnOutput::Failure(FailureKind::InvalidCredential)));
    }

    #[tokio::test]
    async fn no_phone_enrolled_errors_invalid() {
        let (mut ctx, _uid, rec) = fixture(None).await;
        let a = PhoneOtpAuthenticator::new(rec.clone());
        let form = std::collections::BTreeMap::new();
        let err = a.process(&mut ctx, AuthnInput::Submit(form)).await.unwrap_err();
        assert!(matches!(err, AuthnError::Invalid(_)));
    }
}
