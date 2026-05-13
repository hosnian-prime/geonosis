//! Realm (tenant) configuration.

use std::collections::BTreeMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::common::{Amr, JwsAlgorithm, SenderConstraint, SslRequirement};
use crate::id::{GroupId, RealmId, RoleId};

/// A tenant inside a Geonosis deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Realm {
    pub id: RealmId,
    /// URL-safe slug; matches `[a-z0-9-]{2,64}`. Reserved: `admin`, `master`,
    /// `well-known`.
    pub slug: String,
    pub display_name: String,
    pub frontend_url: Option<Url>,
    pub admin_frontend_url: Option<Url>,
    pub enabled: bool,
    pub ssl_required: SslRequirement,

    pub login: LoginSettings,
    pub registration: RegistrationPolicy,
    pub session_policy: SessionPolicy,
    pub token_policy: TokenPolicy,
    pub brute_force: BruteForcePolicy,
    pub password_policy: PasswordPolicy,
    pub otp_policy: OtpPolicy,
    pub webauthn_policy: WebauthnPolicy,
    pub acr_policy: AcrPolicy,
    pub sender_constraint_default: SenderConstraint,

    pub theme_binding: ThemeBinding,
    pub localization: LocalizationPolicy,

    pub events: EventConfig,
    pub default_groups: Vec<GroupId>,
    pub default_roles: DefaultRoles,
    pub organizations_enabled: bool,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginSettings {
    pub remember_me_enabled: bool,
    pub login_with_email_allowed: bool,
    pub registration_allowed: bool,
    pub reset_password_allowed: bool,
    pub edit_username_allowed: bool,
    pub verify_email_required: bool,
    pub duplicate_emails_allowed: bool,
}

impl Default for LoginSettings {
    fn default() -> Self {
        Self {
            remember_me_enabled: true,
            login_with_email_allowed: true,
            registration_allowed: false,
            reset_password_allowed: true,
            edit_username_allowed: false,
            verify_email_required: false,
            duplicate_emails_allowed: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistrationPolicy {
    pub enabled: bool,
    pub email_as_username: bool,
    pub require_terms_acceptance: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPolicy {
    #[serde(with = "duration_secs")]
    pub sso_session_idle: Duration,
    #[serde(with = "duration_secs")]
    pub sso_session_max: Duration,
    #[serde(with = "duration_secs")]
    pub remember_me_idle: Duration,
    #[serde(with = "duration_secs")]
    pub remember_me_max: Duration,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            sso_session_idle: Duration::from_secs(30 * 60),
            sso_session_max: Duration::from_secs(10 * 3600),
            remember_me_idle: Duration::from_secs(60 * 24 * 3600),
            remember_me_max: Duration::from_secs(180 * 24 * 3600),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPolicy {
    #[serde(with = "duration_secs")]
    pub access_token_lifespan: Duration,
    #[serde(with = "duration_secs")]
    pub access_token_lifespan_implicit: Duration,
    #[serde(with = "duration_secs")]
    pub refresh_token_lifespan: Duration,
    #[serde(with = "duration_secs")]
    pub auth_code_lifespan: Duration,
    pub revoke_refresh_token_on_use: bool,
    pub refresh_token_max_reuse: u32,
    pub default_signing_alg: JwsAlgorithm,
    pub allowed_signing_algs: Vec<JwsAlgorithm>,
    /// `kid` of the active signing key, when one is bound. Optional —
    /// callers may resolve via key-state instead.
    pub signing_key_alias: Option<String>,
}

impl Default for TokenPolicy {
    fn default() -> Self {
        Self {
            access_token_lifespan: Duration::from_secs(5 * 60),
            access_token_lifespan_implicit: Duration::from_secs(15 * 60),
            refresh_token_lifespan: Duration::from_secs(30 * 24 * 3600),
            auth_code_lifespan: Duration::from_secs(60),
            revoke_refresh_token_on_use: true,
            refresh_token_max_reuse: 0,
            default_signing_alg: JwsAlgorithm::RS256,
            allowed_signing_algs: vec![
                JwsAlgorithm::RS256,
                JwsAlgorithm::ES256,
                JwsAlgorithm::EdDSA,
            ],
            signing_key_alias: None,
        }
    }
}

/// Per-user brute-force lockout configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForcePolicy {
    pub enabled: bool,
    pub max_login_failures: u32,
    #[serde(with = "duration_secs")]
    pub wait_increment: Duration,
    #[serde(with = "duration_secs")]
    pub max_wait: Duration,
    #[serde(with = "duration_secs")]
    pub failure_reset: Duration,
    pub permanent_lockout: bool,
}

impl Default for BruteForcePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            max_login_failures: 30,
            wait_increment: Duration::from_secs(60),
            max_wait: Duration::from_secs(15 * 60),
            failure_reset: Duration::from_secs(12 * 3600),
            permanent_lockout: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub rules: Vec<PasswordRule>,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            rules: vec![
                PasswordRule::Length { min: 8 },
                PasswordRule::HashIterations { iterations: 3 },
                PasswordRule::HashAlgorithm {
                    algorithm: "argon2id".into(),
                },
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PasswordRule {
    Length { min: u32 },
    SpecialChars { min: u32 },
    UpperCase { min: u32 },
    LowerCase { min: u32 },
    Digits { min: u32 },
    HashIterations { iterations: u32 },
    HashAlgorithm { algorithm: String },
    NotUsername,
    NotEmail,
    PasswordHistory { count: u32 },
    /// Reject passwords found in the haveibeenpwned list (offline corpus).
    Pwned,
    /// Maximum age in days before forced reset.
    Expire { days: u32 },
    /// Disallow passwords matching this regex (admin policy).
    BlacklistRegex { pattern: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpPolicy {
    pub kind: OtpKind,
    pub algorithm: OtpAlgorithm,
    pub digits: u32,
    pub look_ahead_window: u32,
    pub period_seconds: u32,
    pub initial_counter: u64,
}

impl Default for OtpPolicy {
    fn default() -> Self {
        Self {
            kind: OtpKind::Totp,
            algorithm: OtpAlgorithm::Sha1,
            digits: 6,
            look_ahead_window: 1,
            period_seconds: 30,
            initial_counter: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OtpKind {
    Totp,
    Hotp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OtpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnPolicy {
    pub relying_party_id: Option<String>,
    pub relying_party_name: String,
    pub signature_algorithms: Vec<String>,
    pub attestation_conveyance_preference: String,
    pub authenticator_attachment: Option<String>,
    pub require_resident_key: bool,
    pub user_verification: String,
    /// If true, the assertion step is treated as MFA. v0.1 only supports
    /// step assertion; full passkey lifecycle lives in v0.2.
    pub assertion_as_step: bool,
}

impl Default for WebauthnPolicy {
    fn default() -> Self {
        Self {
            relying_party_id: None,
            relying_party_name: "Geonosis".into(),
            signature_algorithms: vec!["ES256".into(), "RS256".into(), "EdDSA".into()],
            attestation_conveyance_preference: "none".into(),
            authenticator_attachment: None,
            require_resident_key: false,
            user_verification: "preferred".into(),
            assertion_as_step: true,
        }
    }
}

/// ACR level policy. Maps `acr_values` request to a concrete authn requirement.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AcrPolicy {
    pub levels: Vec<AcrLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcrLevel {
    pub value: String,
    pub display_name: String,
    pub require: AcrRequirement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AcrRequirement {
    Any,
    AmrContains(Vec<Amr>),
    AllOf(Vec<AcrRequirement>),
    AnyOf(Vec<AcrRequirement>),
    SenderConstrained(SenderConstraint),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThemeBinding {
    pub login: Option<String>,
    pub admin: Option<String>,
    pub email: Option<String>,
    pub account: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalizationPolicy {
    pub default_locale: String,
    pub supported_locales: Vec<String>,
}

impl Default for LocalizationPolicy {
    fn default() -> Self {
        Self {
            default_locale: "en-US".into(),
            supported_locales: vec!["en-US".into()],
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventConfig {
    pub enabled: bool,
    pub admin_enabled: bool,
    pub login_enabled: bool,
    pub events_listeners: Vec<String>,
    pub enabled_events: Vec<String>,
    pub retention_days: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefaultRoles {
    pub realm_roles: Vec<RoleId>,
    pub client_roles: BTreeMap<String, Vec<RoleId>>,
}

// Helper module for serializing Duration as seconds (i64). Keeps JSON form
// compact and matches the admin REST API surface in `08-admin-ui.md`.
mod duration_secs {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(d: &Duration, ser: S) -> Result<S::Ok, S::Error> {
        (d.as_secs() as i64).serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Duration, D::Error> {
        let s = i64::deserialize(de)?;
        let s = u64::try_from(s).map_err(serde::de::Error::custom)?;
        Ok(Duration::from_secs(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::RealmId;

    #[test]
    fn default_token_policy_has_60s_auth_code() {
        let p = TokenPolicy::default();
        assert_eq!(p.auth_code_lifespan, Duration::from_secs(60));
    }

    #[test]
    fn default_token_policy_allows_only_asymmetric() {
        let p = TokenPolicy::default();
        for alg in &p.allowed_signing_algs {
            assert!(alg.is_asymmetric());
        }
    }

    #[test]
    fn realm_serde_roundtrip() {
        let r = Realm {
            id: RealmId::new(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            frontend_url: None,
            admin_frontend_url: None,
            enabled: true,
            ssl_required: SslRequirement::ExternalRequests,
            login: LoginSettings::default(),
            registration: RegistrationPolicy::default(),
            session_policy: SessionPolicy::default(),
            token_policy: TokenPolicy::default(),
            brute_force: BruteForcePolicy::default(),
            password_policy: PasswordPolicy::default(),
            otp_policy: OtpPolicy::default(),
            webauthn_policy: WebauthnPolicy::default(),
            acr_policy: AcrPolicy::default(),
            sender_constraint_default: SenderConstraint::None,
            theme_binding: ThemeBinding::default(),
            localization: LocalizationPolicy::default(),
            events: EventConfig::default(),
            default_groups: vec![],
            default_roles: DefaultRoles::default(),
            organizations_enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let j = serde_json::to_string(&r).unwrap();
        let back: Realm = serde_json::from_str(&j).unwrap();
        assert_eq!(back.slug, "acme");
        assert_eq!(back.token_policy.auth_code_lifespan, Duration::from_secs(60));
    }
}
