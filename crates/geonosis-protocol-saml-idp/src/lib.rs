//! SAML 2.0 Identity Provider — issuing assertions to downstream SPs.
//!
//! Per `docs/20-saml-idp.md`:
//! - Multiple Active signing keys permitted (unlike OIDC) for SP metadata
//!   caching tolerance.
//! - Per-(user, SP) persistent NameID stored in `SamlPersistentId`.
//! - Assertions signed mandatorily; encryption optional per SP config.
//!
//! Module layout:
//! - [`xml`] — canonical XML serialisation of assertions, responses,
//!   and IdP metadata. Sign-time + verify-time canonicalisation
//!   discipline documented inline.
//! - [`sign`] — XML-DSig signing of an assertion against the realm's
//!   active RSA-SHA256 key via the `KeyManagementService` trait.

pub mod logout;
pub mod request;
pub mod sign;
pub mod xml;

pub use logout::{
    parse_logout_request, serialize_logout_response, LogoutParseError, ParsedLogoutRequest,
};
pub use request::{parse_authn_request, ParsedAuthnRequest, ParseError as AuthnRequestParseError};
pub use sign::{sign_assertion, KeyInfoMaterial, SignError};
pub use xml::{
    embed_signature, render_signature_block, render_signed_info, serialize_assertion,
    serialize_idp_metadata, serialize_response, IdpMetadataInput,
};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use geonosis_core::id::{KeyId, RealmId, UserId};
use geonosis_saml_types::{NameIdFormat, SamlAssertion, SamlAttribute, SamlBinding};

#[derive(Debug, Error)]
pub enum SamlIdpError {
    #[error("invalid SP config: {0}")]
    InvalidSp(String),
    #[error("signing: {0}")]
    Sign(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSpClientConfig {
    pub entity_id: String,
    pub acs_urls: Vec<Url>,
    pub slo_url: Option<Url>,
    pub binding: SamlBinding,
    pub name_id_format: NameIdFormat,
    pub want_authnrequest_signed: bool,
    pub want_assertions_encrypted: bool,
    pub signing_key: KeyId,
    pub default_audience: Option<String>,
    pub session_index_strategy: SessionIndexStrategy,
}

impl SamlSpClientConfig {
    /// Parse the typed config out of the `Client.saml_sp_config`
    /// JSONB blob. Returns `Err` with a stable error code when the
    /// blob fails schema validation — the admin REST CRUD path
    /// uses this for round-trip validation before persisting.
    pub fn try_from_value(v: &serde_json::Value) -> Result<Self, SamlIdpError> {
        serde_json::from_value(v.clone()).map_err(|e| SamlIdpError::InvalidSp(e.to_string()))
    }

    /// Render the typed config back into JSON for storage on
    /// `Client.saml_sp_config`. Infallible — every field implements
    /// `Serialize` with documented JSON form.
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("SamlSpClientConfig serializes")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionIndexStrategy {
    UseSessionId,
    Random,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlPersistentId {
    pub realm_id: RealmId,
    pub user_id: UserId,
    pub sp_entity_id: String,
    pub name_id: String,
    pub created_at: DateTime<Utc>,
}

/// Build an unsigned `SamlAssertion` for a `(user, SP)` pair. The actual
/// XML serialization + XML-DSig signing is wired into the server crate.
pub fn build_assertion(
    issuer: &str,
    sp: &SamlSpClientConfig,
    name_id: &str,
    session_index: &str,
    attributes: Vec<SamlAttribute>,
    authn_class_ref: Option<String>,
    ttl_minutes: i64,
) -> SamlAssertion {
    let now = Utc::now();
    SamlAssertion {
        id: format!("_{}", geonosis_crypto::random::random_token()),
        issuer: issuer.into(),
        subject_name_id: name_id.into(),
        subject_name_id_format: sp.name_id_format,
        audience: vec![sp.entity_id.clone()],
        issue_instant: now,
        not_before: now - Duration::seconds(30),
        not_on_or_after: now + Duration::minutes(ttl_minutes),
        destination: sp.acs_urls.first().cloned(),
        attributes,
        authn_context_class_ref: authn_class_ref,
        authn_instant: now,
        session_index: Some(session_index.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_sp() -> SamlSpClientConfig {
        SamlSpClientConfig {
            entity_id: "https://sp.example".into(),
            acs_urls: vec![Url::parse("https://sp.example/acs").unwrap()],
            slo_url: None,
            binding: SamlBinding::HttpPost,
            name_id_format: NameIdFormat::EmailAddress,
            want_authnrequest_signed: false,
            want_assertions_encrypted: false,
            signing_key: KeyId::new(),
            default_audience: None,
            session_index_strategy: SessionIndexStrategy::UseSessionId,
        }
    }

    #[test]
    fn sp_config_round_trips_through_json_value() {
        let sp = sample_sp();
        let v = sp.to_value();
        let parsed = SamlSpClientConfig::try_from_value(&v).unwrap();
        assert_eq!(parsed.entity_id, sp.entity_id);
        assert_eq!(parsed.acs_urls.len(), 1);
        assert!(matches!(parsed.binding, SamlBinding::HttpPost));
        assert!(matches!(
            parsed.session_index_strategy,
            SessionIndexStrategy::UseSessionId
        ));
    }

    #[test]
    fn sp_config_rejects_invalid_json_with_invalid_sp_error() {
        let bad = serde_json::json!({ "entity_id": "x" }); // missing required fields
        let err = SamlSpClientConfig::try_from_value(&bad).unwrap_err();
        assert!(matches!(err, SamlIdpError::InvalidSp(_)));
    }

    #[test]
    fn assertion_carries_audience_and_session_index() {
        let sp = SamlSpClientConfig {
            entity_id: "sp.example".into(),
            acs_urls: vec![Url::parse("https://sp.example/acs").unwrap()],
            slo_url: None,
            binding: SamlBinding::HttpPost,
            name_id_format: NameIdFormat::Persistent,
            want_authnrequest_signed: false,
            want_assertions_encrypted: false,
            signing_key: KeyId::new(),
            default_audience: None,
            session_index_strategy: SessionIndexStrategy::UseSessionId,
        };
        let a = build_assertion(
            "https://idp.example",
            &sp,
            "nameid-1",
            "session-1",
            vec![],
            Some("urn:oasis:names:tc:SAML:2.0:ac:classes:Password".into()),
            5,
        );
        assert_eq!(a.audience, vec!["sp.example".to_string()]);
        assert_eq!(a.session_index.as_deref(), Some("session-1"));
        assert!(a.not_on_or_after > a.issue_instant);
    }
}
