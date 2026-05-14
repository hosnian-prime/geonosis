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

pub mod front_channel_logout;
pub mod logout;
pub mod post_signature;
pub mod redirect;
pub mod request;
pub mod sign;
pub mod xml;

pub use front_channel_logout::{render_front_channel_logout_html, FrontChannelLogoutPeer};
pub use logout::{
    parse_logout_request, serialize_logout_response, LogoutParseError, ParsedLogoutRequest,
};
pub use post_signature::{verify_post_authn_request_signature, PostSigError};
pub use redirect::{
    decode_redirect_payload, verify_redirect_signature, RedirectDecodeError, RedirectSigError,
    RedirectSignatureCheck, REDIRECT_SIG_ALG_RSA_SHA256,
};
pub use request::{parse_authn_request, ParseError as AuthnRequestParseError, ParsedAuthnRequest};
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
    /// PEM-encoded X.509 certs the SP signs AuthnRequest +
    /// LogoutRequest with. The Redirect-binding signature verifier
    /// (`verify_redirect_signature`) tries each cert in order;
    /// rotation is handled by the operator adding the new cert
    /// before retiring the old. Defaults to empty so the field is
    /// forward-compatible with stored SP configs that pre-date the
    /// signature-verification path.
    #[serde(default)]
    pub authn_request_signing_certificates: Vec<String>,
    /// Per `docs/20-saml-idp.md` §"Attribute mapping": operator-
    /// configured mappings that drive the `<AttributeStatement>`
    /// emitted with each assertion. Empty list keeps the hardcoded
    /// default attributes (username, email, given_name,
    /// family_name) — operators opt in to fine-grained control by
    /// supplying mappings. WASM mapper SPI integration adds a
    /// `WasmMapper` variant in v0.1.x; declarative mappings cover
    /// the everyday case in v0.1.
    #[serde(default)]
    pub attribute_mappers: Vec<SamlAttributeMapping>,
    /// Optional front-channel SLO endpoint per `docs/20-saml-idp.md`
    /// §"Single Logout". When the IdP fans logout out to peer SPs
    /// it renders an HTML page with one `<iframe>` per
    /// participating SP whose `src` is this URL. Browser-driven
    /// fan-out clears the SP's cookie state without needing the
    /// SP to expose a back-channel POST endpoint. `None` keeps the
    /// SP in back-channel-only mode (the v0.1 default).
    #[serde(default)]
    pub front_channel_logout_url: Option<Url>,
}

/// One operator-defined `<Attribute>` row to include in the
/// `<AttributeStatement>` per docs/20 §"Attribute mapping".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAttributeMapping {
    /// The SAML `Name` attribute on the emitted `<Attribute>`
    /// element. Conventionally a URI for `nameFormat=uri`.
    pub saml_name: String,
    /// Optional `FriendlyName` SAML attribute.
    #[serde(default)]
    pub friendly_name: Option<String>,
    /// SAML AttributeNameFormat URI; the OASIS uri format is the
    /// default and what every default attribute uses.
    #[serde(default = "default_attribute_name_format")]
    pub name_format: String,
    /// Value source — read from user, static literal, etc.
    pub source: SamlAttributeSource,
}

fn default_attribute_name_format() -> String {
    "urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string()
}

/// Where the value(s) for a [`SamlAttributeMapping`] come from.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SamlAttributeSource {
    /// Fixed value(s) regardless of user.
    Static { values: Vec<String> },
    /// `User.attributes[name]` — multi-valued attribute supported.
    UserAttribute { name: String },
    /// `User.email` (omitted if absent).
    Email,
    /// `User.username` (always present).
    Username,
    /// `User.name.given` if present.
    GivenName,
    /// `User.name.family` if present.
    FamilyName,
    /// `User.name.display` if present.
    DisplayName,
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

/// Resolve `attribute_mappers` against a `User` into a flat list of
/// `SamlAttribute` rows ready for the `<AttributeStatement>`. Empty
/// mappers yield an empty list — the caller decides whether to fall
/// back to default attributes. Per `docs/20-saml-idp.md` §"Attribute
/// mapping".
///
/// Empty resolved values are skipped so an SP never receives an
/// `<Attribute>` with zero `<AttributeValue>` children (a few SP
/// libs treat that as malformed).
pub fn apply_attribute_mappers(
    user: &geonosis_core::User,
    mappings: &[SamlAttributeMapping],
) -> Vec<SamlAttribute> {
    let mut out = Vec::with_capacity(mappings.len());
    for m in mappings {
        let values = resolve_attribute_source(&m.source, user);
        if values.is_empty() {
            continue;
        }
        out.push(SamlAttribute {
            name: m.saml_name.clone(),
            friendly_name: m.friendly_name.clone(),
            name_format: m.name_format.clone(),
            values,
        });
    }
    out
}

fn resolve_attribute_source(
    source: &SamlAttributeSource,
    user: &geonosis_core::User,
) -> Vec<String> {
    match source {
        SamlAttributeSource::Static { values } => values.clone(),
        SamlAttributeSource::UserAttribute { name } => user
            .attributes
            .get(name)
            .map(flatten_attribute_value)
            .unwrap_or_default(),
        SamlAttributeSource::Email => user
            .email
            .as_ref()
            .filter(|s| !s.is_empty())
            .map(|s| vec![s.clone()])
            .unwrap_or_default(),
        SamlAttributeSource::Username => vec![user.username.clone()],
        SamlAttributeSource::GivenName => user
            .name
            .as_ref()
            .and_then(|n| n.given.clone())
            .filter(|s| !s.is_empty())
            .map(|s| vec![s])
            .unwrap_or_default(),
        SamlAttributeSource::FamilyName => user
            .name
            .as_ref()
            .and_then(|n| n.family.clone())
            .filter(|s| !s.is_empty())
            .map(|s| vec![s])
            .unwrap_or_default(),
        SamlAttributeSource::DisplayName => user
            .name
            .as_ref()
            .and_then(|n| n.display.clone())
            .filter(|s| !s.is_empty())
            .map(|s| vec![s])
            .unwrap_or_default(),
    }
}

fn flatten_attribute_value(v: &geonosis_core::AttributeValue) -> Vec<String> {
    use geonosis_core::AttributeValue;
    match v {
        AttributeValue::String(s) => vec![s.clone()],
        AttributeValue::Strings(ss) => ss.clone(),
        AttributeValue::Integer(i) => vec![i.to_string()],
        AttributeValue::Bool(b) => vec![b.to_string()],
        AttributeValue::Float(f) => vec![f.to_string()],
        AttributeValue::Null => vec![],
    }
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
            authn_request_signing_certificates: vec![],
            attribute_mappers: vec![],
            front_channel_logout_url: None,
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
            authn_request_signing_certificates: vec![],
            attribute_mappers: vec![],
            front_channel_logout_url: None,
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

    fn user_with(
        username: &str,
        email: Option<&str>,
        given: Option<&str>,
        family: Option<&str>,
        attrs: Vec<(&str, geonosis_core::AttributeValue)>,
    ) -> geonosis_core::User {
        let mut u = geonosis_core::User {
            username: username.into(),
            email: email.map(String::from),
            email_verified: email.is_some(),
            ..geonosis_core::User::default()
        };
        u.name = Some(geonosis_core::PersonName {
            given: given.map(String::from),
            family: family.map(String::from),
            middle: None,
            display: None,
        });
        for (k, v) in attrs {
            u.attributes.insert(k.into(), v);
        }
        u
    }

    #[test]
    fn empty_mappers_yield_no_attributes() {
        let user = user_with("ada", Some("a@x"), Some("Ada"), Some("L"), vec![]);
        let out = apply_attribute_mappers(&user, &[]);
        assert!(out.is_empty());
    }

    #[test]
    fn static_mapper_emits_literal_values() {
        let user = user_with("ada", None, None, None, vec![]);
        let m = vec![SamlAttributeMapping {
            saml_name: "https://saml.example/role".into(),
            friendly_name: Some("role".into()),
            name_format: default_attribute_name_format(),
            source: SamlAttributeSource::Static {
                values: vec!["editor".into(), "viewer".into()],
            },
        }];
        let out = apply_attribute_mappers(&user, &m);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "https://saml.example/role");
        assert_eq!(out[0].values, vec!["editor".to_string(), "viewer".into()]);
    }

    #[test]
    fn user_attribute_source_reads_attributes() {
        let user = user_with(
            "ada",
            None,
            None,
            None,
            vec![(
                "department",
                geonosis_core::AttributeValue::String("eng".into()),
            )],
        );
        let m = vec![SamlAttributeMapping {
            saml_name: "https://saml.example/department".into(),
            friendly_name: None,
            name_format: default_attribute_name_format(),
            source: SamlAttributeSource::UserAttribute {
                name: "department".into(),
            },
        }];
        let out = apply_attribute_mappers(&user, &m);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].values, vec!["eng".to_string()]);
    }

    #[test]
    fn user_attribute_strings_emits_multi_valued() {
        let user = user_with(
            "ada",
            None,
            None,
            None,
            vec![(
                "groups",
                geonosis_core::AttributeValue::Strings(vec!["a".into(), "b".into()]),
            )],
        );
        let m = vec![SamlAttributeMapping {
            saml_name: "https://saml.example/groups".into(),
            friendly_name: None,
            name_format: default_attribute_name_format(),
            source: SamlAttributeSource::UserAttribute {
                name: "groups".into(),
            },
        }];
        let out = apply_attribute_mappers(&user, &m);
        assert_eq!(out[0].values, vec!["a".to_string(), "b".into()]);
    }

    #[test]
    fn email_givenname_familyname_sources() {
        let user = user_with(
            "ada",
            Some("ada@x.com"),
            Some("Ada"),
            Some("Lovelace"),
            vec![],
        );
        let m = vec![
            SamlAttributeMapping {
                saml_name: "email".into(),
                friendly_name: None,
                name_format: default_attribute_name_format(),
                source: SamlAttributeSource::Email,
            },
            SamlAttributeMapping {
                saml_name: "given".into(),
                friendly_name: None,
                name_format: default_attribute_name_format(),
                source: SamlAttributeSource::GivenName,
            },
            SamlAttributeMapping {
                saml_name: "family".into(),
                friendly_name: None,
                name_format: default_attribute_name_format(),
                source: SamlAttributeSource::FamilyName,
            },
        ];
        let out = apply_attribute_mappers(&user, &m);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].values, vec!["ada@x.com".to_string()]);
        assert_eq!(out[1].values, vec!["Ada".to_string()]);
        assert_eq!(out[2].values, vec!["Lovelace".to_string()]);
    }

    #[test]
    fn empty_sources_skip_emission() {
        // No email on user → email mapper should produce nothing
        // (rather than an empty `<Attribute>`).
        let user = user_with("ada", None, None, None, vec![]);
        let m = vec![SamlAttributeMapping {
            saml_name: "email".into(),
            friendly_name: None,
            name_format: default_attribute_name_format(),
            source: SamlAttributeSource::Email,
        }];
        let out = apply_attribute_mappers(&user, &m);
        assert!(out.is_empty(), "empty-source mapper should skip emission");
    }
}
