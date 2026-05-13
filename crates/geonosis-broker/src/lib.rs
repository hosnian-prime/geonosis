//! Identity broker — Geonosis acting as an OIDC RP / SAML SP towards an
//! external IdP.
//!
//! Per `docs/05-identity-broker.md`:
//! - Generic OIDC + SAML adapters + first-party plugins for Google,
//!   GitHub, Apple, Microsoft.
//! - `BrokerAuthnState` row with 10-minute TTL bridges the outbound
//!   redirect and inbound callback.
//! - Vendor quirks live in the `geonosis:broker-adapter@0.1.0` SPI.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use geonosis_core::attribute::AttributeValue;
use geonosis_core::id::{BrokerAuthnStateId, BrokerLinkId, FlowStateId, IdpId, RealmId, UserId};
use geonosis_core::secret::Secret;

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("unknown idp alias: {0}")]
    UnknownIdp(String),
    #[error("callback state mismatch")]
    StateMismatch,
    #[error("assertion validation: {0}")]
    InvalidAssertion(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdpKind {
    Oidc,
    Saml,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProvider {
    pub id: IdpId,
    pub realm_id: RealmId,
    pub alias: String,
    pub display_name: String,
    pub kind: IdpKind,
    pub config: IdpConfig,
    pub first_login_flow_alias: String,
    pub post_login_flow_alias: Option<String>,
    pub link_only: bool,
    pub adapter_urn: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum IdpConfig {
    Oidc(OidcIdpConfig),
    Saml(SamlIdpConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcIdpConfig {
    pub issuer: String,
    pub discovery_url: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub client_id: String,
    pub client_secret: Option<Secret<String>>,
    pub scopes: Vec<String>,
    pub pkce: bool,
    pub accept_unsigned_userinfo: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlIdpConfig {
    pub entity_id: String,
    pub sso_url: String,
    pub slo_url: Option<String>,
    /// PEM-encoded signing certs (one or more for rotation tolerance).
    pub signing_cert_pems: Vec<String>,
    pub binding_outbound: geonosis_saml_types::SamlBinding,
    pub binding_inbound: geonosis_saml_types::SamlBinding,
    pub name_id_format: geonosis_saml_types::NameIdFormat,
    pub want_assertions_signed: bool,
    pub want_responses_signed: bool,
}

/// State row stored before the redirect, validated on callback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerAuthnState {
    pub id: BrokerAuthnStateId,
    pub realm_id: RealmId,
    pub idp_alias: String,
    /// CSRF random value carried as `state` on the OIDC/SAML round-trip.
    pub state: String,
    pub nonce: Option<String>,
    pub return_to_flow_state: FlowStateId,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl BrokerAuthnState {
    pub fn new(realm: RealmId, idp_alias: String, flow: FlowStateId) -> Self {
        let now = Utc::now();
        Self {
            id: BrokerAuthnStateId::new(),
            realm_id: realm,
            idp_alias,
            state: geonosis_crypto::random::random_token(),
            nonce: Some(geonosis_crypto::random::random_token()),
            return_to_flow_state: flow,
            created_at: now,
            expires_at: now + Duration::minutes(10),
        }
    }

    pub fn assert_state(&self, presented: &str) -> Result<(), BrokerError> {
        if presented == self.state {
            Ok(())
        } else {
            Err(BrokerError::StateMismatch)
        }
    }
}

/// Persistent `user_id ↔ external_id` link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerLink {
    pub id: BrokerLinkId,
    pub realm_id: RealmId,
    pub user_id: UserId,
    pub idp_alias: String,
    pub external_id: String,
    pub external_username: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

/// Result of validating a brokered assertion. The flow executor decides
/// whether to create, link, or reject based on `first_login_flow_alias`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerAssertion {
    pub idp_alias: String,
    pub external_id: String,
    pub issuer: String,
    pub claims: BTreeMap<String, AttributeValue>,
    pub received_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_state_has_csrf_value() {
        let s = BrokerAuthnState::new(RealmId::new(), "google".into(), FlowStateId::new());
        assert!(!s.state.is_empty());
        assert!(s.nonce.as_ref().map_or(false, |n| !n.is_empty()));
    }

    #[test]
    fn state_mismatch_detected() {
        let s = BrokerAuthnState::new(RealmId::new(), "github".into(), FlowStateId::new());
        assert!(s.assert_state("wrong").is_err());
        assert!(s.assert_state(&s.state).is_ok());
    }

    #[test]
    fn config_serializes_with_discriminator() {
        let c = IdpConfig::Oidc(OidcIdpConfig {
            issuer: "https://accounts.google.com".into(),
            discovery_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None,
            client_id: "abc".into(),
            client_secret: None,
            scopes: vec!["openid".into()],
            pkce: true,
            accept_unsigned_userinfo: false,
        });
        let j = serde_json::to_value(&c).unwrap();
        assert_eq!(j.get("kind").and_then(|v| v.as_str()), Some("oidc"));
    }
}
