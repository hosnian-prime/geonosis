//! Broker-adapter SPI surface + first-party vendor implementations.
//!
//! The trait is the in-tree analogue of the `geonosis:broker-adapter@0.1.0`
//! WIT interface — host-side adapter packages (Google, GitHub, Apple,
//! Microsoft) implement it natively so they can ship in the core binary
//! while remaining version-compatible with their WASM equivalents.
//!
//! Hooks (every method has a default that delegates to the generic
//! adapter):
//! - `extra_authorization_params` — extra query params on `/authorize`
//! - `extra_token_params` — extra fields on the token-endpoint POST
//! - `userinfo_override` — vendor-specific userinfo composition (GitHub
//!   builds a synthetic doc from `/user` + `/user/emails`)
//! - `enrich_assertion` — last-mile claim massaging (Apple's private-relay
//!   `email_relay=true` flag, MS `tid` propagation)
//!
//! ## Why this shape differs from `Authenticator`
//!
//! Both broker adapters and authenticators are URN-dispatched plug
//! points, but their lifecycle is different:
//!
//! - An **authenticator** runs in a single `.process()` call per flow
//!   step. The single-method trait fits — `geonosis-flow` calls it
//!   once via [`geonosis_flow::AuthnDispatcher`].
//! - A **broker adapter** plugs into FOUR distinct phases of the OIDC
//!   broker handshake (build authorize URL → callback parse → token
//!   exchange → claims enrichment). Each phase needs different inputs
//!   and produces different outputs.
//!
//! Forcing both into a single-`process()` trait would either lose
//! domain meaning (one big `BrokerEvent` enum) or split the adapter
//! across multiple traits the broker handler then has to coordinate.
//! The multi-hook trait is the natural fit; the divergence from
//! `Authenticator` is intentional, not an inconsistency to flatten.
//!
//! See `crates/geonosis-server/src/authenticators.rs` §"Pattern note"
//! for the cross-reference.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::Deserialize;

use geonosis_core::attribute::AttributeValue;

use crate::oidc::{IdTokenClaims, TokenResponse};
use crate::types::{BrokerAssertion, BrokerError, OidcIdpConfig};

/// Built-in vendor adapter URNs. Matched to a concrete `BrokerAdapter`
/// at boot time.
pub mod urn {
    pub const GENERIC_OIDC: &str = "builtin:broker-adapter:generic-oidc";
    pub const GOOGLE: &str = "builtin:broker-adapter:google";
    pub const GITHUB: &str = "builtin:broker-adapter:github";
    pub const APPLE: &str = "builtin:broker-adapter:apple";
    pub const MICROSOFT: &str = "builtin:broker-adapter:microsoft";
}

#[async_trait]
pub trait BrokerAdapter: Send + Sync {
    fn urn(&self) -> &'static str;

    fn extra_authorization_params(&self, _cfg: &OidcIdpConfig) -> Vec<(&'static str, String)> {
        Vec::new()
    }

    fn extra_token_params(&self, _cfg: &OidcIdpConfig) -> Vec<(&'static str, String)> {
        Vec::new()
    }

    /// Vendor-specific userinfo composition. Default: do nothing; the
    /// generic OIDC adapter relies entirely on the id_token claims.
    async fn userinfo_override(
        &self,
        _http: &reqwest::Client,
        _cfg: &OidcIdpConfig,
        _access_token: &str,
    ) -> Result<Option<BTreeMap<String, AttributeValue>>, BrokerError> {
        Ok(None)
    }

    /// Final adjustments to the assertion before it leaves the broker.
    fn enrich_assertion(&self, _claims: &IdTokenClaims, assertion: &mut BrokerAssertion) {
        let _ = assertion;
    }

    /// Massage the raw token response. The default adapter is a no-op;
    /// Apple's first-login flow uses this to capture the `user`
    /// payload that arrives only on the first authorization.
    fn map_token_response(&self, _token: &TokenResponse) -> BTreeMap<String, AttributeValue> {
        BTreeMap::new()
    }
}

/// Container holding all first-party adapters. Indexed by URN.
pub struct BuiltinAdapters {
    by_urn: BTreeMap<&'static str, Box<dyn BrokerAdapter>>,
}

impl Default for BuiltinAdapters {
    fn default() -> Self {
        let mut by_urn: BTreeMap<&'static str, Box<dyn BrokerAdapter>> = BTreeMap::new();
        by_urn.insert(urn::GENERIC_OIDC, Box::new(GenericOidcAdapter));
        by_urn.insert(urn::GOOGLE, Box::new(GoogleAdapter));
        by_urn.insert(urn::GITHUB, Box::new(GitHubAdapter));
        by_urn.insert(urn::APPLE, Box::new(AppleAdapter));
        by_urn.insert(urn::MICROSOFT, Box::new(MicrosoftAdapter));
        Self { by_urn }
    }
}

impl BuiltinAdapters {
    pub fn get(&self, urn: &str) -> &dyn BrokerAdapter {
        self.by_urn.get(urn).map(|b| b.as_ref()).unwrap_or_else(|| {
            self.by_urn
                .get(urn::GENERIC_OIDC)
                .expect("generic adapter always registered")
                .as_ref()
        })
    }

    pub fn list(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.by_urn.keys().copied()
    }
}

pub struct GenericOidcAdapter;

#[async_trait]
impl BrokerAdapter for GenericOidcAdapter {
    fn urn(&self) -> &'static str {
        urn::GENERIC_OIDC
    }
}

/// Google: forwards `hd` (hosted domain) + `prompt=select_account` per
/// `docs/05-identity-broker.md`. Group claims are emitted under
/// `groups` natively, so no userinfo override is needed.
pub struct GoogleAdapter;

#[async_trait]
impl BrokerAdapter for GoogleAdapter {
    fn urn(&self) -> &'static str {
        urn::GOOGLE
    }

    fn extra_authorization_params(&self, _cfg: &OidcIdpConfig) -> Vec<(&'static str, String)> {
        vec![("prompt", "select_account".into())]
    }
}

/// GitHub: OAuth2 only, no id_token; we synthesize one from `/user` +
/// `/user/emails` (the primary verified mail). Returned as a
/// `userinfo_override` so the OIDC verifier branch can be reused with
/// a manually-constructed pseudo-claims map.
pub struct GitHubAdapter;

#[derive(Deserialize)]
struct GhUser {
    id: u64,
    login: String,
    name: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Deserialize)]
struct GhEmail {
    email: String,
    primary: bool,
    verified: bool,
}

#[async_trait]
impl BrokerAdapter for GitHubAdapter {
    fn urn(&self) -> &'static str {
        urn::GITHUB
    }

    async fn userinfo_override(
        &self,
        http: &reqwest::Client,
        _cfg: &OidcIdpConfig,
        access_token: &str,
    ) -> Result<Option<BTreeMap<String, AttributeValue>>, BrokerError> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::ACCEPT,
            "application/vnd.github+json".parse().unwrap(),
        );
        headers.insert(
            reqwest::header::USER_AGENT,
            "geonosis-broker".parse().unwrap(),
        );
        let user: GhUser = http
            .get("https://api.github.com/user")
            .bearer_auth(access_token)
            .headers(headers.clone())
            .send()
            .await
            .map_err(|e| BrokerError::Transport(e.to_string()))?
            .error_for_status()
            .map_err(|e| BrokerError::Transport(e.to_string()))?
            .json()
            .await
            .map_err(|e| BrokerError::Transport(e.to_string()))?;
        let emails: Vec<GhEmail> = http
            .get("https://api.github.com/user/emails")
            .bearer_auth(access_token)
            .headers(headers)
            .send()
            .await
            .map_err(|e| BrokerError::Transport(e.to_string()))?
            .error_for_status()
            .map_err(|e| BrokerError::Transport(e.to_string()))?
            .json()
            .await
            .map_err(|e| BrokerError::Transport(e.to_string()))?;
        let primary = emails.iter().find(|e| e.primary && e.verified);
        let mut out: BTreeMap<String, AttributeValue> = BTreeMap::new();
        out.insert("sub".into(), AttributeValue::String(user.id.to_string()));
        out.insert(
            "preferred_username".into(),
            AttributeValue::String(user.login.clone()),
        );
        if let Some(n) = user.name {
            out.insert("name".into(), AttributeValue::String(n));
        }
        if let Some(p) = primary {
            out.insert("email".into(), AttributeValue::String(p.email.clone()));
            out.insert("email_verified".into(), AttributeValue::Bool(true));
        }
        if let Some(av) = user.avatar_url {
            out.insert("picture".into(), AttributeValue::String(av));
        }
        Ok(Some(out))
    }
}

/// Apple: `response_mode=form_post` + first-login `user` JSON payload
/// (the only place where Apple shares the user's name).
pub struct AppleAdapter;

#[async_trait]
impl BrokerAdapter for AppleAdapter {
    fn urn(&self) -> &'static str {
        urn::APPLE
    }

    fn extra_authorization_params(&self, _cfg: &OidcIdpConfig) -> Vec<(&'static str, String)> {
        vec![
            ("response_mode", "form_post".into()),
            ("scope", "openid email name".into()),
        ]
    }

    fn enrich_assertion(&self, claims: &IdTokenClaims, assertion: &mut BrokerAssertion) {
        if let Some(email) = &claims.email {
            // privaterelay.appleid.com marks Apple's relay form.
            if email.ends_with("@privaterelay.appleid.com") {
                assertion
                    .claims
                    .insert("email_relay".into(), AttributeValue::Bool(true));
            }
        }
    }
}

/// Microsoft Entra (Azure AD): `tid` propagation + `prompt=select_account`
/// for the `common` tenant.
pub struct MicrosoftAdapter;

#[async_trait]
impl BrokerAdapter for MicrosoftAdapter {
    fn urn(&self) -> &'static str {
        urn::MICROSOFT
    }

    fn extra_authorization_params(&self, _cfg: &OidcIdpConfig) -> Vec<(&'static str, String)> {
        vec![("prompt", "select_account".into())]
    }

    fn enrich_assertion(&self, claims: &IdTokenClaims, assertion: &mut BrokerAssertion) {
        if let Some(tid) = claims.extra.get("tid").and_then(|v| v.as_str()) {
            assertion
                .claims
                .insert("tid".into(), AttributeValue::String(tid.to_string()));
        }
        if let Some(oid) = claims.extra.get("oid").and_then(|v| v.as_str()) {
            assertion
                .claims
                .insert("oid".into(), AttributeValue::String(oid.to_string()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::IdTokenClaims;

    fn claims_with(extra: BTreeMap<String, serde_json::Value>) -> IdTokenClaims {
        IdTokenClaims {
            iss: "iss".into(),
            sub: "sub".into(),
            aud: serde_json::json!("aud"),
            exp: 0,
            iat: 0,
            nbf: None,
            nonce: None,
            azp: None,
            email: None,
            email_verified: None,
            preferred_username: None,
            name: None,
            given_name: None,
            family_name: None,
            extra,
        }
    }

    #[test]
    fn google_emits_select_account() {
        let cfg = OidcIdpConfig {
            issuer: "https://accounts.google.com".into(),
            discovery_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None,
            client_id: "x".into(),
            client_secret: None,
            scopes: vec![],
            pkce: true,
            accept_unsigned_userinfo: false,
            client_auth: crate::ClientAuthMethod::None,
            client_assertion_key: None,
            prompt: None,
            response_mode: None,
        };
        let params = GoogleAdapter.extra_authorization_params(&cfg);
        assert!(params
            .iter()
            .any(|(k, v)| *k == "prompt" && v == "select_account"));
    }

    #[test]
    fn apple_flags_private_relay() {
        let mut a = BrokerAssertion {
            idp_alias: "apple".into(),
            external_id: "x".into(),
            issuer: "x".into(),
            claims: BTreeMap::new(),
            received_at: chrono::Utc::now(),
            expires_at: None,
        };
        let mut c = claims_with(BTreeMap::new());
        c.email = Some("padme@privaterelay.appleid.com".into());
        AppleAdapter.enrich_assertion(&c, &mut a);
        assert!(matches!(
            a.claims.get("email_relay"),
            Some(AttributeValue::Bool(true))
        ));
    }

    #[test]
    fn microsoft_propagates_tid() {
        let mut a = BrokerAssertion {
            idp_alias: "microsoft".into(),
            external_id: "x".into(),
            issuer: "x".into(),
            claims: BTreeMap::new(),
            received_at: chrono::Utc::now(),
            expires_at: None,
        };
        let mut extra = BTreeMap::new();
        extra.insert("tid".into(), serde_json::json!("tenant-id"));
        let c = claims_with(extra);
        MicrosoftAdapter.enrich_assertion(&c, &mut a);
        assert!(matches!(
            a.claims.get("tid"),
            Some(AttributeValue::String(s)) if s == "tenant-id"
        ));
    }

    #[test]
    fn registry_covers_all_first_party() {
        let r = BuiltinAdapters::default();
        let names: Vec<&'static str> = r.list().collect();
        for u in [
            urn::GENERIC_OIDC,
            urn::GOOGLE,
            urn::GITHUB,
            urn::APPLE,
            urn::MICROSOFT,
        ] {
            assert!(names.contains(&u), "missing {u}");
        }
    }
}
