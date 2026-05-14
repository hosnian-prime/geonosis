//! `/authorize` request parsing + validation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use geonosis_core::scope::parse_scope_string;
use geonosis_core::{Client, ClientKind, ScopeName};

/// Allowed response_type values. Geonosis is OAuth 2.1 — `code` only.
/// Implicit and Hybrid are intentionally absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResponseType {
    Code,
}

/// Parsed `/authorize` request — every field validated and typed.
#[derive(Debug, Clone)]
pub struct AuthorizeRequest {
    pub response_type: ResponseType,
    pub client_id: String,
    pub redirect_uri: Url,
    pub scope: Vec<ScopeName>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub acr_values: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<i64>,
    pub login_hint: Option<String>,
    /// Other parameters echoed back as-is (`ui_locales` etc.).
    pub extra: BTreeMap<String, String>,
}

#[derive(Debug, Error)]
pub enum AuthorizeRequestError {
    #[error("missing required parameter: {0}")]
    Missing(&'static str),
    #[error("invalid parameter: {0}: {1}")]
    Invalid(&'static str, String),
    #[error("response_type must be 'code'")]
    UnsupportedResponseType,
    #[error("redirect_uri does not match any registered URI for the client")]
    RedirectMismatch,
    #[error("PKCE required for this client (public client_id, FAPI Baseline, or admin policy)")]
    PkceRequired,
    #[error("code_challenge_method 'plain' is forbidden")]
    PkcePlainRejected,
    #[error("openid scope requires nonce")]
    NonceRequired,
    #[error("unsupported scope: {0}")]
    UnsupportedScope(String),
}

impl AuthorizeRequest {
    pub fn parse(params: BTreeMap<String, String>) -> Result<Self, AuthorizeRequestError> {
        let rt = params
            .get("response_type")
            .ok_or(AuthorizeRequestError::Missing("response_type"))?;
        if rt != "code" {
            return Err(AuthorizeRequestError::UnsupportedResponseType);
        }
        let client_id = params
            .get("client_id")
            .cloned()
            .ok_or(AuthorizeRequestError::Missing("client_id"))?;
        let redirect_uri_raw = params
            .get("redirect_uri")
            .cloned()
            .ok_or(AuthorizeRequestError::Missing("redirect_uri"))?;
        let redirect_uri = Url::parse(&redirect_uri_raw)
            .map_err(|e| AuthorizeRequestError::Invalid("redirect_uri", e.to_string()))?;

        let scope = parse_scope_string(params.get("scope").map(String::as_str).unwrap_or(""))
            .map_err(|e| AuthorizeRequestError::Invalid("scope", e.0))?;

        let code_challenge = params.get("code_challenge").cloned();
        let code_challenge_method = params.get("code_challenge_method").cloned();
        if let Some(m) = &code_challenge_method {
            if m.eq_ignore_ascii_case("plain") {
                return Err(AuthorizeRequestError::PkcePlainRejected);
            }
        }

        let nonce = params.get("nonce").cloned();
        if scope.iter().any(|s| s.as_str() == "openid") && nonce.is_none() {
            return Err(AuthorizeRequestError::NonceRequired);
        }

        let state = params.get("state").cloned();
        let acr_values = params.get("acr_values").cloned();
        let prompt = params.get("prompt").cloned();
        let max_age = params.get("max_age").and_then(|v| v.parse().ok());
        let login_hint = params.get("login_hint").cloned();

        let extra = params
            .into_iter()
            .filter(|(k, _)| {
                ![
                    "response_type",
                    "client_id",
                    "redirect_uri",
                    "scope",
                    "state",
                    "nonce",
                    "code_challenge",
                    "code_challenge_method",
                    "acr_values",
                    "prompt",
                    "max_age",
                    "login_hint",
                ]
                .contains(&k.as_str())
            })
            .collect();

        Ok(Self {
            response_type: ResponseType::Code,
            client_id,
            redirect_uri,
            scope,
            state,
            nonce,
            code_challenge,
            code_challenge_method,
            acr_values,
            prompt,
            max_age,
            login_hint,
            extra,
        })
    }

    /// Final policy gate against the resolved `Client` record.
    /// MUST be called after `parse`.
    pub fn enforce_client_policy(&self, client: &Client) -> Result<(), AuthorizeRequestError> {
        // Redirect URI must match one of the registered patterns.
        let candidate = self.redirect_uri.as_str();
        let matches = client
            .redirect_uris
            .iter()
            .any(|r| r.matches(candidate.trim_end_matches('/')) || r.matches(candidate));
        if !matches {
            return Err(AuthorizeRequestError::RedirectMismatch);
        }

        // PKCE: required for public clients, optional but enforced if presented.
        if client.kind == ClientKind::Public && self.code_challenge.is_none() {
            return Err(AuthorizeRequestError::PkceRequired);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use geonosis_core::{
        AccessTokenType, ClientAuthMethod, ConsentPolicy, FlowBinding, GrantPolicy, RedirectUri,
    };

    fn params(s: &[(&str, &str)]) -> BTreeMap<String, String> {
        s.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn rejects_pkce_plain() {
        let p = params(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://example.com/cb"),
            ("code_challenge", "ABC"),
            ("code_challenge_method", "plain"),
        ]);
        let err = AuthorizeRequest::parse(p).unwrap_err();
        assert!(matches!(err, AuthorizeRequestError::PkcePlainRejected));
    }

    #[test]
    fn rejects_non_code_response_type() {
        let p = params(&[
            ("response_type", "token"),
            ("client_id", "spa"),
            ("redirect_uri", "https://example.com/cb"),
        ]);
        assert!(matches!(
            AuthorizeRequest::parse(p).unwrap_err(),
            AuthorizeRequestError::UnsupportedResponseType
        ));
    }

    #[test]
    fn openid_scope_requires_nonce() {
        let p = params(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://example.com/cb"),
            ("scope", "openid profile"),
        ]);
        let err = AuthorizeRequest::parse(p).unwrap_err();
        assert!(matches!(err, AuthorizeRequestError::NonceRequired));
    }

    fn public_client() -> Client {
        Client {
            id: geonosis_core::ClientId::new(),
            realm_id: geonosis_core::RealmId::new(),
            client_id: "spa".into(),
            display_name: None,
            kind: ClientKind::Public,
            grants: GrantPolicy::public_app(),
            auth_method: ClientAuthMethod::None,
            flow_binding: FlowBinding::default(),
            default_scopes: vec![],
            optional_scopes: vec![],
            redirect_uris: vec![RedirectUri {
                uri: "https://example.com/cb".into(),
                wildcard_path: false,
            }],
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
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn public_client_without_pkce_rejected_by_policy_gate() {
        let p = params(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://example.com/cb"),
            ("scope", "openid"),
            ("nonce", "n1"),
        ]);
        let req = AuthorizeRequest::parse(p).unwrap();
        let err = req.enforce_client_policy(&public_client()).unwrap_err();
        assert!(matches!(err, AuthorizeRequestError::PkceRequired));
    }

    #[test]
    fn redirect_must_match_registered() {
        let p = params(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://evil.com/cb"),
            ("scope", "openid"),
            ("nonce", "n1"),
            ("code_challenge", "abc"),
            ("code_challenge_method", "S256"),
        ]);
        let req = AuthorizeRequest::parse(p).unwrap();
        let err = req.enforce_client_policy(&public_client()).unwrap_err();
        assert!(matches!(err, AuthorizeRequestError::RedirectMismatch));
    }

    #[test]
    fn valid_request_accepted() {
        let p = params(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://example.com/cb"),
            ("scope", "openid"),
            ("nonce", "n1"),
            ("code_challenge", "abc"),
            ("code_challenge_method", "S256"),
            ("state", "s1"),
        ]);
        let req = AuthorizeRequest::parse(p).unwrap();
        assert_eq!(req.state.as_deref(), Some("s1"));
        req.enforce_client_policy(&public_client()).unwrap();
    }
}
