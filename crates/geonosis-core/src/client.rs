//! OAuth/OIDC client (relying party) entity.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::common::JwsAlgorithm;
use crate::id::{ClientId, FlowId, RealmId};
use crate::scope::ScopeName;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub id: ClientId,
    pub realm_id: RealmId,
    /// Public OAuth identifier (the `client_id` URL param).
    /// Charset: `[A-Za-z0-9_.-]{1,128}`.
    pub client_id: String,
    pub display_name: Option<String>,
    pub kind: ClientKind,

    pub grants: GrantPolicy,
    pub auth_method: ClientAuthMethod,
    pub flow_binding: FlowBinding,

    pub default_scopes: Vec<ScopeName>,
    pub optional_scopes: Vec<ScopeName>,

    pub redirect_uris: Vec<RedirectUri>,
    pub post_logout_redirect_uris: Vec<RedirectUri>,
    pub web_origins: Vec<String>,

    pub access_token_type: AccessTokenType,
    pub consent: ConsentPolicy,

    pub access_token_lifespan: Option<Duration>,
    pub refresh_token_lifespan: Option<Duration>,
    pub access_token_signing_alg: Option<JwsAlgorithm>,

    pub front_channel_logout_enabled: bool,
    pub backchannel_logout_url: Option<Url>,

    /// `kid` references for JWT client auth (one of these MUST verify the
    /// assertion). Empty for clients that don't use private-key-jwt.
    pub client_authentication_keys: Vec<String>,

    pub pairwise_sub_algorithm: Option<String>,

    /// SAML 2.0 SP config blob — present iff `kind = SamlServiceProvider`
    /// and the operator has registered the SP. The typed form lives in
    /// `geonosis_protocol_saml_idp::SamlSpClientConfig`; the SAML
    /// runtime parses this value at the protocol boundary, keeping
    /// `geonosis-core` free of SAML-specific schema while still letting
    /// the persistent shape ride on the `Client` row per
    /// `docs/20-saml-idp.md` §"SP as a Client".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml_sp_config: Option<serde_json::Value>,

    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientKind {
    Confidential,
    Public,
    BearerOnly,
    ServiceAccount,
    SamlServiceProvider,
    ScimClient,
}

impl ClientKind {
    /// Per FAPI 1 Baseline + OAuth 2.1, public clients MUST use PKCE.
    pub fn requires_pkce(self) -> bool {
        matches!(self, Self::Public)
    }
}

/// Allowed grant types for this client.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GrantPolicy {
    pub authorization_code: bool,
    pub refresh_token: bool,
    pub client_credentials: bool,
    pub password: bool,
    pub device_code: bool,
    pub token_exchange: bool,
}

impl GrantPolicy {
    /// Sane default for a confidential web app.
    pub fn web_app() -> Self {
        Self {
            authorization_code: true,
            refresh_token: true,
            ..Self::default()
        }
    }

    /// Sane default for a public SPA / native app.
    pub fn public_app() -> Self {
        Self {
            authorization_code: true,
            refresh_token: true,
            ..Self::default()
        }
    }

    /// Sane default for a service account.
    pub fn service_account() -> Self {
        Self {
            client_credentials: true,
            ..Self::default()
        }
    }

    /// Returns true if any grant is permitted (rejects mis-configured clients early).
    pub fn any_enabled(&self) -> bool {
        self.authorization_code
            || self.refresh_token
            || self.client_credentials
            || self.password
            || self.device_code
            || self.token_exchange
    }
}

/// Grant types known to the protocol layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    RefreshToken,
    ClientCredentials,
    Password,
    /// `urn:ietf:params:oauth:grant-type:device_code`.
    DeviceCode,
    /// `urn:ietf:params:oauth:grant-type:token-exchange`.
    TokenExchange,
}

impl GrantType {
    pub fn as_token_param(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
            Self::ClientCredentials => "client_credentials",
            Self::Password => "password",
            Self::DeviceCode => "urn:ietf:params:oauth:grant-type:device_code",
            Self::TokenExchange => "urn:ietf:params:oauth:grant-type:token-exchange",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "authorization_code" => Self::AuthorizationCode,
            "refresh_token" => Self::RefreshToken,
            "client_credentials" => Self::ClientCredentials,
            "password" => Self::Password,
            "urn:ietf:params:oauth:grant-type:device_code" => Self::DeviceCode,
            "urn:ietf:params:oauth:grant-type:token-exchange" => Self::TokenExchange,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
    ClientSecretJwt,
    PrivateKeyJwt,
    None,
    TlsClientAuth,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowBinding {
    pub browser: Option<FlowId>,
    pub direct_grant: Option<FlowId>,
    pub registration: Option<FlowId>,
    pub reset_credentials: Option<FlowId>,
    pub client_authentication: Option<FlowId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessTokenType {
    #[default]
    Jwt,
    Opaque,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConsentPolicy {
    pub required: bool,
    pub display_on_consent_screen: bool,
    pub consent_screen_text: Option<String>,
}

/// Permissive vs strict redirect URI matching. v0.1 uses strict exact-string
/// match unless `wildcard_path` is set (admin must opt in explicitly).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectUri {
    pub uri: String,
    /// If true, suffix `/*` matches any path under the URI. Disallowed for
    /// confidential web clients in v0.1.
    pub wildcard_path: bool,
}

impl RedirectUri {
    pub fn matches(&self, candidate: &str) -> bool {
        if self.uri == candidate {
            return true;
        }
        if self.wildcard_path {
            if let Some(prefix) = self.uri.strip_suffix("/*") {
                return candidate.starts_with(prefix)
                    && (candidate.len() == prefix.len() || candidate.as_bytes()[prefix.len()] == b'/');
            }
        }
        false
    }

    /// Per `docs/03-protocols-oidc.md` §"Conformance defaults" and OAuth 2.1
    /// §9.7.2, registered redirect URIs MUST use HTTPS, except for:
    /// - loopback (`http://localhost`, `http://127.0.0.1`, `http://[::1]`)
    /// - non-HTTP custom schemes (e.g. mobile deep links `com.example.app://`)
    ///
    /// Admin REST + `geoctl` clients call this when accepting redirect URIs
    /// so that an `http://example.com/cb` registration fails fast instead of
    /// being silently honoured at runtime. The runtime `authorize` path
    /// still enforces exact-match against the registered list — this is the
    /// register-time gate.
    pub fn validate_scheme(uri: &str) -> Result<(), RedirectUriError> {
        // `*` wildcards are stripped before parse so `https://app/*` validates.
        let parseable = uri.trim_end_matches("/*");
        let parsed = url::Url::parse(parseable)
            .map_err(|e| RedirectUriError::Unparseable(e.to_string()))?;
        match parsed.scheme() {
            "https" => Ok(()),
            "http" => {
                let host = parsed.host_str().unwrap_or("");
                if is_loopback_host(host) {
                    Ok(())
                } else {
                    Err(RedirectUriError::HttpRequiresLoopback {
                        host: host.to_string(),
                    })
                }
            }
            // OAuth 2.1 §9.7.2 native-app callback schemes (must contain a
            // dot, per RFC 7595 — `com.example.app`, `bundle.id`, etc.).
            // Bare `urn:` or `data:` are excluded.
            s if s.contains('.') => Ok(()),
            other => Err(RedirectUriError::UnsupportedScheme(other.to_string())),
        }
    }
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

/// Errors returned by [`RedirectUri::validate_scheme`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RedirectUriError {
    #[error("redirect_uri unparseable as URL: {0}")]
    Unparseable(String),
    #[error("http:// redirect_uri only allowed for loopback hosts (got `{host}`); use https://")]
    HttpRequiresLoopback { host: String },
    #[error("unsupported redirect_uri scheme `{0}`; expected https://, http:// loopback, or a reverse-DNS custom scheme")]
    UnsupportedScheme(String),
}

/// Per-client PKCE policy. The realm/global default is "required for public".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PkceMode {
    /// PKCE MUST be present. `plain` is rejected regardless.
    Required,
    /// PKCE accepted if presented.
    IfSupported,
    /// PKCE disabled (v0.1: only valid for `BearerOnly` / `ServiceAccount`).
    Off,
}

impl Default for PkceMode {
    fn default() -> Self {
        Self::Required
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_client_requires_pkce() {
        assert!(ClientKind::Public.requires_pkce());
        assert!(!ClientKind::Confidential.requires_pkce());
    }

    #[test]
    fn redirect_exact_match() {
        let r = RedirectUri {
            uri: "https://example.com/cb".into(),
            wildcard_path: false,
        };
        assert!(r.matches("https://example.com/cb"));
        assert!(!r.matches("https://example.com/cb2"));
        assert!(!r.matches("https://evil.com/cb"));
    }

    #[test]
    fn redirect_wildcard_path() {
        let r = RedirectUri {
            uri: "https://example.com/*".into(),
            wildcard_path: true,
        };
        assert!(r.matches("https://example.com/a"));
        assert!(r.matches("https://example.com/a/b"));
        // host-only wildcard should not collapse the slash boundary
        assert!(!r.matches("https://example.com2/a"));
    }

    #[test]
    fn redirect_scheme_https_accepted() {
        RedirectUri::validate_scheme("https://example.com/cb").unwrap();
        RedirectUri::validate_scheme("https://app.example.com/auth/callback").unwrap();
    }

    #[test]
    fn redirect_scheme_http_loopback_accepted() {
        RedirectUri::validate_scheme("http://localhost:3000/cb").unwrap();
        RedirectUri::validate_scheme("http://127.0.0.1/cb").unwrap();
        RedirectUri::validate_scheme("http://[::1]:8080/cb").unwrap();
    }

    #[test]
    fn redirect_scheme_http_non_loopback_rejected() {
        let err = RedirectUri::validate_scheme("http://example.com/cb").unwrap_err();
        assert!(matches!(err, RedirectUriError::HttpRequiresLoopback { .. }));
        let err = RedirectUri::validate_scheme("http://10.0.0.1/cb").unwrap_err();
        assert!(matches!(err, RedirectUriError::HttpRequiresLoopback { .. }));
    }

    #[test]
    fn redirect_scheme_native_app_custom_scheme_accepted() {
        // Reverse-DNS mobile deep-link callbacks per RFC 7595 + OAuth 2.1 §9.7.2.
        RedirectUri::validate_scheme("com.example.app://cb").unwrap();
        RedirectUri::validate_scheme("io.geonosis.demo://oauth/callback").unwrap();
    }

    #[test]
    fn redirect_scheme_bare_custom_rejected() {
        // `urn:` and `data:` shouldn't be valid OAuth redirect schemes.
        let err = RedirectUri::validate_scheme("urn:foo:bar").unwrap_err();
        assert!(matches!(err, RedirectUriError::UnsupportedScheme(_)));
    }

    #[test]
    fn redirect_scheme_validates_with_wildcard_suffix() {
        RedirectUri::validate_scheme("https://example.com/*").unwrap();
        let err = RedirectUri::validate_scheme("http://example.com/*").unwrap_err();
        assert!(matches!(err, RedirectUriError::HttpRequiresLoopback { .. }));
    }

    #[test]
    fn grant_type_str_roundtrip() {
        for g in [
            GrantType::AuthorizationCode,
            GrantType::DeviceCode,
            GrantType::TokenExchange,
        ] {
            assert_eq!(GrantType::parse(g.as_token_param()), Some(g));
        }
    }
}
