//! OIDC discovery document (`.well-known/openid-configuration`).

use serde::{Deserialize, Serialize};
use url::Url;

/// Subset of OIDC Discovery 1.0 fields v0.1 advertises. Additional fields
/// are added as features land.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryDocument {
    pub issuer: Url,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub userinfo_endpoint: Url,
    pub jwks_uri: Url,
    pub registration_endpoint: Option<Url>,
    pub end_session_endpoint: Url,
    pub revocation_endpoint: Url,
    pub introspection_endpoint: Url,
    pub pushed_authorization_request_endpoint: Url,
    pub device_authorization_endpoint: Url,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub response_modes_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub require_pushed_authorization_requests: bool,
    pub require_request_uri_registration: bool,
    /// JAR (RFC 9101) `request` parameter support. v0.1 returns false
    /// to surface the gap honestly; PAR (RFC 9126) is the supported
    /// equivalent surface and is advertised separately above.
    pub request_parameter_supported: bool,
    /// JAR `request_uri` parameter. v0.1 only accepts `request_uri`
    /// values minted by our own PAR endpoint; advertising support is
    /// kept conservative to match.
    pub request_uri_parameter_supported: bool,
    pub frontchannel_logout_supported: bool,
    pub backchannel_logout_supported: bool,
    pub end_session_endpoint_supported: bool,
}

/// Build a discovery document. The issuer URL is the base URL the realm
/// is published under (typically `https://geonosis.example/realms/{slug}`).
pub fn discovery_document(issuer: Url) -> DiscoveryDocument {
    let base = issuer.clone();
    let join = |suffix: &str| {
        let mut u = base.clone();
        u.set_path(&format!("{}{}", base.path().trim_end_matches('/'), suffix));
        u
    };
    DiscoveryDocument {
        authorization_endpoint: join("/protocol/openid-connect/auth"),
        token_endpoint: join("/protocol/openid-connect/token"),
        userinfo_endpoint: join("/protocol/openid-connect/userinfo"),
        jwks_uri: join("/protocol/openid-connect/jwks"),
        registration_endpoint: None,
        end_session_endpoint: join("/protocol/openid-connect/logout"),
        revocation_endpoint: join("/protocol/openid-connect/revoke"),
        introspection_endpoint: join("/protocol/openid-connect/introspect"),
        pushed_authorization_request_endpoint: join("/protocol/openid-connect/par"),
        device_authorization_endpoint: join("/protocol/openid-connect/device/authorize"),
        issuer,
        scopes_supported: vec![
            "openid".into(),
            "profile".into(),
            "email".into(),
            "offline_access".into(),
            "roles".into(),
            "groups".into(),
            "org".into(),
        ],
        response_types_supported: vec!["code".into()],
        response_modes_supported: vec!["query".into(), "form_post".into()],
        grant_types_supported: vec![
            "authorization_code".into(),
            "refresh_token".into(),
            "client_credentials".into(),
            "password".into(),
            "urn:ietf:params:oauth:grant-type:device_code".into(),
            "urn:ietf:params:oauth:grant-type:token-exchange".into(),
        ],
        subject_types_supported: vec!["public".into(), "pairwise".into()],
        id_token_signing_alg_values_supported: vec!["RS256".into(), "ES256".into(), "EdDSA".into()],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_basic".into(),
            "client_secret_post".into(),
            "client_secret_jwt".into(),
            "private_key_jwt".into(),
            "none".into(),
        ],
        code_challenge_methods_supported: vec!["S256".into()],
        claims_supported: vec![
            "sub".into(),
            "iss".into(),
            "aud".into(),
            "exp".into(),
            "iat".into(),
            "auth_time".into(),
            "nonce".into(),
            "acr".into(),
            "amr".into(),
            "azp".into(),
            "sid".into(),
            "email".into(),
            "email_verified".into(),
            "preferred_username".into(),
            "name".into(),
            "groups".into(),
            "org".into(),
        ],
        require_pushed_authorization_requests: false,
        require_request_uri_registration: false,
        request_parameter_supported: false,
        request_uri_parameter_supported: false,
        frontchannel_logout_supported: true,
        backchannel_logout_supported: true,
        end_session_endpoint_supported: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_advertises_s256_only() {
        let d = discovery_document(Url::parse("https://g.example/realms/r").unwrap());
        assert_eq!(d.code_challenge_methods_supported, vec!["S256".to_string()]);
        assert_eq!(d.response_types_supported, vec!["code".to_string()]);
    }

    #[test]
    fn discovery_paths_relative_to_issuer() {
        let d = discovery_document(Url::parse("https://g.example/realms/r").unwrap());
        assert!(
            d.token_endpoint.as_str().ends_with("/protocol/openid-connect/token"),
            "got {}",
            d.token_endpoint
        );
        assert!(d
            .jwks_uri
            .as_str()
            .ends_with("/protocol/openid-connect/jwks"));
    }

    #[test]
    fn discovery_advertises_device_and_token_exchange() {
        let d = discovery_document(Url::parse("https://g.example/realms/r").unwrap());
        assert!(d.grant_types_supported.iter().any(|g| g.contains("device_code")));
        assert!(d
            .grant_types_supported
            .iter()
            .any(|g| g.contains("token-exchange")));
    }

    #[test]
    fn discovery_advertises_password_grant() {
        // `password` (Direct Access Grant) is part of the v0.1 surface per
        // docs/03 §"Path 4" and docs/06 §`direct-grant` → `grant_type=password`.
        // RFC 6749 §3.3 requires the OP to advertise every grant it supports.
        let d = discovery_document(Url::parse("https://g.example/realms/r").unwrap());
        assert!(
            d.grant_types_supported.iter().any(|g| g == "password"),
            "discovery must advertise `password` grant: {:?}",
            d.grant_types_supported,
        );
    }
}
