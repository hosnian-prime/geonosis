//! RFC 7662 — OAuth 2.0 Token Introspection.

use serde::{Deserialize, Serialize};

use geonosis_core::AccessTokenClaims;

/// Standard introspection response shape.
///
/// `active=false` is the **only** field returned for unknown / expired
/// / revoked tokens (RFC 7662 §2.2). When `active=true`, additional
/// claims accompany it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

impl IntrospectionResponse {
    /// "Token is unknown / inactive" reply per RFC 7662 §2.2.
    pub fn inactive() -> Self {
        Self {
            active: false,
            scope: None,
            client_id: None,
            username: None,
            token_type: None,
            exp: None,
            iat: None,
            sub: None,
            aud: None,
            iss: None,
            jti: None,
        }
    }
}

/// Construct an `IntrospectionResponse` from validated access-token claims.
pub fn build_introspection(claims: &AccessTokenClaims, username: Option<String>) -> IntrospectionResponse {
    IntrospectionResponse {
        active: true,
        scope: Some(claims.scope.clone()),
        client_id: Some(claims.azp.clone()),
        username,
        token_type: Some("Bearer".into()),
        exp: Some(claims.exp),
        iat: Some(claims.iat),
        sub: Some(claims.sub.clone()),
        aud: Some(claims.aud.clone()),
        iss: Some(claims.iss.clone()),
        jti: Some(claims.jti.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_serializes_with_only_active_field() {
        let r = IntrospectionResponse::inactive();
        let j = serde_json::to_value(&r).unwrap();
        assert_eq!(j.as_object().unwrap().len(), 1);
        assert_eq!(j["active"], serde_json::Value::Bool(false));
    }

    #[test]
    fn active_includes_standard_claims() {
        let claims = AccessTokenClaims {
            iss: "https://g.example/realms/r".into(),
            sub: "user-1".into(),
            aud: vec!["client-1".into()],
            exp: 1,
            iat: 0,
            jti: "jti-1".into(),
            scope: "openid".into(),
            azp: "client-1".into(),
            sid: None,
            realm_access: None,
            resource_access: Default::default(),
            groups: None,
            ext: Default::default(),
        };
        let r = build_introspection(&claims, Some("ada".into()));
        assert!(r.active);
        assert_eq!(r.client_id.as_deref(), Some("client-1"));
        assert_eq!(r.username.as_deref(), Some("ada"));
        assert_eq!(r.token_type.as_deref(), Some("Bearer"));
    }
}
