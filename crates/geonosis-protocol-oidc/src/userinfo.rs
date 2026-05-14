//! OIDC `/userinfo` claim assembly.

use serde::{Deserialize, Serialize};

use geonosis_core::{ScopeName, User};

/// Standard claims returned from `/userinfo`. `sub` is always present;
/// other fields appear only when the requested scopes permit them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserinfoClaims {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

/// Build userinfo claims for a user, respecting requested scopes.
///
/// Per OIDC §5.4: `profile` releases name + given_name + family_name +
/// preferred_username; `email` releases email + email_verified.
pub fn userinfo_for(user: &User, scopes: &[ScopeName]) -> UserinfoClaims {
    let want = |name: &str| scopes.iter().any(|s| s.as_str() == name);
    let mut out = UserinfoClaims {
        sub: user.id.to_string(),
        name: None,
        given_name: None,
        family_name: None,
        preferred_username: None,
        email: None,
        email_verified: None,
    };
    if want("profile") {
        out.preferred_username = Some(user.username.clone());
        if let Some(name) = &user.name {
            out.given_name = name.given.clone();
            out.family_name = name.family.clone();
            out.name = name.display_or_concat();
        }
    }
    if want("email") {
        out.email = user.email.clone();
        if user.email.is_some() {
            out.email_verified = Some(user.email_verified);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use geonosis_core::{PersonName, RealmId, UserId};

    fn fixture_user() -> User {
        User {
            id: UserId::new(),
            realm_id: RealmId::new(),
            username: "ada".into(),
            email: Some("ada@example.com".into()),
            email_verified: true,
            failed_attempts: 0,
            locked_until: None,
            last_failed_at: None,
            name: Some(PersonName {
                given: Some("Ada".into()),
                family: Some("Lovelace".into()),
                middle: None,
                display: None,
            }),
            credentials: vec![],
            federation: None,
            attributes: Default::default(),
            required_actions: vec![],
            required_flow: None,
            organizations: vec![],
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn sub_always_present_no_other_claims_without_scope() {
        let u = fixture_user();
        let claims = userinfo_for(&u, &[]);
        assert!(claims.email.is_none());
        assert!(claims.preferred_username.is_none());
        assert_eq!(claims.sub, u.id.to_string());
    }

    #[test]
    fn profile_scope_releases_name_fields() {
        let u = fixture_user();
        let claims = userinfo_for(&u, &[ScopeName::new("profile").unwrap()]);
        assert_eq!(claims.preferred_username.as_deref(), Some("ada"));
        assert_eq!(claims.given_name.as_deref(), Some("Ada"));
        assert_eq!(claims.family_name.as_deref(), Some("Lovelace"));
        assert_eq!(claims.name.as_deref(), Some("Ada Lovelace"));
        // email not requested
        assert!(claims.email.is_none());
    }

    #[test]
    fn email_scope_releases_email_only() {
        let u = fixture_user();
        let claims = userinfo_for(&u, &[ScopeName::new("email").unwrap()]);
        assert_eq!(claims.email.as_deref(), Some("ada@example.com"));
        assert_eq!(claims.email_verified, Some(true));
        assert!(claims.preferred_username.is_none());
    }
}
