//! Token + code grant entities (no I/O).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::common::Amr;
use crate::id::{ClientId, CodeId, RealmId, RefreshTokenId, SessionId, TokenFamilyId, UserId};
use crate::scope::ScopeName;

/// PKCE code-challenge as stored against a `CodeGrant`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeChallenge {
    pub method: CodeChallengeMethod,
    /// The challenge value as presented in `/authorize`.
    pub challenge: String,
}

/// PKCE challenge methods. **`plain` is intentionally absent.** v0.1
/// rejects `code_challenge_method=plain` outright per FAPI 1 Baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CodeChallengeMethod {
    /// `BASE64URL(SHA256(code_verifier))`.
    S256,
}

impl CodeChallengeMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::S256 => "S256",
        }
    }
}

/// Authorization code grant row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeGrant {
    pub code: CodeId,
    pub realm_id: RealmId,
    pub client_id: ClientId,
    pub user_id: UserId,
    pub session_id: SessionId,
    pub scope: Vec<ScopeName>,
    pub redirect_uri: Url,
    pub code_challenge: Option<CodeChallenge>,
    pub nonce: Option<String>,
    pub state: Option<String>,
    pub amr: Vec<Amr>,
    /// Achieved ACR (authentication context class reference). Populated
    /// from `FlowContext.authn_level` when the authorize flow completes.
    /// Threaded into the id_token `acr` claim at code exchange.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    pub auth_time: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Refresh token row. The `id` field is the BLAKE3-keyed hash of the bearer
/// secret; plaintext is never persisted (see `docs/12-security-crypto.md`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub id: RefreshTokenId,
    pub family_id: TokenFamilyId,
    pub realm_id: RealmId,
    pub client_id: ClientId,
    pub user_id: UserId,
    pub session_id: SessionId,
    pub scope: Vec<ScopeName>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// True once exchanged. Re-presentation of a `used` refresh token MUST
    /// invalidate the whole family.
    pub used: bool,
}

/// ID Token claim shape (OIDC §2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub auth_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub azp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<Amr>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

/// Access Token claim shape (Geonosis convention).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub scope: String,
    pub azp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_access: Option<RealmAccess>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub resource_access: BTreeMap<String, ResourceAccess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
    /// Active Organization context, when the user signed in inside an
    /// org-scoped flow or has a default org membership. Shape matches
    /// doc 15 §"Token shape".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<OrgClaim>,
    /// RFC 8693 `act` chain. When present, the token was issued via
    /// Token Exchange; each level identifies an upstream actor. Shape
    /// is recursive: `act.sub` is the actor and `act.act` (optional)
    /// the actor's actor. See doc 18 §"`act` claim chain".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<serde_json::Value>,
    /// Mapper-emitted custom claims. Flattened into the top-level token by
    /// the OIDC layer.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub ext: BTreeMap<String, serde_json::Value>,
}

/// Per doc 15 §"Token shape — `org` claim". One organization context
/// per token; multi-org users get one token per org and switch by
/// re-authorizing with `?org=<alias>` or by Token Exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgClaim {
    /// Stable URL-safe alias.
    pub alias: String,
    /// Organization id (ULID, encoded as text on the wire).
    pub id: String,
    /// Optional human-readable name (omitted when chrome only needs the alias).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Org-scoped role names the user holds in this org.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmAccess {
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAccess {
    pub roles: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_plain_is_not_a_variant() {
        // Compile-time: this assertion fails to build if `plain` is added.
        // Runtime: ensure deserializing "plain" is rejected.
        let r: Result<CodeChallengeMethod, _> = serde_json::from_str("\"plain\"");
        assert!(r.is_err(), "plain MUST be rejected");
    }

    #[test]
    fn pkce_s256_serializes() {
        let s = serde_json::to_string(&CodeChallengeMethod::S256).unwrap();
        assert_eq!(s, "\"S256\"");
    }
}
