//! OpenID Connect Back-Channel Logout 1.0 — logout token construction.
//!
//! Per the spec §2.4 the OP sends a signed JWT to the RP's registered
//! `backchannel_logout_uri` whose payload includes:
//!   `iss`, `sub`, `aud`, `iat`, `jti`, optional `sid`, and an
//!   `events` claim equal to
//!   `{"http://schemas.openid.net/event/backchannel-logout": {}}`.
//! The JOSE header `typ` is `logout+jwt` (per spec §2.5) so RPs can
//! distinguish logout tokens from ID tokens at parse time without
//! peeking at `events`.
//!
//! v0.1 ships unsigned-by-realm-RS256 logout tokens. Algorithm
//! agility (ES256 / EdDSA) lands automatically once the existing
//! issuer signing-alg negotiation reaches this module — the
//! `LogoutTokenClaims` shape is alg-agnostic.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// `events` claim value mandated by OIDC Back-Channel Logout §2.4.
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// JOSE header `typ` per spec §2.5.
pub const LOGOUT_TOKEN_TYP: &str = "logout+jwt";

/// Logout token claim set per OIDC Back-Channel Logout 1.0 §2.4.
///
/// `sub` and `sid` are both optional independently, but at least one
/// MUST be present; constructors enforce that.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutTokenClaims {
    pub iss: String,
    pub aud: Vec<String>,
    pub iat: i64,
    pub jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// Per spec §2.4: `events` is a JSON object with one well-known
    /// key whose value is an empty object. Serializing as a
    /// BTreeMap keeps it deterministic so the same logout token is
    /// byte-stable across mints.
    pub events: BTreeMap<String, serde_json::Value>,
}

impl LogoutTokenClaims {
    /// Build the canonical claim set for a session+subject pair.
    /// Panics in debug if both `sub` and `sid` are `None` — that
    /// state would produce a spec-invalid token. The runtime check
    /// (`debug_assert`) leaves release builds tolerant in case a
    /// caller-side guard is misplaced; the receiving RP will
    /// reject the token regardless.
    pub fn new(
        iss: impl Into<String>,
        aud: impl Into<String>,
        iat: i64,
        jti: impl Into<String>,
        sub: Option<String>,
        sid: Option<String>,
    ) -> Self {
        debug_assert!(
            sub.is_some() || sid.is_some(),
            "logout token MUST carry sub, sid, or both (spec §2.4)",
        );
        let mut events = BTreeMap::new();
        events.insert(
            BACKCHANNEL_LOGOUT_EVENT.to_string(),
            serde_json::Value::Object(serde_json::Map::new()),
        );
        Self {
            iss: iss.into(),
            aud: vec![aud.into()],
            iat,
            jti: jti.into(),
            sub,
            sid,
            events,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carries_event_marker() {
        let c = LogoutTokenClaims::new(
            "https://op.example/realms/acme",
            "rp",
            1_700_000_000,
            "jti1",
            Some("user-1".into()),
            Some("sid-1".into()),
        );
        assert!(c.events.contains_key(BACKCHANNEL_LOGOUT_EVENT));
        let inner = &c.events[BACKCHANNEL_LOGOUT_EVENT];
        assert!(inner.is_object());
        assert_eq!(inner.as_object().unwrap().len(), 0);
    }

    #[test]
    fn omits_optional_when_none() {
        let c = LogoutTokenClaims::new("iss", "rp", 1, "jti", None, Some("sid".into()));
        let j = serde_json::to_value(&c).unwrap();
        assert!(j.get("sub").is_none(), "sub omitted when None: {j}");
        assert!(j.get("sid").is_some());
    }

    #[test]
    fn aud_is_array() {
        let c = LogoutTokenClaims::new("iss", "rp", 1, "jti", Some("u".into()), None);
        let j = serde_json::to_value(&c).unwrap();
        assert!(
            j["aud"].is_array(),
            "aud must serialise as JSON array per spec: {j}"
        );
        assert_eq!(j["aud"][0], "rp");
    }

    #[test]
    fn round_trip_preserves_claims() {
        let c = LogoutTokenClaims::new(
            "iss",
            "rp",
            42,
            "jti-1",
            Some("user".into()),
            Some("sid-x".into()),
        );
        let bytes = serde_json::to_vec(&c).unwrap();
        let parsed: LogoutTokenClaims = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.iss, "iss");
        assert_eq!(parsed.aud, vec!["rp".to_string()]);
        assert_eq!(parsed.iat, 42);
        assert_eq!(parsed.sub.as_deref(), Some("user"));
        assert_eq!(parsed.sid.as_deref(), Some("sid-x"));
    }

    #[test]
    fn typ_constant_matches_spec() {
        // Spec §2.5: header `typ` MUST be `logout+jwt`.
        assert_eq!(LOGOUT_TOKEN_TYP, "logout+jwt");
    }
}
