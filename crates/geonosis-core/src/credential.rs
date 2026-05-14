//! User credentials.
//!
//! Storage of secret material lives in `geonosis-storage`. This crate
//! only describes the credential reference and its metadata.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::id::CredentialId;

/// What kind of credential is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialKind {
    Password,
    Otp,
    WebauthnPasswordless,
    Webauthn,
    RecoveryCode,
    /// Magic-link tokens are issued ad-hoc — no persistent credential row
    /// is required; the variant exists for audit tagging only.
    MagicLink,
}

/// Lightweight reference attached to a `User`. The opaque secret material
/// is stored separately and never serialized on the `User` projection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRef {
    pub id: CredentialId,
    pub kind: CredentialKind,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Full credential record with opaque secret material. Constructed at the
/// storage boundary; never serialized to clients.
#[derive(Debug, Clone)]
pub struct Credential {
    pub id: CredentialId,
    pub user_id: crate::id::UserId,
    pub kind: CredentialKind,
    pub label: Option<String>,
    /// Algorithm-specific serialized payload (e.g. PHC string for Argon2id,
    /// base32 secret for TOTP). Never log.
    pub secret_data: Vec<u8>,
    /// Algorithm-specific public metadata (e.g. WebAuthn credential id).
    pub public_data: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_kind_serializes_kebab() {
        let s = serde_json::to_string(&CredentialKind::RecoveryCode).unwrap();
        assert_eq!(s, "\"recovery-code\"");
    }
}
