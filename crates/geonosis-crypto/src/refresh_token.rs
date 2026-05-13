//! Refresh-token secret + hash type.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hash::token_hash;
use crate::random::random_bytes;

/// Plain refresh-token bearer string. NEVER persisted. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RefreshTokenSecret(pub String);

impl std::fmt::Debug for RefreshTokenSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RefreshTokenSecret(***)")
    }
}

impl RefreshTokenSecret {
    /// Generate a fresh 32-byte base64url secret.
    pub fn generate() -> Self {
        let b: [u8; 32] = random_bytes();
        Self(crate::base64url::encode(b))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Compute the storage hash (BLAKE3-keyed). Result is hex-encoded for
    /// database column-friendliness.
    pub fn hash(&self, key: &[u8; 32]) -> RefreshTokenHash {
        let h = token_hash(key, self.0.as_bytes());
        RefreshTokenHash(hex::encode(h))
    }
}

/// Hex-encoded hash form. This is what becomes the `RefreshTokenId.0`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RefreshTokenHash(pub String);

/// Convenience helper used by the OAuth grant layer.
pub fn refresh_token_hash(secret: &str, key: &[u8; 32]) -> String {
    hex::encode(token_hash(key, secret.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_hash() {
        let s = RefreshTokenSecret::generate();
        let k = [4u8; 32];
        let h1 = s.hash(&k);
        let h2 = s.hash(&k);
        assert_eq!(h1, h2);
    }

    #[test]
    fn distinct_secrets_distinct_hashes() {
        let a = RefreshTokenSecret::generate();
        let b = RefreshTokenSecret::generate();
        let k = [4u8; 32];
        assert_ne!(a.hash(&k), b.hash(&k));
    }
}
