//! Constant-time keyed hashing for opaque tokens.

use blake3::Hasher;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HashError {
    #[error("invalid key length: expected 32, got {0}")]
    BadKey(usize),
}

/// Compute a keyed BLAKE3 hash over the bearer secret. The hash is what we
/// persist in the database; the plaintext bearer never lands on disk.
///
/// Per `docs/12-security-crypto.md`: the key is the realm's
/// `token_hash_key` (derived from master at boot).
pub fn token_hash(key: &[u8; 32], secret: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new_keyed(key);
    h.update(secret);
    *h.finalize().as_bytes()
}

/// Constant-time comparison of two byte slices.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq::constant_time_eq(a, b)
}

/// Compute a pairwise subject identifier per OIDC Core §8.1.
///
/// Uses HMAC-SHA256 keyed with `sector` (typically the client_id or
/// sector_identifier_uri host) over the raw `user_id` string. The
/// output is URL-safe base64 (no padding) — opaque to the relying
/// party, deterministic for a given (sector, user_id) pair.
pub fn pairwise_subject_hash(sector: &str, user_id: &str) -> String {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac =
        Hmac::<Sha256>::new_from_slice(sector.as_bytes()).expect("HMAC accepts any key length");
    mac.update(user_id.as_bytes());
    let result = mac.finalize().into_bytes();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyed_hash_is_deterministic_for_fixed_key() {
        let key = [7u8; 32];
        let h1 = token_hash(&key, b"abc");
        let h2 = token_hash(&key, b"abc");
        assert_eq!(h1, h2);
    }

    #[test]
    fn keyed_hash_diverges_on_key_change() {
        let h1 = token_hash(&[1u8; 32], b"abc");
        let h2 = token_hash(&[2u8; 32], b"abc");
        assert_ne!(h1, h2);
    }

    #[test]
    fn keyed_hash_diverges_on_input_change() {
        let key = [9u8; 32];
        let h1 = token_hash(&key, b"abc");
        let h2 = token_hash(&key, b"abcd");
        assert_ne!(h1, h2);
    }

    #[test]
    fn pairwise_is_deterministic() {
        let a = super::pairwise_subject_hash("my-client", "user-123");
        let b = super::pairwise_subject_hash("my-client", "user-123");
        assert_eq!(a, b);
    }

    #[test]
    fn pairwise_differs_across_sectors() {
        let a = super::pairwise_subject_hash("client-a", "user-123");
        let b = super::pairwise_subject_hash("client-b", "user-123");
        assert_ne!(a, b);
    }

    #[test]
    fn ct_eq_matches() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
