//! CSPRNG-backed helpers.

use rand::rngs::OsRng;
use rand::RngCore;

/// Fill a fixed-length array with cryptographically-strong random bytes.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// 32-byte base64url token (used for session ids, code ids, refresh tokens).
pub fn random_token() -> String {
    let bytes: [u8; 32] = random_bytes();
    crate::base64url::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_distinct() {
        let a = random_token();
        let b = random_token();
        assert_ne!(a, b);
        // 32 bytes base64url = 43 chars.
        assert_eq!(a.len(), 43);
    }
}
