//! RFC 8628 — OAuth 2.0 Device Authorization Grant.

use serde::{Deserialize, Serialize};

/// Default device-code TTL: 10 minutes (RFC 8628 recommends 5–30).
pub const DEVICE_CODE_DEFAULT_TTL_SECS: i64 = 600;

/// Default poll interval per `docs/14-roadmap.md`: hard-coded 5s in v0.1
/// (per-realm override lands in v0.2).
pub const DEVICE_CODE_DEFAULT_INTERVAL_SECS: u32 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: i64,
    pub interval: u32,
}

/// Generate an 8-char user code grouped as `XXXX-XXXX` from an
/// unambiguous alphabet (no I/O/0/1).
pub fn generate_user_code() -> String {
    use rand::rngs::OsRng;
    use rand::RngCore;
    const ALPHA: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    let chars: Vec<char> = bytes
        .iter()
        .map(|b| ALPHA[(*b as usize) % ALPHA.len()] as char)
        .collect();
    format!(
        "{}{}{}{}-{}{}{}{}",
        chars[0], chars[1], chars[2], chars[3], chars[4], chars[5], chars[6], chars[7]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_code_format() {
        let c = generate_user_code();
        assert_eq!(c.len(), 9);
        assert_eq!(c.as_bytes()[4], b'-');
        // No confusable characters allowed.
        for ch in c.chars() {
            assert!(!matches!(ch, 'I' | 'O' | '0' | '1' | 'L'));
        }
    }

    #[test]
    fn user_codes_distinct() {
        // Birthday-bound test: with 32^8 ≈ 1e12 codes, two random draws
        // colliding is astronomically unlikely.
        let a = generate_user_code();
        let b = generate_user_code();
        assert_ne!(a, b);
    }
}
