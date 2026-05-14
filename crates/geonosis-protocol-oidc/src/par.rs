//! RFC 9126 — Pushed Authorization Requests.

use serde::{Deserialize, Serialize};

/// Default lifetime per RFC 9126 §2.2 — short, single-use.
pub const PAR_DEFAULT_TTL_SECS: i64 = 60;

/// Successful PAR response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParResponse {
    pub request_uri: String,
    pub expires_in: i64,
}

/// Build a `urn:ietf:params:oauth:request_uri:` URI per RFC 9126 §2.2
/// with a 256-bit random suffix.
pub fn generate_request_uri() -> String {
    format!(
        "urn:ietf:params:oauth:request_uri:{}",
        geonosis_crypto::random::random_token()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_uri_uses_standard_namespace() {
        let u = generate_request_uri();
        assert!(u.starts_with("urn:ietf:params:oauth:request_uri:"));
        // 32-byte random base64url is 43 chars after the prefix.
        let suffix = u.trim_start_matches("urn:ietf:params:oauth:request_uri:");
        assert_eq!(suffix.len(), 43);
    }

    #[test]
    fn each_request_uri_distinct() {
        assert_ne!(generate_request_uri(), generate_request_uri());
    }
}
