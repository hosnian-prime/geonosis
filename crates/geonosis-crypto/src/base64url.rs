//! URL-safe base64 without padding (per RFC 7515 §2).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("invalid base64url: {0}")]
pub struct DecodeError(pub String);

pub fn encode<T: AsRef<[u8]>>(input: T) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

pub fn decode(input: &str) -> Result<Vec<u8>, DecodeError> {
    URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|e| DecodeError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let original: &[u8] = b"hello world";
        let s = encode(original);
        assert!(!s.contains('='));
        assert!(!s.contains('+'));
        assert!(!s.contains('/'));
        assert_eq!(decode(&s).unwrap(), original);
    }
}
