//! PKCE (RFC 7636).
//!
//! v0.1 invariant: `code_challenge_method=plain` is rejected outright.
//! Only `S256` is supported. The verifier MUST be 43–128 unreserved chars.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PkceError {
    #[error("plain code_challenge_method is forbidden")]
    PlainRejected,
    #[error("unsupported code_challenge_method: {0}")]
    UnsupportedMethod(String),
    #[error("invalid code_verifier (length or charset)")]
    InvalidVerifier,
    #[error("code_verifier does not match code_challenge")]
    VerifierMismatch,
}

const UNRESERVED: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

/// `BASE64URL_NOPAD(SHA256(code_verifier))` — RFC 7636 §4.2.
pub fn derive_challenge_s256(code_verifier: &str) -> Result<String, PkceError> {
    validate_code_verifier(code_verifier)?;
    let digest = Sha256::digest(code_verifier.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

pub fn validate_code_verifier(verifier: &str) -> Result<(), PkceError> {
    let len = verifier.len();
    if !(43..=128).contains(&len) {
        return Err(PkceError::InvalidVerifier);
    }
    if !verifier.bytes().all(|b| UNRESERVED.contains(&b)) {
        return Err(PkceError::InvalidVerifier);
    }
    Ok(())
}

/// Compare a presented verifier against a stored challenge, in constant time.
pub fn verify_code_verifier_against_challenge(
    method: &str,
    verifier: &str,
    challenge: &str,
) -> Result<(), PkceError> {
    if method.eq_ignore_ascii_case("plain") {
        return Err(PkceError::PlainRejected);
    }
    if !method.eq_ignore_ascii_case("S256") {
        return Err(PkceError::UnsupportedMethod(method.into()));
    }
    let derived = derive_challenge_s256(verifier)?;
    if !constant_time_eq_str(&derived, challenge) {
        return Err(PkceError::VerifierMismatch);
    }
    Ok(())
}

fn constant_time_eq_str(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.as_bytes().iter().zip(b.as_bytes().iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_test_vector() {
        // RFC 7636 §B.1
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let got = derive_challenge_s256(verifier).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn plain_method_is_rejected() {
        let v = "01234567890123456789012345678901234567890123";
        let err = verify_code_verifier_against_challenge("plain", v, "anything").unwrap_err();
        assert!(matches!(err, PkceError::PlainRejected));
        // Same when called via uppercase too.
        let err = verify_code_verifier_against_challenge("PLAIN", v, "anything").unwrap_err();
        assert!(matches!(err, PkceError::PlainRejected));
    }

    #[test]
    fn unknown_method_is_rejected() {
        let v = "01234567890123456789012345678901234567890123";
        let err = verify_code_verifier_against_challenge("SHA1", v, "anything").unwrap_err();
        assert!(matches!(err, PkceError::UnsupportedMethod(_)));
    }

    #[test]
    fn invalid_verifier_charset_rejected() {
        let bad = "this has spaces and is too long but contains spaces blah blah";
        assert!(validate_code_verifier(bad).is_err());
    }

    #[test]
    fn verifier_too_short_rejected() {
        assert!(validate_code_verifier("short").is_err());
    }

    #[test]
    fn matching_verifier_verifies() {
        let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let c = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        verify_code_verifier_against_challenge("S256", v, c).unwrap();
    }

    #[test]
    fn nonmatching_verifier_rejected() {
        let v = "01234567890123456789012345678901234567890123";
        let c = "definitelynotthechallenge";
        let err = verify_code_verifier_against_challenge("S256", v, c).unwrap_err();
        assert!(matches!(err, PkceError::VerifierMismatch));
    }
}
