//! Argon2id password hashing.

use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::{Algorithm, Argon2, Params, Version};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("hashing failed: {0}")]
    Hash(String),
    #[error("verification failed: {0}")]
    Verify(String),
    #[error("malformed stored hash: {0}")]
    Malformed(String),
}

/// Hash a plaintext password into the PHC string form.
///
/// Parameters per `docs/12-security-crypto.md`: `m=64 MiB, t=3, p=4`.
pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);
    let params =
        Params::new(64 * 1024, 3, 4, None).map_err(|e| PasswordError::Hash(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| PasswordError::Hash(e.to_string()))
}

/// Verify a plaintext password against the stored PHC string. Constant-time.
pub fn verify_password(password: &str, stored_hash: &str) -> Result<bool, PasswordError> {
    let parsed =
        PasswordHash::new(stored_hash).map_err(|e| PasswordError::Malformed(e.to_string()))?;
    let argon = Argon2::default();
    match argon.verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(PasswordError::Verify(e.to_string())),
    }
}

/// Run a dummy Argon2 verification to normalize timing on unknown-user
/// paths. Always returns `false` (the hash won't match any real input).
/// The point is to burn the same CPU time as a real verification.
///
/// Instead of using a static PHC string (which may be malformed and
/// silently fail to parse), we run the same Argon2 computation inline
/// using a fixed salt. This guarantees identical CPU cost.
pub fn dummy_verify(password: &str) {
    use argon2::PasswordHasher;
    let salt = SaltString::from_b64("R2Vvbm9zaXNEdW1teVNhbHQ").expect("static salt must parse");
    let params = Params::new(64 * 1024, 3, 4, None).expect("static params must parse");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    // We don't care about the result — only the time cost.
    let _ = argon.hash_password(password.as_bytes(), &salt);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let h = hash_password("hunter2-XXX").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("hunter2-XXX", &h).unwrap());
        assert!(!verify_password("wrong", &h).unwrap());
    }

    #[test]
    fn malformed_hash_rejected() {
        assert!(verify_password("any", "not-a-hash").is_err());
    }
}
