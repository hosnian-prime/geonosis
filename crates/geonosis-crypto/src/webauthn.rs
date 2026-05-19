//! WebAuthn assertion verification (W3C Level 2, §7.2).
//!
//! Implements the "Verifying an Authentication Assertion" ceremony using
//! the project's existing crypto primitives (`p256`, `rsa`, `ed25519-dalek`).
//! No dependency on `webauthn-rs` — keeps the dependency surface auditable.
//!
//! v0.1 scope: assertion-as-step only. Full passkey lifecycle (registration
//! ceremony, resident-key discovery) lands in v0.2.

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use thiserror::Error;

// -- public types ---------------------------------------------------------

/// A stored WebAuthn credential (extracted during registration, persisted
/// as JSON in `user.attributes["webauthn:credentials"]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    /// Base64url-encoded credential ID.
    pub credential_id: String,
    /// COSE algorithm identifier: -7 = ES256, -257 = RS256, -8 = EdDSA.
    pub cose_alg: i64,
    /// Base64url-encoded public key material.
    /// ES256: uncompressed EC point (65 bytes: 0x04 || x || y).
    /// RS256: DER-encoded RSAPublicKey (PKCS#1).
    /// EdDSA: raw 32-byte Ed25519 public key.
    pub public_key_b64: String,
    /// Signature counter at last successful assertion.
    pub sign_count: u32,
}

/// Parameters for assertion verification.
pub struct AssertionParams<'a> {
    /// Raw `clientDataJSON` bytes from the browser.
    pub client_data_json: &'a [u8],
    /// Raw `authenticatorData` bytes from the browser.
    pub authenticator_data: &'a [u8],
    /// Raw signature bytes from the browser.
    pub signature: &'a [u8],
    /// The base64url-encoded challenge that was issued to the browser.
    pub expected_challenge: &'a str,
    /// Expected origin (e.g. "https://example.com").
    pub expected_origin: &'a str,
    /// Relying Party ID (e.g. "example.com").
    pub rp_id: &'a str,
    /// The enrolled credential to verify against.
    pub credential: &'a StoredCredential,
    /// Whether user verification (UV flag) is required.
    pub require_user_verification: bool,
}

/// Result of a successful assertion verification.
#[derive(Debug, Clone)]
pub struct VerifiedAssertion {
    pub credential_id: String,
    pub new_sign_count: u32,
    pub user_present: bool,
    pub user_verified: bool,
}

#[derive(Debug, Error)]
pub enum WebauthnError {
    #[error("malformed assertion: {0}")]
    Malformed(String),
    #[error("client data type must be webauthn.get, got {0}")]
    WrongType(String),
    #[error("challenge mismatch")]
    ChallengeMismatch,
    #[error("origin mismatch: got {got}, expected {expected}")]
    OriginMismatch { got: String, expected: String },
    #[error("cross-origin assertions not permitted")]
    CrossOrigin,
    #[error("rp_id hash mismatch")]
    RpIdMismatch,
    #[error("user presence flag not set")]
    UserNotPresent,
    #[error("user verification required but not performed")]
    UserNotVerified,
    #[error("unsupported COSE algorithm: {0}")]
    UnsupportedAlgorithm(i64),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("sign count regression: stored={stored}, got={got}")]
    SignCountRegression { stored: u32, got: u32 },
    #[error("key error: {0}")]
    KeyError(String),
}

// -- client data ----------------------------------------------------------

#[derive(Deserialize)]
struct CollectedClientData {
    #[serde(rename = "type")]
    type_: String,
    challenge: String,
    origin: String,
    #[serde(default, rename = "crossOrigin")]
    cross_origin: Option<bool>,
}

// -- COSE algorithm constants ---------------------------------------------

const COSE_ES256: i64 = -7;
const COSE_RS256: i64 = -257;
const COSE_EDDSA: i64 = -8;

// -- public API -----------------------------------------------------------

/// Verify a WebAuthn authentication assertion per W3C §7.2.
pub fn verify_assertion(params: &AssertionParams<'_>) -> Result<VerifiedAssertion, WebauthnError> {
    // §7.2 step 11: parse clientDataJSON
    let client_data: CollectedClientData = serde_json::from_slice(params.client_data_json)
        .map_err(|e| WebauthnError::Malformed(format!("clientDataJSON: {e}")))?;

    // §7.2 step 12: verify type
    if client_data.type_ != "webauthn.get" {
        return Err(WebauthnError::WrongType(client_data.type_));
    }

    // §7.2 step 13: verify challenge
    if client_data.challenge != params.expected_challenge {
        return Err(WebauthnError::ChallengeMismatch);
    }

    // §7.2 step 14: verify origin
    if client_data.origin != params.expected_origin {
        return Err(WebauthnError::OriginMismatch {
            got: client_data.origin,
            expected: params.expected_origin.to_string(),
        });
    }

    // §7.2 step 14 (continued): reject cross-origin assertions.
    // v0.1 does not support cross-origin WebAuthn usage.
    if client_data.cross_origin.unwrap_or(false) {
        return Err(WebauthnError::CrossOrigin);
    }

    // §7.2 step 15: verify rpIdHash
    let auth_data = params.authenticator_data;
    if auth_data.len() < 37 {
        return Err(WebauthnError::Malformed(format!(
            "authenticatorData too short: {} bytes",
            auth_data.len()
        )));
    }
    let rp_id_hash = &auth_data[0..32];
    let expected_rp_hash = sha2::Sha256::digest(params.rp_id.as_bytes());
    if rp_id_hash != &expected_rp_hash[..] {
        return Err(WebauthnError::RpIdMismatch);
    }

    // §7.2 step 16-17: check flags
    let flags = auth_data[32];
    let user_present = flags & 0x01 != 0;
    let user_verified = flags & 0x04 != 0;
    if !user_present {
        return Err(WebauthnError::UserNotPresent);
    }
    if params.require_user_verification && !user_verified {
        return Err(WebauthnError::UserNotVerified);
    }

    // §7.2 step 18: parse sign count (big-endian u32)
    let sign_count =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);

    // §7.2 step 19: compute verification data
    // verificationData = authenticatorData || SHA-256(clientDataJSON)
    let client_data_hash = sha2::Sha256::digest(params.client_data_json);
    let mut verification_data = Vec::with_capacity(auth_data.len() + 32);
    verification_data.extend_from_slice(auth_data);
    verification_data.extend_from_slice(&client_data_hash);

    // §7.2 step 20: verify signature
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let pub_key_bytes = b64
        .decode(&params.credential.public_key_b64)
        .map_err(|e| WebauthnError::KeyError(format!("base64: {e}")))?;

    verify_signature(
        params.credential.cose_alg,
        &pub_key_bytes,
        &verification_data,
        params.signature,
    )?;

    // §7.2 step 21: sign count validation
    if params.credential.sign_count > 0 && sign_count <= params.credential.sign_count {
        return Err(WebauthnError::SignCountRegression {
            stored: params.credential.sign_count,
            got: sign_count,
        });
    }

    Ok(VerifiedAssertion {
        credential_id: params.credential.credential_id.clone(),
        new_sign_count: sign_count,
        user_present,
        user_verified,
    })
}

// -- signature dispatch ---------------------------------------------------

fn verify_signature(
    cose_alg: i64,
    pub_key_bytes: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<(), WebauthnError> {
    match cose_alg {
        COSE_ES256 => verify_es256(pub_key_bytes, data, sig_bytes),
        COSE_RS256 => verify_rs256(pub_key_bytes, data, sig_bytes),
        COSE_EDDSA => verify_eddsa(pub_key_bytes, data, sig_bytes),
        other => Err(WebauthnError::UnsupportedAlgorithm(other)),
    }
}

fn verify_es256(pub_key_bytes: &[u8], data: &[u8], sig_bytes: &[u8]) -> Result<(), WebauthnError> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::EncodedPoint;

    let point = EncodedPoint::from_bytes(pub_key_bytes)
        .map_err(|e| WebauthnError::KeyError(format!("ES256 point: {e}")))?;
    let vk = VerifyingKey::from_encoded_point(&point)
        .map_err(|e| WebauthnError::KeyError(format!("ES256 key: {e}")))?;
    // WebAuthn uses DER-encoded ECDSA signatures (unlike JWS raw R||S).
    let sig = Signature::from_der(sig_bytes).map_err(|_| WebauthnError::InvalidSignature)?;
    vk.verify(data, &sig)
        .map_err(|_| WebauthnError::InvalidSignature)
}

fn verify_rs256(pub_key_bytes: &[u8], data: &[u8], sig_bytes: &[u8]) -> Result<(), WebauthnError> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::sha2::Sha256;
    use rsa::signature::Verifier;
    use rsa::RsaPublicKey;

    let pk = RsaPublicKey::from_pkcs1_der(pub_key_bytes)
        .map_err(|e| WebauthnError::KeyError(format!("RS256 DER: {e}")))?;
    let vk = VerifyingKey::<Sha256>::new(pk);
    let sig = Signature::try_from(sig_bytes)
        .map_err(|e| WebauthnError::KeyError(format!("RS256 sig: {e}")))?;
    vk.verify(data, &sig)
        .map_err(|_| WebauthnError::InvalidSignature)
}

fn verify_eddsa(pub_key_bytes: &[u8], data: &[u8], sig_bytes: &[u8]) -> Result<(), WebauthnError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    if pub_key_bytes.len() != 32 {
        return Err(WebauthnError::KeyError(format!(
            "EdDSA key must be 32 bytes, got {}",
            pub_key_bytes.len()
        )));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(pub_key_bytes);
    let vk = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| WebauthnError::KeyError(format!("EdDSA key: {e}")))?;
    let sig = Signature::try_from(sig_bytes).map_err(|_| WebauthnError::InvalidSignature)?;
    vk.verify(data, &sig)
        .map_err(|_| WebauthnError::InvalidSignature)
}

// -- tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature as P256Sig, SigningKey as P256Sk};

    fn make_es256_credential() -> (P256Sk, StoredCredential) {
        let sk = P256Sk::random(&mut rand::thread_rng());
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        StoredCredential {
            credential_id: "test-cred-1".into(),
            cose_alg: COSE_ES256,
            public_key_b64: b64.encode(point.as_bytes()),
            sign_count: 0,
        }
        .pipe(|c| (sk, c))
    }

    trait Pipe: Sized {
        fn pipe<F, R>(self, f: F) -> R
        where
            F: FnOnce(Self) -> R,
        {
            f(self)
        }
    }
    impl<T> Pipe for T {}

    fn build_assertion(
        sk: &P256Sk,
        rp_id: &str,
        challenge: &str,
        origin: &str,
        sign_count: u32,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": origin,
        });
        let client_data_json = serde_json::to_vec(&client_data).unwrap();

        let rp_id_hash = sha2::Sha256::digest(rp_id.as_bytes());
        let flags: u8 = 0x01 | 0x04; // UP + UV
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(flags);
        auth_data.extend_from_slice(&sign_count.to_be_bytes());

        let client_data_hash = sha2::Sha256::digest(&client_data_json);
        let mut verification_data = Vec::new();
        verification_data.extend_from_slice(&auth_data);
        verification_data.extend_from_slice(&client_data_hash);

        let sig: P256Sig = sk.sign(&verification_data);
        let sig_der = sig.to_der();

        (client_data_json, auth_data, sig_der.as_bytes().to_vec())
    }

    #[test]
    fn es256_assertion_roundtrip() {
        let (sk, cred) = make_es256_credential();
        let (cdj, auth_data, sig) =
            build_assertion(&sk, "example.com", "Y2hhbGxlbmdl", "https://example.com", 1);

        let result = verify_assertion(&AssertionParams {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &sig,
            expected_challenge: "Y2hhbGxlbmdl",
            expected_origin: "https://example.com",
            rp_id: "example.com",
            credential: &cred,
            require_user_verification: false,
        });
        let verified = result.unwrap();
        assert_eq!(verified.new_sign_count, 1);
        assert!(verified.user_present);
        assert!(verified.user_verified);
    }

    #[test]
    fn wrong_challenge_rejected() {
        let (sk, cred) = make_es256_credential();
        let (cdj, auth_data, sig) =
            build_assertion(&sk, "example.com", "wrong", "https://example.com", 1);

        let result = verify_assertion(&AssertionParams {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &sig,
            expected_challenge: "Y2hhbGxlbmdl",
            expected_origin: "https://example.com",
            rp_id: "example.com",
            credential: &cred,
            require_user_verification: false,
        });
        assert!(matches!(result, Err(WebauthnError::ChallengeMismatch)));
    }

    #[test]
    fn wrong_origin_rejected() {
        let (sk, cred) = make_es256_credential();
        let (cdj, auth_data, sig) =
            build_assertion(&sk, "example.com", "ch", "https://evil.com", 1);

        let result = verify_assertion(&AssertionParams {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &sig,
            expected_challenge: "ch",
            expected_origin: "https://example.com",
            rp_id: "example.com",
            credential: &cred,
            require_user_verification: false,
        });
        assert!(matches!(result, Err(WebauthnError::OriginMismatch { .. })));
    }

    #[test]
    fn rp_id_mismatch_rejected() {
        let (sk, cred) = make_es256_credential();
        let (cdj, auth_data, sig) =
            build_assertion(&sk, "other.com", "ch", "https://example.com", 1);

        let result = verify_assertion(&AssertionParams {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &sig,
            expected_challenge: "ch",
            expected_origin: "https://example.com",
            rp_id: "example.com",
            credential: &cred,
            require_user_verification: false,
        });
        assert!(matches!(result, Err(WebauthnError::RpIdMismatch)));
    }

    #[test]
    fn sign_count_regression_rejected() {
        let (sk, mut cred) = make_es256_credential();
        cred.sign_count = 10; // stored
        let (cdj, auth_data, sig) =
            build_assertion(&sk, "example.com", "ch", "https://example.com", 5); // regression

        let result = verify_assertion(&AssertionParams {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &sig,
            expected_challenge: "ch",
            expected_origin: "https://example.com",
            rp_id: "example.com",
            credential: &cred,
            require_user_verification: false,
        });
        assert!(matches!(
            result,
            Err(WebauthnError::SignCountRegression { .. })
        ));
    }

    #[test]
    fn tampered_signature_rejected() {
        let (sk, cred) = make_es256_credential();
        let (cdj, auth_data, mut sig) =
            build_assertion(&sk, "example.com", "ch", "https://example.com", 1);
        // Tamper the last byte
        if let Some(last) = sig.last_mut() {
            *last ^= 0xFF;
        }

        let result = verify_assertion(&AssertionParams {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &sig,
            expected_challenge: "ch",
            expected_origin: "https://example.com",
            rp_id: "example.com",
            credential: &cred,
            require_user_verification: false,
        });
        assert!(matches!(result, Err(WebauthnError::InvalidSignature)));
    }

    #[test]
    fn user_verification_required_but_missing() {
        let (sk, cred) = make_es256_credential();
        let (cdj, mut auth_data, _) =
            build_assertion(&sk, "example.com", "ch", "https://example.com", 1);
        // Clear the UV flag (bit 2)
        auth_data[32] &= !0x04;
        // Re-sign with modified auth_data
        let client_data_hash = sha2::Sha256::digest(&cdj);
        let mut vd = Vec::new();
        vd.extend_from_slice(&auth_data);
        vd.extend_from_slice(&client_data_hash);
        let sig: P256Sig = sk.sign(&vd);
        let sig_bytes = sig.to_der().as_bytes().to_vec();

        let result = verify_assertion(&AssertionParams {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &sig_bytes,
            expected_challenge: "ch",
            expected_origin: "https://example.com",
            rp_id: "example.com",
            credential: &cred,
            require_user_verification: true,
        });
        assert!(matches!(result, Err(WebauthnError::UserNotVerified)));
    }
}
