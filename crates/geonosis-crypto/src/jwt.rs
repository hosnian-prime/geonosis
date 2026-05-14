//! Compact-JWS encoding + verification.
//!
//! v0.1 supports RS256, ES256, EdDSA. PS256 and ES384 are accepted in JWK
//! advertisement but rejected at signing time with `Unsupported` — they
//! land with a real implementation as part of `crypto-completion` in v0.1
//! follow-up commits.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use p256::ecdsa::signature::{Signer as P256Signer, Verifier as P256Verifier};
use p256::ecdsa::{Signature as P256Sig, SigningKey as P256Sk, VerifyingKey as P256Vk};
use rsa::pkcs1v15::{Signature as RsaSig, SigningKey as RsaSk, VerifyingKey as RsaVk};
use rsa::sha2::Sha256;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier as RsaVerifier};
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use geonosis_core::common::JwsAlgorithm;

use crate::base64url;

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("unsupported alg for sign: {0:?}")]
    Unsupported(JwsAlgorithm),
    #[error("payload not serializable: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("signing failed: {0}")]
    Sign(String),
    #[error("key length / parse error: {0}")]
    Key(String),
}

#[derive(Debug, Error)]
pub enum JwtVerifyError {
    #[error("malformed compact JWS: {0}")]
    Malformed(String),
    #[error("base64url: {0}")]
    Base64(String),
    #[error("alg mismatch: header={header} expected={expected}")]
    AlgMismatch { header: String, expected: String },
    #[error("kid mismatch: header={header} expected={expected}")]
    KidMismatch { header: String, expected: String },
    #[error("invalid signature")]
    InvalidSignature,
    #[error("verifier key invalid: {0}")]
    Key(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwsHeader {
    pub alg: String,
    pub kid: String,
    pub typ: String,
}

impl JwsHeader {
    pub fn new(alg: JwsAlgorithm, kid: impl Into<String>, typ: impl Into<String>) -> Self {
        Self {
            alg: alg.as_str().into(),
            kid: kid.into(),
            typ: typ.into(),
        }
    }
}

/// Private-key material the signer accepts. Constructors pick the right
/// arm; callers do not normally construct this directly — the KMS layer
/// resolves a `kid` into a `PrivateMaterial`.
#[derive(Debug, Clone)]
pub enum PrivateMaterial {
    Rs256(Box<RsaPrivateKey>),
    Es256(P256Sk),
    EdDsa(SigningKey),
}

#[derive(Debug, Clone)]
pub enum PublicMaterial {
    Rs256(Box<rsa::RsaPublicKey>),
    Es256(P256Vk),
    EdDsa(VerifyingKey),
}

/// Sign a claims payload into compact JWS form (`header.payload.sig`).
pub fn sign_jwt<T: Serialize>(
    header: &JwsHeader,
    claims: &T,
    key: &PrivateMaterial,
) -> Result<String, JwtError> {
    let h = serde_json::to_vec(header)?;
    let p = serde_json::to_vec(claims)?;
    let mut signing_input = base64url::encode(&h);
    signing_input.push('.');
    signing_input.push_str(&base64url::encode(&p));

    let sig = match (header.alg.as_str(), key) {
        ("RS256", PrivateMaterial::Rs256(rsa)) => {
            let sk = RsaSk::<Sha256>::new((**rsa).clone());
            let mut rng = rand::rngs::OsRng;
            let s: RsaSig = sk.sign_with_rng(&mut rng, signing_input.as_bytes());
            s.to_bytes().to_vec()
        }
        ("ES256", PrivateMaterial::Es256(sk)) => {
            let s: P256Sig = P256Signer::sign(sk, signing_input.as_bytes());
            // ECDSA signatures in JWS are R || S concatenated (raw form).
            s.to_bytes().to_vec()
        }
        ("EdDSA", PrivateMaterial::EdDsa(sk)) => {
            let s = sk.sign(signing_input.as_bytes());
            s.to_bytes().to_vec()
        }
        (alg, _) => {
            return Err(JwtError::Unsupported(
                match alg {
                    "RS256" => JwsAlgorithm::RS256,
                    "ES256" => JwsAlgorithm::ES256,
                    "EdDSA" => JwsAlgorithm::EdDSA,
                    _ => JwsAlgorithm::HS256,
                },
            ));
        }
    };

    let mut out = signing_input;
    out.push('.');
    out.push_str(&base64url::encode(sig));
    Ok(out)
}

/// Verify a compact JWS, return the parsed claims of type `C` on success.
pub fn verify_jwt<C: for<'de> Deserialize<'de>>(
    token: &str,
    expected_alg: JwsAlgorithm,
    expected_kid: &str,
    key: &PublicMaterial,
) -> Result<C, JwtVerifyError> {
    let mut parts = token.split('.');
    let h_b64 = parts
        .next()
        .ok_or_else(|| JwtVerifyError::Malformed("no header".into()))?;
    let p_b64 = parts
        .next()
        .ok_or_else(|| JwtVerifyError::Malformed("no payload".into()))?;
    let s_b64 = parts
        .next()
        .ok_or_else(|| JwtVerifyError::Malformed("no sig".into()))?;
    if parts.next().is_some() {
        return Err(JwtVerifyError::Malformed("extra segment".into()));
    }

    let h_bytes =
        base64url::decode(h_b64).map_err(|e| JwtVerifyError::Base64(e.to_string()))?;
    let header: JwsHeader = serde_json::from_slice(&h_bytes)
        .map_err(|e| JwtVerifyError::Malformed(e.to_string()))?;
    if header.alg != expected_alg.as_str() {
        return Err(JwtVerifyError::AlgMismatch {
            header: header.alg,
            expected: expected_alg.as_str().to_string(),
        });
    }
    if header.kid != expected_kid {
        return Err(JwtVerifyError::KidMismatch {
            header: header.kid,
            expected: expected_kid.to_string(),
        });
    }

    let signing_input = format!("{h_b64}.{p_b64}");
    let sig_bytes =
        base64url::decode(s_b64).map_err(|e| JwtVerifyError::Base64(e.to_string()))?;

    let ok = match (expected_alg, key) {
        (JwsAlgorithm::RS256, PublicMaterial::Rs256(pk)) => {
            let vk = RsaVk::<Sha256>::new((**pk).clone());
            let s = RsaSig::try_from(sig_bytes.as_slice())
                .map_err(|e| JwtVerifyError::Key(e.to_string()))?;
            RsaVerifier::verify(&vk, signing_input.as_bytes(), &s).is_ok()
        }
        (JwsAlgorithm::ES256, PublicMaterial::Es256(vk)) => {
            let s = P256Sig::try_from(sig_bytes.as_slice())
                .map_err(|e| JwtVerifyError::Key(e.to_string()))?;
            P256Verifier::verify(vk, signing_input.as_bytes(), &s).is_ok()
        }
        (JwsAlgorithm::EdDSA, PublicMaterial::EdDsa(vk)) => {
            let s = ed25519_dalek::Signature::try_from(sig_bytes.as_slice())
                .map_err(|e| JwtVerifyError::Key(e.to_string()))?;
            vk.verify(signing_input.as_bytes(), &s).is_ok()
        }
        _ => return Err(JwtVerifyError::Key("alg / key mismatch".into())),
    };

    if !ok {
        return Err(JwtVerifyError::InvalidSignature);
    }

    let p_bytes =
        base64url::decode(p_b64).map_err(|e| JwtVerifyError::Base64(e.to_string()))?;
    let claims: C = serde_json::from_slice(&p_bytes)
        .map_err(|e| JwtVerifyError::Malformed(e.to_string()))?;
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey as Ed25519Sk;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use rsa::RsaPrivateKey;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Claims {
        sub: String,
        n: i64,
    }

    #[test]
    fn eddsa_sign_verify_roundtrip() {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let sk = Ed25519Sk::from_bytes(&bytes);
        let vk = sk.verifying_key();

        let header = JwsHeader::new(JwsAlgorithm::EdDSA, "k1", "JWT");
        let claims = Claims {
            sub: "alice".into(),
            n: 7,
        };
        let token = sign_jwt(&header, &claims, &PrivateMaterial::EdDsa(sk)).unwrap();
        assert!(token.matches('.').count() == 2);

        let verified: Claims = verify_jwt(
            &token,
            JwsAlgorithm::EdDSA,
            "k1",
            &PublicMaterial::EdDsa(vk),
        )
        .unwrap();
        assert_eq!(verified, claims);
    }

    #[test]
    fn rejects_alg_mismatch() {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let sk = Ed25519Sk::from_bytes(&bytes);
        let vk = sk.verifying_key();
        let header = JwsHeader::new(JwsAlgorithm::EdDSA, "k1", "JWT");
        let claims = Claims {
            sub: "alice".into(),
            n: 7,
        };
        let token = sign_jwt(&header, &claims, &PrivateMaterial::EdDsa(sk)).unwrap();
        let err = verify_jwt::<Claims>(&token, JwsAlgorithm::RS256, "k1", &PublicMaterial::EdDsa(vk))
            .unwrap_err();
        match err {
            JwtVerifyError::AlgMismatch { .. } => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn rs256_sign_verify_roundtrip() {
        let mut rng = OsRng;
        let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pubkey = key.to_public_key();

        let header = JwsHeader::new(JwsAlgorithm::RS256, "k2", "JWT");
        let claims = Claims {
            sub: "bob".into(),
            n: 42,
        };
        let token = sign_jwt(&header, &claims, &PrivateMaterial::Rs256(Box::new(key))).unwrap();
        let v: Claims = verify_jwt(
            &token,
            JwsAlgorithm::RS256,
            "k2",
            &PublicMaterial::Rs256(Box::new(pubkey)),
        )
        .unwrap();
        assert_eq!(v, claims);
    }

    #[test]
    fn rejects_kid_mismatch() {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let sk = Ed25519Sk::from_bytes(&bytes);
        let vk = sk.verifying_key();
        let header = JwsHeader::new(JwsAlgorithm::EdDSA, "k1", "JWT");
        let claims = Claims {
            sub: "alice".into(),
            n: 7,
        };
        let token = sign_jwt(&header, &claims, &PrivateMaterial::EdDsa(sk)).unwrap();
        let err =
            verify_jwt::<Claims>(&token, JwsAlgorithm::EdDSA, "k2", &PublicMaterial::EdDsa(vk))
                .unwrap_err();
        assert!(matches!(err, JwtVerifyError::KidMismatch { .. }));
    }
}
