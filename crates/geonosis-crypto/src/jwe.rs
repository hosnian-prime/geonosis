//! Compact-JWE encryption + decryption (RFC 7516).
//!
//! v0.1 ships a deliberately small allowlist so the audit surface stays
//! narrow:
//!
//! - `alg` (key-wrap): `RSA-OAEP-256` (RFC 7518 §4.3), `dir` (§4.5)
//! - `enc` (content-encryption): `A256GCM` (RFC 7518 §5.3)
//!
//! Anything outside the allowlist is rejected at construction (encrypt) or
//! at header-parse time (decrypt). The crate hand-rolls the compact form on
//! top of `rsa` + `aes-gcm` rather than pulling in `josekit` — same posture
//! as the JWS module, where a small audited surface beats a large library.
//!
//! Compact serialization (5 base64url segments, RFC 7516 §3):
//!
//! ```text
//! BASE64URL(header) "." BASE64URL(encrypted_key) "." BASE64URL(iv)
//!   "." BASE64URL(ciphertext) "." BASE64URL(tag)
//! ```

// `aes-gcm 0.10` still exports the `generic-array 0.14` constructors that
// migrated to `1.x` upstream; the same allowance lives in `wrap.rs` until
// the workspace pin moves.
#![allow(deprecated)]

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes256Gcm;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::sha2::Sha256;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::base64url;

/// Key-management algorithms in the v0.1 allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JweAlg {
    /// RSAES OAEP with SHA-256 (RFC 7518 §4.3).
    RsaOaep256,
    /// Direct use of a shared symmetric key (RFC 7518 §4.5). No key wrap.
    Dir,
}

impl JweAlg {
    pub fn as_str(self) -> &'static str {
        match self {
            JweAlg::RsaOaep256 => "RSA-OAEP-256",
            JweAlg::Dir => "dir",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "RSA-OAEP-256" => Some(JweAlg::RsaOaep256),
            "dir" => Some(JweAlg::Dir),
            _ => None,
        }
    }
}

/// Content-encryption algorithms in the v0.1 allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JweEnc {
    /// AES-256-GCM (RFC 7518 §5.3): 256-bit key, 96-bit IV, 128-bit tag.
    A256Gcm,
}

impl JweEnc {
    pub fn as_str(self) -> &'static str {
        match self {
            JweEnc::A256Gcm => "A256GCM",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "A256GCM" => Some(JweEnc::A256Gcm),
            _ => None,
        }
    }

    /// Required content-encryption-key length in bytes.
    fn cek_len(self) -> usize {
        match self {
            JweEnc::A256Gcm => 32,
        }
    }

    /// IV length in bytes (96-bit for GCM, per RFC 7518 §5.3).
    fn iv_len(self) -> usize {
        match self {
            JweEnc::A256Gcm => 12,
        }
    }
}

#[derive(Debug, Error)]
pub enum JweError {
    #[error("unsupported alg: {0}")]
    UnsupportedAlg(String),
    #[error("unsupported enc: {0}")]
    UnsupportedEnc(String),
    #[error("malformed JWE: {0}")]
    Malformed(String),
    #[error("base64url: {0}")]
    Base64(String),
    #[error("key wrap / unwrap failed: {0}")]
    KeyWrap(String),
    #[error("content encryption / decryption failed")]
    Aead,
    #[error("serialization: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("invalid key material: {0}")]
    Key(String),
}

/// Recipient public-key material for `encrypt`.
///
/// `Dir` wraps a 32-byte CEK the caller already shares with the recipient;
/// `RsaOaep256` wraps the recipient's RSA public key (>= 2048 bits in
/// practice — the underlying `rsa` crate enforces a minimum).
#[derive(Debug, Clone)]
pub enum JweRecipientKey {
    RsaOaep256(Box<RsaPublicKey>),
    Dir([u8; 32]),
}

/// Recipient private-key material for `decrypt`. Mirrors `JweRecipientKey`.
#[derive(Debug, Clone)]
pub enum JweRecipientPrivateKey {
    RsaOaep256(Box<RsaPrivateKey>),
    Dir([u8; 32]),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JweHeader {
    alg: String,
    enc: String,
}

/// Encrypt `plaintext` into a compact JWE.
///
/// `plaintext` is normally the serialized JWT claims. The function picks a
/// fresh CEK (for `RSA-OAEP-256`) or uses the caller-supplied symmetric key
/// (for `dir`), then runs `A256GCM` with the protected header as AAD per
/// RFC 7516 §5.1.
pub fn encrypt(
    plaintext: &[u8],
    recipient: &JweRecipientKey,
    alg: JweAlg,
    enc: JweEnc,
) -> Result<String, JweError> {
    // Cross-check: `dir` only makes sense when the caller already holds the
    // CEK; `RSA-OAEP-256` only makes sense when wrapping a random CEK.
    match (alg, recipient) {
        (JweAlg::RsaOaep256, JweRecipientKey::RsaOaep256(_)) => {}
        (JweAlg::Dir, JweRecipientKey::Dir(_)) => {}
        _ => return Err(JweError::Key("alg / recipient key mismatch".into())),
    }

    // Step 1: derive the CEK and the wrapped-key segment.
    let (cek, encrypted_key): (Vec<u8>, Vec<u8>) = match (alg, recipient) {
        (JweAlg::RsaOaep256, JweRecipientKey::RsaOaep256(pk)) => {
            let mut cek = vec![0u8; enc.cek_len()];
            OsRng.fill_bytes(&mut cek);
            let padding = Oaep::new::<Sha256>();
            let wrapped = pk
                .encrypt(&mut OsRng, padding, &cek)
                .map_err(|e| JweError::KeyWrap(e.to_string()))?;
            (cek, wrapped)
        }
        (JweAlg::Dir, JweRecipientKey::Dir(k)) => {
            // RFC 7518 §4.5: encrypted_key is the empty octet sequence.
            (k.to_vec(), Vec::new())
        }
        _ => unreachable!("guarded above"),
    };

    if cek.len() != enc.cek_len() {
        return Err(JweError::Key(format!(
            "CEK length {} != {} required by enc",
            cek.len(),
            enc.cek_len()
        )));
    }

    // Step 2: serialize the protected header. Per RFC 7516 §5.1 step 14 the
    // header is encoded BEFORE we run AEAD, because the encoded form is the
    // AAD bound into the tag.
    let header = JweHeader {
        alg: alg.as_str().into(),
        enc: enc.as_str().into(),
    };
    let header_json = serde_json::to_vec(&header)?;
    let header_b64 = base64url::encode(&header_json);

    // Step 3: AES-GCM. JWE splits the AEAD output into ciphertext + tag, so
    // we use the detached-tag path rather than the combined `encrypt`.
    let mut iv = vec![0u8; enc.iv_len()];
    OsRng.fill_bytes(&mut iv);

    let cipher = Aes256Gcm::new_from_slice(&cek).map_err(|e| JweError::Key(e.to_string()))?;
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(
            GenericArray::from_slice(&iv),
            header_b64.as_bytes(),
            &mut buffer,
        )
        .map_err(|_| JweError::Aead)?;

    // Step 4: assemble compact form.
    let mut out = header_b64;
    out.push('.');
    out.push_str(&base64url::encode(&encrypted_key));
    out.push('.');
    out.push_str(&base64url::encode(&iv));
    out.push('.');
    out.push_str(&base64url::encode(&buffer));
    out.push('.');
    out.push_str(&base64url::encode(tag.as_slice()));
    Ok(out)
}

/// Decrypt a compact JWE. Returns the plaintext (typically JSON claims).
///
/// The header is parsed first and its `alg`/`enc` are checked against the
/// v0.1 allowlist before any cryptographic work runs. The AAD bound into
/// the AEAD tag is the original base64url-encoded header segment — we keep
/// the original bytes rather than re-encoding, so a header that round-trips
/// through serde with a different key order still authenticates.
pub fn decrypt(jwe: &str, recipient: &JweRecipientPrivateKey) -> Result<Vec<u8>, JweError> {
    let mut parts = jwe.split('.');
    let h_b64 = parts
        .next()
        .ok_or_else(|| JweError::Malformed("missing header".into()))?;
    let ek_b64 = parts
        .next()
        .ok_or_else(|| JweError::Malformed("missing encrypted_key".into()))?;
    let iv_b64 = parts
        .next()
        .ok_or_else(|| JweError::Malformed("missing iv".into()))?;
    let ct_b64 = parts
        .next()
        .ok_or_else(|| JweError::Malformed("missing ciphertext".into()))?;
    let tag_b64 = parts
        .next()
        .ok_or_else(|| JweError::Malformed("missing tag".into()))?;
    if parts.next().is_some() {
        return Err(JweError::Malformed("extra segment".into()));
    }

    let header_bytes = base64url::decode(h_b64).map_err(|e| JweError::Base64(e.to_string()))?;
    let header: JweHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| JweError::Malformed(format!("header json: {e}")))?;

    let alg =
        JweAlg::parse(&header.alg).ok_or_else(|| JweError::UnsupportedAlg(header.alg.clone()))?;
    let enc =
        JweEnc::parse(&header.enc).ok_or_else(|| JweError::UnsupportedEnc(header.enc.clone()))?;

    // Match alg to recipient key arm. A mismatch here is a caller bug, not
    // a protocol error — return `Key` so it surfaces clearly in logs.
    let cek: Vec<u8> = match (alg, recipient) {
        (JweAlg::RsaOaep256, JweRecipientPrivateKey::RsaOaep256(sk)) => {
            let wrapped = base64url::decode(ek_b64).map_err(|e| JweError::Base64(e.to_string()))?;
            let padding = Oaep::new::<Sha256>();
            sk.decrypt(padding, &wrapped)
                .map_err(|e| JweError::KeyWrap(e.to_string()))?
        }
        (JweAlg::Dir, JweRecipientPrivateKey::Dir(k)) => {
            if !ek_b64.is_empty() {
                return Err(JweError::Malformed(
                    "dir alg requires empty encrypted_key".into(),
                ));
            }
            k.to_vec()
        }
        _ => return Err(JweError::Key("alg / recipient key mismatch".into())),
    };

    if cek.len() != enc.cek_len() {
        return Err(JweError::Key(format!(
            "CEK length {} != {} required by enc",
            cek.len(),
            enc.cek_len()
        )));
    }

    let iv = base64url::decode(iv_b64).map_err(|e| JweError::Base64(e.to_string()))?;
    if iv.len() != enc.iv_len() {
        return Err(JweError::Malformed(format!(
            "iv length {} != {}",
            iv.len(),
            enc.iv_len()
        )));
    }
    let mut buffer = base64url::decode(ct_b64).map_err(|e| JweError::Base64(e.to_string()))?;
    let tag = base64url::decode(tag_b64).map_err(|e| JweError::Base64(e.to_string()))?;
    if tag.len() != 16 {
        return Err(JweError::Malformed(format!(
            "tag length {} != 16",
            tag.len()
        )));
    }

    let cipher = Aes256Gcm::new_from_slice(&cek).map_err(|e| JweError::Key(e.to_string()))?;
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(&iv),
            h_b64.as_bytes(),
            &mut buffer,
            GenericArray::from_slice(&tag),
        )
        .map_err(|_| JweError::Aead)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    use rsa::RsaPrivateKey;

    const PAYLOAD: &[u8] = br#"{"sub":"alice","iat":1700000000,"scope":"read"}"#;

    fn fresh_rsa() -> RsaPrivateKey {
        // 2048 is the smallest size the RSA crate accepts for OAEP-SHA256
        // with a 32-byte CEK. Tests stay reasonably fast.
        RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen")
    }

    #[test]
    fn rsa_oaep_256_a256gcm_roundtrip() {
        let sk = fresh_rsa();
        let pk = sk.to_public_key();
        let jwe = encrypt(
            PAYLOAD,
            &JweRecipientKey::RsaOaep256(Box::new(pk)),
            JweAlg::RsaOaep256,
            JweEnc::A256Gcm,
        )
        .unwrap();
        assert_eq!(jwe.matches('.').count(), 4, "compact JWE has 5 segments");

        let pt = decrypt(&jwe, &JweRecipientPrivateKey::RsaOaep256(Box::new(sk))).unwrap();
        assert_eq!(pt, PAYLOAD);
    }

    #[test]
    fn dir_a256gcm_roundtrip() {
        let key = crate::random::random_bytes::<32>();
        let jwe = encrypt(
            PAYLOAD,
            &JweRecipientKey::Dir(key),
            JweAlg::Dir,
            JweEnc::A256Gcm,
        )
        .unwrap();
        // dir => encrypted_key segment is empty.
        let parts: Vec<&str> = jwe.split('.').collect();
        assert_eq!(parts.len(), 5);
        assert!(parts[1].is_empty(), "encrypted_key must be empty for dir");

        let pt = decrypt(&jwe, &JweRecipientPrivateKey::Dir(key)).unwrap();
        assert_eq!(pt, PAYLOAD);
    }

    #[test]
    fn tampered_ciphertext_fails_aead() {
        let key = crate::random::random_bytes::<32>();
        let jwe = encrypt(
            PAYLOAD,
            &JweRecipientKey::Dir(key),
            JweAlg::Dir,
            JweEnc::A256Gcm,
        )
        .unwrap();
        let mut parts: Vec<String> = jwe.split('.').map(str::to_string).collect();
        // Flip one byte of ciphertext.
        let mut ct = base64url::decode(&parts[3]).unwrap();
        ct[0] ^= 0x01;
        parts[3] = base64url::encode(&ct);
        let tampered = parts.join(".");
        let err = decrypt(&tampered, &JweRecipientPrivateKey::Dir(key)).unwrap_err();
        assert!(matches!(err, JweError::Aead), "got {err:?}");
    }

    #[test]
    fn wrong_key_fails() {
        let k1 = crate::random::random_bytes::<32>();
        let k2 = crate::random::random_bytes::<32>();
        let jwe = encrypt(
            PAYLOAD,
            &JweRecipientKey::Dir(k1),
            JweAlg::Dir,
            JweEnc::A256Gcm,
        )
        .unwrap();
        let err = decrypt(&jwe, &JweRecipientPrivateKey::Dir(k2)).unwrap_err();
        assert!(matches!(err, JweError::Aead), "got {err:?}");
    }

    #[test]
    fn rejects_unsupported_alg() {
        // Hand-craft a header with a forbidden alg ("A128KW") and a valid
        // enc; we never need real ciphertext because the header check runs
        // first.
        let header = serde_json::json!({"alg":"A128KW","enc":"A256GCM"});
        let h_b64 = base64url::encode(serde_json::to_vec(&header).unwrap());
        let token = format!(
            "{h_b64}..{}..{}",
            base64url::encode([0u8; 12]),
            base64url::encode([0u8; 16])
        );
        let key = [0u8; 32];
        let err = decrypt(&token, &JweRecipientPrivateKey::Dir(key)).unwrap_err();
        assert!(
            matches!(err, JweError::UnsupportedAlg(ref s) if s == "A128KW"),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_unsupported_enc() {
        // RFC 7518 §5.2 defines A128CBC-HS256; we explicitly do not accept it.
        let header = serde_json::json!({"alg":"dir","enc":"A128CBC-HS256"});
        let h_b64 = base64url::encode(serde_json::to_vec(&header).unwrap());
        let token = format!(
            "{h_b64}..{}..{}",
            base64url::encode([0u8; 12]),
            base64url::encode([0u8; 16])
        );
        let key = [0u8; 32];
        let err = decrypt(&token, &JweRecipientPrivateKey::Dir(key)).unwrap_err();
        assert!(
            matches!(err, JweError::UnsupportedEnc(ref s) if s == "A128CBC-HS256"),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_malformed_segment_count() {
        let key = [0u8; 32];
        let err = decrypt("a.b.c", &JweRecipientPrivateKey::Dir(key)).unwrap_err();
        assert!(matches!(err, JweError::Malformed(_)), "got {err:?}");
        let err = decrypt("a.b.c.d.e.f", &JweRecipientPrivateKey::Dir(key)).unwrap_err();
        assert!(matches!(err, JweError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn rejects_alg_recipient_mismatch_on_encrypt() {
        let key = crate::random::random_bytes::<32>();
        let err = encrypt(
            PAYLOAD,
            &JweRecipientKey::Dir(key),
            JweAlg::RsaOaep256,
            JweEnc::A256Gcm,
        )
        .unwrap_err();
        assert!(matches!(err, JweError::Key(_)), "got {err:?}");
    }
}
