//! AES-256-GCM master-key wrap.
//!
//! Private keys at rest are wrapped under a 32-byte master key supplied at
//! boot via env (`GEONOSIS_MASTER_KEY`). The master key is never persisted.

#![allow(deprecated)]

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Error)]
pub enum WrapError {
    #[error("wrap failed: {0}")]
    Encrypt(String),
    #[error("unwrap failed: {0}")]
    Decrypt(String),
    #[error("master key must be 32 bytes (got {0})")]
    BadKeyLen(usize),
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(***)")
    }
}

impl MasterKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(b: &[u8]) -> Result<Self, WrapError> {
        b.try_into()
            .map(Self)
            .map_err(|_| WrapError::BadKeyLen(b.len()))
    }

    /// Generate a fresh master key (test / boot fallback only).
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        Self(k)
    }

    pub fn wrap(&self, plaintext: &[u8]) -> Result<WrappedSecret, WrapError> {
        let cipher = Aes256Gcm::new_from_slice(&self.0)
            .map_err(|e| WrapError::Encrypt(e.to_string()))?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(GenericArray::from_slice(&nonce), plaintext)
            .map_err(|e| WrapError::Encrypt(e.to_string()))?;
        Ok(WrappedSecret {
            nonce: nonce.to_vec(),
            ciphertext: ct,
        })
    }

    pub fn unwrap(&self, wrapped: &WrappedSecret) -> Result<zeroize::Zeroizing<Vec<u8>>, WrapError> {
        let cipher = Aes256Gcm::new_from_slice(&self.0)
            .map_err(|e| WrapError::Decrypt(e.to_string()))?;
        let pt = cipher
            .decrypt(
                GenericArray::from_slice(&wrapped.nonce),
                wrapped.ciphertext.as_slice(),
            )
            .map_err(|e| WrapError::Decrypt(e.to_string()))?;
        Ok(zeroize::Zeroizing::new(pt))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedSecret {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let k = MasterKey::generate();
        let pt = b"super-secret-key-material";
        let w = k.wrap(pt).unwrap();
        let pt2 = k.unwrap(&w).unwrap();
        assert_eq!(&pt2[..], pt);
    }

    #[test]
    fn unwrap_fails_under_wrong_key() {
        let k1 = MasterKey::generate();
        let k2 = MasterKey::generate();
        let w = k1.wrap(b"x").unwrap();
        assert!(k2.unwrap(&w).is_err());
    }

    #[test]
    fn each_wrap_uses_fresh_nonce() {
        let k = MasterKey::generate();
        let a = k.wrap(b"x").unwrap();
        let b = k.wrap(b"x").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn debug_redacts_key() {
        let k = MasterKey::from_bytes([1u8; 32]);
        assert_eq!(format!("{k:?}"), "MasterKey(***)");
    }
}
