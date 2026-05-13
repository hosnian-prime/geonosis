//! Key Management Service trait + software implementation.
//!
//! Per `docs/12-security-crypto.md`:
//! - Every signing operation goes through `KeyManagementService`
//! - v0.1 ships a software impl: keys wrapped with `MasterKey`
//! - v0.2 plugs Vault Transit / AWS KMS / GCP KMS through the same trait

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use geonosis_core::common::JwsAlgorithm;
use geonosis_core::id::{KeyId, RealmId};

use crate::jwk::{Jwk, JwkSet};
use crate::jwt::{PrivateMaterial, PublicMaterial};
use crate::wrap::{MasterKey, WrappedSecret};

#[derive(Debug, Error)]
pub enum KmsError {
    #[error("key not found: {0}")]
    NotFound(KeyId),
    #[error("alg mismatch: key={key:?} requested={requested:?}")]
    AlgMismatch {
        key: JwsAlgorithm,
        requested: JwsAlgorithm,
    },
    #[error("wrong key state: {0:?}")]
    WrongState(KeyState),
    #[error("wrap error: {0}")]
    Wrap(#[from] crate::wrap::WrapError),
    #[error("signing error: {0}")]
    Sign(String),
    #[error("internal: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyUsage {
    Sig,
    Enc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyState {
    Active,
    PreviousActive,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMaterial {
    pub id: KeyId,
    pub realm_id: RealmId,
    pub usage: KeyUsage,
    pub alg: JwsAlgorithm,
    pub state: KeyState,
    pub public_jwk: Jwk,
    pub private_ref: PrivateKeyRef,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivateKeyRef {
    /// Master-key-wrapped private material held in-process.
    Local(WrappedSecret),
    /// External KMS reference (Vault / AWS / GCP). Resolved by the KMS impl.
    Kms { uri: String },
}

#[async_trait]
pub trait KeyManagementService: Send + Sync {
    /// Sign a payload with the active key for the given (realm, alg) tuple.
    async fn sign(
        &self,
        realm: RealmId,
        kid: &KeyId,
        algo: JwsAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, KmsError>;

    /// Unwrap an arbitrary wrapped secret (used by federation passwords etc.).
    async fn unwrap(&self, wrapped: &WrappedSecret) -> Result<Zeroizing<Vec<u8>>, KmsError>;

    /// Get the public JWK for a key.
    async fn jwk(&self, kid: &KeyId) -> Result<Jwk, KmsError>;

    /// All keys (active + grace) for JWKS rendering.
    async fn jwks(&self, realm: RealmId) -> Result<JwkSet, KmsError>;

    /// Resolve the active signing key id for a realm.
    async fn active_signing_kid(
        &self,
        realm: RealmId,
        algo: JwsAlgorithm,
    ) -> Result<KeyId, KmsError>;

    /// Load the in-process private-material representation of a key. The
    /// software impl returns a real `PrivateMaterial`; external KMS impls
    /// MAY return `Err(KmsError::Internal(_))` and instead implement `sign`
    /// natively without exposing the material.
    async fn load_private(&self, kid: &KeyId) -> Result<PrivateMaterial, KmsError>;

    /// Load the public material for verification.
    async fn load_public(&self, kid: &KeyId) -> Result<PublicMaterial, KmsError>;
}

/// In-process software implementation. Keys are stored wrapped; the master
/// key lives in the process memory.
pub struct SoftwareKms {
    master: Arc<MasterKey>,
    store: RwLock<HashMap<KeyId, StoredKey>>,
}

struct StoredKey {
    material: KeyMaterial,
    /// Unwrapped private bytes (zeroized on drop).
    private_pem: Zeroizing<Vec<u8>>,
}

impl SoftwareKms {
    pub fn new(master: MasterKey) -> Self {
        Self {
            master: Arc::new(master),
            store: RwLock::new(HashMap::new()),
        }
    }

    /// Register a key by wrapping its PKCS#8 PEM-encoded private bytes.
    pub fn register(
        &self,
        material: KeyMaterial,
        private_pem: &[u8],
    ) -> Result<(), KmsError> {
        let _wrapped = self.master.wrap(private_pem)?;
        let stored = StoredKey {
            material,
            private_pem: Zeroizing::new(private_pem.to_vec()),
        };
        self.store.write().unwrap().insert(stored.material.id, stored);
        Ok(())
    }

    fn get_stored(&self, kid: &KeyId) -> Result<StoredKey, KmsError> {
        let guard = self.store.read().unwrap();
        let entry = guard.get(kid).ok_or(KmsError::NotFound(*kid))?;
        Ok(StoredKey {
            material: entry.material.clone(),
            private_pem: Zeroizing::new(entry.private_pem.to_vec()),
        })
    }
}

#[async_trait]
impl KeyManagementService for SoftwareKms {
    async fn sign(
        &self,
        _realm: RealmId,
        kid: &KeyId,
        algo: JwsAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, KmsError> {
        let s = self.get_stored(kid)?;
        if s.material.alg != algo {
            return Err(KmsError::AlgMismatch {
                key: s.material.alg,
                requested: algo,
            });
        }
        if s.material.state != KeyState::Active {
            return Err(KmsError::WrongState(s.material.state));
        }
        let priv_mat = pem_to_private(&s.private_pem, algo)?;
        let signing_input = data;
        match (algo, priv_mat) {
            (JwsAlgorithm::EdDSA, PrivateMaterial::EdDsa(sk)) => {
                use ed25519_dalek::Signer;
                Ok(sk.sign(signing_input).to_bytes().to_vec())
            }
            (JwsAlgorithm::ES256, PrivateMaterial::Es256(sk)) => {
                use p256::ecdsa::signature::Signer as P256Signer;
                let s: p256::ecdsa::Signature = P256Signer::sign(&sk, signing_input);
                Ok(s.to_bytes().to_vec())
            }
            (JwsAlgorithm::RS256, PrivateMaterial::Rs256(rsa)) => {
                use rsa::pkcs1v15::SigningKey;
                use rsa::sha2::Sha256;
                use rsa::signature::{RandomizedSigner, SignatureEncoding};
                let sk = SigningKey::<Sha256>::new((*rsa).clone());
                let mut rng = rand::rngs::OsRng;
                let s = sk.sign_with_rng(&mut rng, signing_input);
                Ok(s.to_bytes().to_vec())
            }
            _ => Err(KmsError::Sign("alg/key mismatch".into())),
        }
    }

    async fn unwrap(&self, wrapped: &WrappedSecret) -> Result<Zeroizing<Vec<u8>>, KmsError> {
        Ok(self.master.unwrap(wrapped)?)
    }

    async fn jwk(&self, kid: &KeyId) -> Result<Jwk, KmsError> {
        let s = self.get_stored(kid)?;
        Ok(s.material.public_jwk)
    }

    async fn jwks(&self, realm: RealmId) -> Result<JwkSet, KmsError> {
        let guard = self.store.read().unwrap();
        let keys = guard
            .values()
            .filter(|s| s.material.realm_id == realm)
            .filter(|s| matches!(s.material.state, KeyState::Active | KeyState::PreviousActive))
            .map(|s| s.material.public_jwk.clone())
            .collect();
        Ok(JwkSet { keys })
    }

    async fn active_signing_kid(
        &self,
        realm: RealmId,
        algo: JwsAlgorithm,
    ) -> Result<KeyId, KmsError> {
        let guard = self.store.read().unwrap();
        guard
            .values()
            .find(|s| {
                s.material.realm_id == realm
                    && s.material.alg == algo
                    && s.material.state == KeyState::Active
            })
            .map(|s| s.material.id)
            .ok_or_else(|| KmsError::Internal(format!("no active key for {algo:?} in {realm}")))
    }

    async fn load_private(&self, kid: &KeyId) -> Result<PrivateMaterial, KmsError> {
        let s = self.get_stored(kid)?;
        pem_to_private(&s.private_pem, s.material.alg)
    }

    async fn load_public(&self, kid: &KeyId) -> Result<PublicMaterial, KmsError> {
        let s = self.get_stored(kid)?;
        pem_to_public_via_private(&s.private_pem, s.material.alg)
    }
}

fn pem_to_private(pem: &[u8], alg: JwsAlgorithm) -> Result<PrivateMaterial, KmsError> {
    use pkcs8::DecodePrivateKey;
    let pem_str = std::str::from_utf8(pem).map_err(|e| KmsError::Internal(e.to_string()))?;
    match alg {
        JwsAlgorithm::EdDSA => {
            let sk = ed25519_dalek::SigningKey::from_pkcs8_pem(pem_str)
                .map_err(|e| KmsError::Internal(e.to_string()))?;
            Ok(PrivateMaterial::EdDsa(sk))
        }
        JwsAlgorithm::ES256 => {
            let sk = p256::ecdsa::SigningKey::from_pkcs8_pem(pem_str)
                .map_err(|e| KmsError::Internal(e.to_string()))?;
            Ok(PrivateMaterial::Es256(sk))
        }
        JwsAlgorithm::RS256 => {
            let sk = rsa::RsaPrivateKey::from_pkcs8_pem(pem_str)
                .map_err(|e| KmsError::Internal(e.to_string()))?;
            Ok(PrivateMaterial::Rs256(Box::new(sk)))
        }
        other => Err(KmsError::Internal(format!("alg not supported in v0.1 soft KMS: {other:?}"))),
    }
}

fn pem_to_public_via_private(pem: &[u8], alg: JwsAlgorithm) -> Result<PublicMaterial, KmsError> {
    match pem_to_private(pem, alg)? {
        PrivateMaterial::EdDsa(sk) => Ok(PublicMaterial::EdDsa(sk.verifying_key())),
        PrivateMaterial::Es256(sk) => Ok(PublicMaterial::Es256(*sk.verifying_key())),
        PrivateMaterial::Rs256(rsa) => Ok(PublicMaterial::Rs256(Box::new(rsa.to_public_key()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::Jwk;
    use ed25519_dalek::SigningKey;
    use pkcs8::EncodePrivateKey;
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn ed25519_pem() -> Vec<u8> {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let sk = SigningKey::from_bytes(&bytes);
        sk.to_pkcs8_pem(pkcs8::LineEnding::LF)
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    #[tokio::test]
    async fn register_and_jwk_lookup() {
        let kms = SoftwareKms::new(MasterKey::generate());
        let kid = KeyId::new();
        let realm = RealmId::new();
        let material = KeyMaterial {
            id: kid,
            realm_id: realm,
            usage: KeyUsage::Sig,
            alg: JwsAlgorithm::EdDSA,
            state: KeyState::Active,
            public_jwk: Jwk {
                kid: kid.to_string(),
                kty: "OKP".into(),
                r#use: "sig".into(),
                alg: "EdDSA".into(),
                params: serde_json::Map::new(),
            },
            private_ref: PrivateKeyRef::Local(WrappedSecret {
                nonce: vec![],
                ciphertext: vec![],
            }),
            created_at: Utc::now(),
            rotated_at: None,
        };
        kms.register(material, &ed25519_pem()).unwrap();
        let j = kms.jwk(&kid).await.unwrap();
        assert_eq!(j.alg, "EdDSA");
    }

    #[tokio::test]
    async fn active_signing_kid_for_alg() {
        let kms = SoftwareKms::new(MasterKey::generate());
        let kid = KeyId::new();
        let realm = RealmId::new();
        let material = KeyMaterial {
            id: kid,
            realm_id: realm,
            usage: KeyUsage::Sig,
            alg: JwsAlgorithm::EdDSA,
            state: KeyState::Active,
            public_jwk: Jwk {
                kid: kid.to_string(),
                kty: "OKP".into(),
                r#use: "sig".into(),
                alg: "EdDSA".into(),
                params: serde_json::Map::new(),
            },
            private_ref: PrivateKeyRef::Local(WrappedSecret {
                nonce: vec![],
                ciphertext: vec![],
            }),
            created_at: Utc::now(),
            rotated_at: None,
        };
        kms.register(material, &ed25519_pem()).unwrap();
        let found = kms.active_signing_kid(realm, JwsAlgorithm::EdDSA).await.unwrap();
        assert_eq!(found, kid);
    }

    #[tokio::test]
    async fn jwks_excludes_disabled() {
        let kms = SoftwareKms::new(MasterKey::generate());
        let realm = RealmId::new();
        for state in [KeyState::Active, KeyState::PreviousActive, KeyState::Disabled] {
            let kid = KeyId::new();
            let material = KeyMaterial {
                id: kid,
                realm_id: realm,
                usage: KeyUsage::Sig,
                alg: JwsAlgorithm::EdDSA,
                state,
                public_jwk: Jwk {
                    kid: kid.to_string(),
                    kty: "OKP".into(),
                    r#use: "sig".into(),
                    alg: "EdDSA".into(),
                    params: serde_json::Map::new(),
                },
                private_ref: PrivateKeyRef::Local(WrappedSecret {
                    nonce: vec![],
                    ciphertext: vec![],
                }),
                created_at: Utc::now(),
                rotated_at: None,
            };
            kms.register(material, &ed25519_pem()).unwrap();
        }
        let set = kms.jwks(realm).await.unwrap();
        assert_eq!(set.keys.len(), 2);
    }
}
