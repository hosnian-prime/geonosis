//! Signed plugin manifest.
//!
//! Per `docs/07-spi-wasm.md` §"Signed manifests": every WASM plugin
//! distributed to operators ships with a manifest TOML describing
//! WHAT it is (alias, interface, sha256 of the .wasm bytes) and a
//! detached Ed25519 signature signed by the author's release key.
//! Operators import the signer pubkey out-of-band and the runtime
//! refuses to install a plugin whose signature doesn't match.
//!
//! Wire format:
//! - `manifest.toml` — claims, no signature field
//! - `manifest.sig`  — base64-encoded raw Ed25519 signature over the
//!   manifest TOML bytes
//!
//! Keeping the signature detached means the manifest stays
//! diff-friendly + the signing tooling never has to re-emit a
//! canonical TOML.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Bumped if the manifest shape ever changes. v0.1 ships v1.
    pub schema_version: u32,
    /// Operator-facing alias (`spi-twilio`, `spi-google-broker`, …).
    pub alias: String,
    /// Stable WIT interface name, e.g. `geonosis:event@0.1.0`.
    pub interface: String,
    /// Hex-encoded SHA-256 of the `.wasm` bytecode. Verified at
    /// install time so an attacker can't swap the bytecode after
    /// signing.
    pub sha256: String,
    /// Plugin author's release version (semver string).
    pub version: String,
    /// Base64-encoded raw 32-byte Ed25519 public key of the signer.
    /// Operators pin trusted signers via `geoctl spi trust <pubkey>`;
    /// the runtime refuses unknown signers.
    pub signer_pubkey_b64: String,
    /// Free-text description shown in the admin UI.
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("invalid TOML: {0}")]
    Toml(String),
    #[error("invalid signature encoding: {0}")]
    BadSignature(String),
    #[error("invalid pubkey encoding: {0}")]
    BadPubkey(String),
    #[error("signature does not verify against pubkey + manifest bytes")]
    SignatureMismatch,
    #[error("wasm sha256 mismatch: manifest={manifest} actual={actual}")]
    Sha256Mismatch { manifest: String, actual: String },
    #[error("untrusted signer pubkey: {0}")]
    UntrustedSigner(String),
}

impl PluginManifest {
    pub fn from_toml(bytes: &[u8]) -> Result<Self, ManifestError> {
        let s =
            std::str::from_utf8(bytes).map_err(|e| ManifestError::Toml(format!("utf-8: {e}")))?;
        toml::from_str(s).map_err(|e| ManifestError::Toml(e.to_string()))
    }

    pub fn to_toml(&self) -> Result<Vec<u8>, ManifestError> {
        toml::to_string(self)
            .map(|s| s.into_bytes())
            .map_err(|e| ManifestError::Toml(e.to_string()))
    }
}

/// Verify a detached Ed25519 signature over the manifest bytes against
/// the embedded `signer_pubkey_b64`. Returns the parsed manifest on
/// success.
pub fn verify_signature(
    manifest_bytes: &[u8],
    signature_b64: &str,
) -> Result<PluginManifest, ManifestError> {
    use base64::{engine::general_purpose, Engine as _};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let manifest = PluginManifest::from_toml(manifest_bytes)?;

    let pubkey_bytes = general_purpose::STANDARD
        .decode(&manifest.signer_pubkey_b64)
        .map_err(|e| ManifestError::BadPubkey(e.to_string()))?;
    if pubkey_bytes.len() != 32 {
        return Err(ManifestError::BadPubkey(format!(
            "expected 32 bytes, got {}",
            pubkey_bytes.len()
        )));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pubkey_bytes);
    let verifying_key =
        VerifyingKey::from_bytes(&pk_arr).map_err(|e| ManifestError::BadPubkey(e.to_string()))?;

    let sig_bytes = general_purpose::STANDARD
        .decode(signature_b64.trim())
        .map_err(|e| ManifestError::BadSignature(e.to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(ManifestError::BadSignature(format!(
            "expected 64 bytes, got {}",
            sig_bytes.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify(manifest_bytes, &signature)
        .map_err(|_| ManifestError::SignatureMismatch)?;
    Ok(manifest)
}

/// Verify the manifest's `sha256` claim matches the actual bytecode.
/// Call AFTER `verify_signature` — bytecode tampering after the
/// signature is the attack signed manifests block.
pub fn verify_bytecode_sha256(
    manifest: &PluginManifest,
    bytecode: &[u8],
) -> Result<(), ManifestError> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytecode);
    let actual = hex::encode(hasher.finalize());
    if actual != manifest.sha256 {
        return Err(ManifestError::Sha256Mismatch {
            manifest: manifest.sha256.clone(),
            actual,
        });
    }
    Ok(())
}

/// Confirm the manifest's signer is in the operator's allow-list.
/// Empty `trusted` means "any signer accepted" — used for dev/test;
/// production deployments MUST seed this list via `geoctl spi trust`.
pub fn check_trusted(manifest: &PluginManifest, trusted: &[String]) -> Result<(), ManifestError> {
    if trusted.is_empty() {
        return Ok(());
    }
    if trusted.iter().any(|p| p == &manifest.signer_pubkey_b64) {
        Ok(())
    } else {
        Err(ManifestError::UntrustedSigner(
            manifest.signer_pubkey_b64.clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture_manifest(pubkey_b64: String) -> PluginManifest {
        PluginManifest {
            schema_version: 1,
            alias: "spi-twilio".into(),
            interface: "geonosis:event@0.1.0".into(),
            sha256: "0".repeat(64),
            version: "1.0.0".into(),
            signer_pubkey_b64: pubkey_b64,
            description: Some("test plugin".into()),
        }
    }

    #[test]
    fn manifest_round_trips_through_toml() {
        let m = fixture_manifest("A".repeat(44));
        let bytes = m.to_toml().unwrap();
        let back = PluginManifest::from_toml(&bytes).unwrap();
        assert_eq!(back.alias, m.alias);
        assert_eq!(back.interface, m.interface);
        assert_eq!(back.sha256, m.sha256);
        assert_eq!(back.version, m.version);
    }

    #[test]
    fn valid_signature_verifies() {
        let signing = SigningKey::generate(&mut rand_core::OsRng);
        let pk_b64 = general_purpose::STANDARD.encode(signing.verifying_key().to_bytes());
        let manifest = fixture_manifest(pk_b64);
        let bytes = manifest.to_toml().unwrap();
        let sig = signing.sign(&bytes);
        let sig_b64 = general_purpose::STANDARD.encode(sig.to_bytes());

        let parsed = verify_signature(&bytes, &sig_b64).expect("valid signature");
        assert_eq!(parsed.alias, manifest.alias);
    }

    #[test]
    fn tampered_manifest_fails_verification() {
        let signing = SigningKey::generate(&mut rand_core::OsRng);
        let pk_b64 = general_purpose::STANDARD.encode(signing.verifying_key().to_bytes());
        let manifest = fixture_manifest(pk_b64);
        let bytes = manifest.to_toml().unwrap();
        let sig = signing.sign(&bytes);
        let sig_b64 = general_purpose::STANDARD.encode(sig.to_bytes());

        // Modify the bytes after signing.
        let mut tampered = bytes.clone();
        if let Some(first) = tampered.first_mut() {
            *first = first.wrapping_add(1);
        }
        let err = verify_signature(&tampered, &sig_b64).unwrap_err();
        assert!(matches!(
            err,
            ManifestError::SignatureMismatch | ManifestError::Toml(_)
        ));
    }

    #[test]
    fn wrong_pubkey_fails_verification() {
        let signing = SigningKey::generate(&mut rand_core::OsRng);
        let wrong = SigningKey::generate(&mut rand_core::OsRng);
        let wrong_pk_b64 = general_purpose::STANDARD.encode(wrong.verifying_key().to_bytes());
        let manifest = fixture_manifest(wrong_pk_b64);
        let bytes = manifest.to_toml().unwrap();
        // Sign with the OTHER (real) key, but pubkey in manifest is wrong.
        let sig = signing.sign(&bytes);
        let sig_b64 = general_purpose::STANDARD.encode(sig.to_bytes());

        let err = verify_signature(&bytes, &sig_b64).unwrap_err();
        assert!(matches!(err, ManifestError::SignatureMismatch));
    }

    #[test]
    fn bytecode_sha256_must_match() {
        let mut m = fixture_manifest("A".repeat(44));
        let real_bytes = b"some-wasm-bytes";
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(real_bytes);
        m.sha256 = hex::encode(h.finalize());
        verify_bytecode_sha256(&m, real_bytes).unwrap();

        let tampered = b"different-bytes";
        let err = verify_bytecode_sha256(&m, tampered).unwrap_err();
        assert!(matches!(err, ManifestError::Sha256Mismatch { .. }));
    }

    #[test]
    fn trust_list_rejects_unknown_signer() {
        let m = fixture_manifest("A".repeat(44));
        let trusted = vec!["B".repeat(44)];
        let err = check_trusted(&m, &trusted).unwrap_err();
        assert!(matches!(err, ManifestError::UntrustedSigner(_)));
    }

    #[test]
    fn empty_trust_list_accepts_any_signer() {
        let m = fixture_manifest("A".repeat(44));
        assert!(check_trusted(&m, &[]).is_ok());
    }
}
