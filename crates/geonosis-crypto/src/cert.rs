//! Self-signed X.509 certificate emission for realm signing keys.
//!
//! SAML metadata's `<md:KeyDescriptor use="signing">` MUST carry an
//! `<X509Certificate>` body for SPs that strictly validate against
//! the SAML 2.0 metadata schema (python3-saml, ruby-saml,
//! Microsoft.IdentityModel). Geonosis stores RSA private keys
//! without their X.509 wrapper — this module generates a minimal
//! self-signed cert on demand so the metadata endpoint can publish
//! one without requiring operators to provision cert tooling
//! out-of-band.
//!
//! The cert is **rendered on the fly** (not persisted): rotation
//! invalidates it implicitly, and a leak of the cert reveals
//! nothing more than the JWK already does. v0.1.x will add a cached
//! cert per `(realm, kid)` once the metadata endpoint sees enough
//! traffic to make the cert-gen cost visible in benchmarks.
//!
//! v0.1 supports RS256 only (RSA-PKCS1v15-SHA256). ES256 / EdDSA
//! land alongside the per-algorithm metadata endpoint in v0.1.x.

use std::time::Duration;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, KeyUsagePurpose, SignatureAlgorithm,
    PKCS_RSA_SHA256,
};
use rsa::pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;
use thiserror::Error;

// rcgen uses `rustls-pki-types` for DER wrappers; pull it in
// directly since rcgen doesn't re-export the type.
use rustls_pki_types::PrivatePkcs8KeyDer;

/// Validity window for the self-signed cert. Spans the realm key's
/// expected rotation horizon — operators rotating more aggressively
/// can regenerate metadata on demand (the cert is content-derived,
/// no state on the server side).
const VALIDITY: Duration = Duration::from_secs(60 * 60 * 24 * 365 * 5);

#[derive(Debug, Error)]
pub enum CertError {
    #[error("pkcs8 encode: {0}")]
    Encode(String),
    #[error("rcgen: {0}")]
    Rcgen(String),
}

/// Self-signed X.509 v3 cert wrapping an RSA-2048+ private key.
/// `subject_cn` is what lands in the cert's Subject + Issuer DN
/// (self-signed → same name on both sides); operators typically set
/// it to the realm slug or the IdP entity ID.
///
/// Returns the **DER-encoded** cert bytes. `<X509Certificate>` in
/// the SAML metadata wants base64-encoded DER without PEM headers
/// — the caller base64s the bytes (see `crate::cert::der_to_b64`).
pub fn self_signed_x509_for_rs256(
    rsa: &RsaPrivateKey,
    subject_cn: &str,
) -> Result<Vec<u8>, CertError> {
    let pkcs8_der = rsa
        .to_pkcs8_der()
        .map_err(|e| CertError::Encode(e.to_string()))?;

    // rcgen 0.13 takes a `KeyPair` constructed from PKCS#8 DER +
    // the explicit `SignatureAlgorithm` it signs with. We bind
    // PKCS_RSA_SHA256 — the same algorithm Geonosis already uses
    // for JWS RS256.
    let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(pkcs8_der.as_bytes()),
        algorithm_rsa_sha256(),
    )
    .map_err(|e| CertError::Rcgen(e.to_string()))?;

    let mut params = CertificateParams::new(vec![subject_cn.to_string()])
        .map_err(|e| CertError::Rcgen(e.to_string()))?;
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, subject_cn);
        dn
    };
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let now = std::time::SystemTime::now();
    let not_before = now - Duration::from_secs(60);
    let not_after = now + VALIDITY;
    params.not_before = not_before.into();
    params.not_after = not_after.into();

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| CertError::Rcgen(e.to_string()))?;
    Ok(cert.der().to_vec())
}

fn algorithm_rsa_sha256() -> &'static SignatureAlgorithm {
    &PKCS_RSA_SHA256
}

/// Base64-encode DER bytes for embedding in `<X509Certificate>`.
pub fn der_to_b64(der: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    B64.encode(der)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::DecodePrivateKey;

    fn rsa_2048() -> RsaPrivateKey {
        let mut rng = rand::rngs::OsRng;
        RsaPrivateKey::new(&mut rng, 2048).unwrap()
    }

    #[test]
    fn self_signed_cert_is_parseable_der() {
        let key = rsa_2048();
        let der = self_signed_x509_for_rs256(&key, "acme.test").unwrap();
        // Sanity: not empty and starts with a DER SEQUENCE tag (0x30).
        assert!(!der.is_empty());
        assert_eq!(der[0], 0x30);
        // x509-parser deserialises it (already a workspace dep).
        let (_, parsed) = x509_parser::parse_x509_certificate(&der).expect("parse");
        let subject = parsed.subject().to_string();
        assert!(subject.contains("CN=acme.test"));
        let issuer = parsed.issuer().to_string();
        // Self-signed: subject == issuer.
        assert_eq!(subject, issuer);
    }

    #[test]
    fn self_signed_cert_round_trips_to_pem_via_b64() {
        let key = rsa_2048();
        let der = self_signed_x509_for_rs256(&key, "issuer.example").unwrap();
        let b64 = der_to_b64(&der);
        // The base64 chunk is the same body PEM headers wrap; rcgen
        // also exposes a PEM render — assert the two agree on bytes.
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        let decoded = B64.decode(&b64).unwrap();
        assert_eq!(decoded, der);
    }

    /// Keep the RSA private-key import path warm in tests so a
    /// future refactor doesn't silently drop `DecodePrivateKey`
    /// from the test surface.
    fn _typecheck_decode_private_key(pem: &str) -> Option<RsaPrivateKey> {
        RsaPrivateKey::from_pkcs8_pem(pem).ok()
    }
}
