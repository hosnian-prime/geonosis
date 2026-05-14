//! XML-DSig signing of a SAML assertion.
//!
//! v0.1 supports the RSA-SHA256 + SHA-256 algorithm pair only;
//! ES256 / EdDSA land alongside the per-realm-algorithm metadata
//! endpoint in v0.1.x. The signature shape per the W3C XMLDSig
//! recommendation
//! (<https://www.w3.org/TR/xmldsig-core1/>):
//!
//! 1. Canonicalise the assertion-without-signature element →
//!    `digest_b64 = base64(SHA-256(canonical_assertion))`.
//! 2. Construct `<ds:SignedInfo>` referencing the assertion by
//!    `URI="#<assertion.id>"` with that `DigestValue`.
//! 3. Canonicalise the `<ds:SignedInfo>` →
//!    `signature_b64 = base64(RSA-SHA256(canonical_signed_info))`.
//! 4. Emit `<ds:Signature>` with `<ds:SignatureValue>` carrying the
//!    base64 signature and `<ds:KeyInfo>` carrying the signing
//!    cert (the caller supplies the cert; v0.1 ships RSAKeyValue
//!    when no cert is available — see `KeyInfoMaterial` below).
//! 5. Embed `<ds:Signature>` as the second child of
//!    `<saml:Assertion>` (right after `<saml:Issuer>`).
//!
//! Canonicalisation here is the **single-line, sorted-attributes,
//! namespaces-on-the-root** subset of Exclusive-C14N — see
//! `xml.rs` for the matching emit-side discipline. Real SPs that
//! re-canonicalise the wire bytes (saml2-js, Microsoft.IdentityModel)
//! verify the signature; ones that compare byte-for-byte against the
//! exact emit-side canonicalisation may need the full Exc-C14N
//! implementation v0.1.x lands.

use std::fmt::Write as _;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use geonosis_core::id::{KeyId, RealmId};
use geonosis_core::JwsAlgorithm;
use geonosis_crypto::KeyManagementService;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::xml::{embed_signature, render_signature_block, render_signed_info, XMLNS_DS};

#[derive(Debug, Error)]
pub enum SignError {
    #[error("kms: {0}")]
    Kms(String),
    #[error("input lacks <saml:Assertion> shell with embeddable position")]
    Shape,
}

/// `<ds:KeyInfo>` payload variants.
///
/// `X509Certificate` is the SAML-canonical form — most SP libraries
/// (python3-saml, ruby-saml, .NET) require it. `RSAKeyValue` is the
/// spec-compliant alternative for IdPs that don't ship X.509 certs;
/// modern SP libraries (saml2-js, Microsoft.IdentityModel) accept
/// it. v0.1 lets the caller pick so operators with cert tooling can
/// use the canonical form and the rest aren't blocked.
pub enum KeyInfoMaterial {
    /// Base64-encoded DER X.509 certificate body (no PEM headers).
    X509Certificate { cert_b64: String },
    /// RSA modulus + exponent in big-endian unsigned bytes, base64'd.
    RsaKeyValue {
        modulus_b64: String,
        exponent_b64: String,
    },
}

impl KeyInfoMaterial {
    fn render(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push_str("<ds:KeyInfo>");
        match self {
            KeyInfoMaterial::X509Certificate { cert_b64 } => {
                out.push_str("<ds:X509Data><ds:X509Certificate>");
                out.push_str(cert_b64);
                out.push_str("</ds:X509Certificate></ds:X509Data>");
            }
            KeyInfoMaterial::RsaKeyValue {
                modulus_b64,
                exponent_b64,
            } => {
                out.push_str("<ds:KeyValue><ds:RSAKeyValue>");
                write!(out, "<ds:Modulus>{}</ds:Modulus>", modulus_b64).unwrap();
                write!(out, "<ds:Exponent>{}</ds:Exponent>", exponent_b64).unwrap();
                out.push_str("</ds:RSAKeyValue></ds:KeyValue>");
            }
        }
        out.push_str("</ds:KeyInfo>");
        out
    }
}

/// Sign `assertion_xml` (produced by [`crate::xml::serialize_assertion`])
/// against the realm's active RSA-SHA256 key. Returns the
/// assertion XML with `<ds:Signature>` embedded.
///
/// `reference_uri` MUST be the assertion's `ID` value (without the
/// leading `#`); the signer wraps it in the `URI="#..."` form.
pub async fn sign_assertion<K>(
    kms: &K,
    realm: RealmId,
    kid: &KeyId,
    reference_uri: &str,
    assertion_xml: &str,
    key_info: KeyInfoMaterial,
) -> Result<String, SignError>
where
    K: KeyManagementService + ?Sized,
{
    // 1. Compute the assertion digest. The Enveloped-Signature
    //    transform says: hash the assertion with the (not-yet-present)
    //    ds:Signature element removed. Since we sign before
    //    embedding, the input is the assertion-without-signature
    //    bytes verbatim.
    let mut hasher = Sha256::new();
    hasher.update(assertion_xml.as_bytes());
    let assertion_digest = hasher.finalize();
    let digest_b64 = B64.encode(assertion_digest);

    // 2. Build <ds:SignedInfo> with the digest. Same renderer the
    //    embedded signature will use, so emit-side bytes match.
    let signed_info = render_signed_info(reference_uri, &digest_b64);

    // 3. Sign the SignedInfo bytes with RSA-SHA256. The KMS hashes
    //    internally (PKCS#1 v1.5 with the SHA-256 OID).
    let signature = kms
        .sign(realm, kid, JwsAlgorithm::RS256, signed_info.as_bytes())
        .await
        .map_err(|e| SignError::Kms(e.to_string()))?;
    let signature_b64 = B64.encode(signature);

    // 4. Render the <ds:Signature> block.
    let key_info_xml = key_info.render();
    let signature_xml =
        render_signature_with_key_info(reference_uri, &digest_b64, &signature_b64, &key_info_xml);

    // 5. Embed it after <saml:Issuer>.
    Ok(embed_signature(assertion_xml, &signature_xml))
}

/// Same shape [`render_signature_block`] produces, but with a
/// caller-rendered `<ds:KeyInfo>` payload (handles the X.509 vs
/// RSAKeyValue split).
fn render_signature_with_key_info(
    reference_uri: &str,
    digest_b64: &str,
    signature_b64: &str,
    key_info_xml: &str,
) -> String {
    let signed_info = render_signed_info(reference_uri, digest_b64);
    let mut out = String::with_capacity(2048);
    write!(out, "<ds:Signature xmlns:ds=\"{}\">", XMLNS_DS).unwrap();
    out.push_str(&signed_info);
    write!(
        out,
        "<ds:SignatureValue>{}</ds:SignatureValue>",
        signature_b64
    )
    .unwrap();
    out.push_str(key_info_xml);
    out.push_str("</ds:Signature>");
    out
}

// `render_signature_block` is the X.509-only shortcut still used by
// older call sites + tests.
#[allow(dead_code)]
fn _shortcut_signature_block_kept(
    reference_uri: &str,
    digest_b64: &str,
    signature_b64: &str,
    cert_b64: &str,
) -> String {
    render_signature_block(reference_uri, digest_b64, signature_b64, cert_b64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::serialize_assertion;
    use async_trait::async_trait;
    use chrono::TimeZone;
    use geonosis_core::id::{KeyId, RealmId};
    use geonosis_core::JwsAlgorithm;
    use geonosis_crypto::jwt::{PrivateMaterial, PublicMaterial};
    use geonosis_crypto::{Jwk, JwkSet, KeyManagementService, KmsError, WrappedSecret};
    use geonosis_saml_types::{NameIdFormat, SamlAssertion, SamlAttribute};
    use parking_lot::Mutex;
    use url::Url;
    use zeroize::Zeroizing;

    /// Minimal `KeyManagementService` for the signing tests — owns
    /// one in-memory RSA key, exposes `sign(_, _, RS256, data)` and
    /// nothing else. Keeps the SAML signing tests self-contained
    /// (no master-key + KeyMaterial dance required just to drive
    /// RSA-SHA256).
    struct TestKms {
        key: Mutex<rsa::RsaPrivateKey>,
    }

    impl TestKms {
        fn new() -> Self {
            let mut rng = rand::rngs::OsRng;
            let key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
            Self {
                key: Mutex::new(key),
            }
        }
    }

    #[async_trait]
    impl KeyManagementService for TestKms {
        async fn sign(
            &self,
            _realm: RealmId,
            _kid: &KeyId,
            algo: JwsAlgorithm,
            data: &[u8],
        ) -> Result<Vec<u8>, KmsError> {
            assert!(matches!(algo, JwsAlgorithm::RS256));
            use rsa::pkcs1v15::SigningKey;
            use rsa::sha2::Sha256;
            use rsa::signature::{RandomizedSigner, SignatureEncoding};
            let key = self.key.lock().clone();
            let sk = SigningKey::<Sha256>::new(key);
            let mut rng = rand::rngs::OsRng;
            let sig = sk.sign_with_rng(&mut rng, data);
            Ok(sig.to_bytes().to_vec())
        }
        async fn unwrap(&self, _wrapped: &WrappedSecret) -> Result<Zeroizing<Vec<u8>>, KmsError> {
            unimplemented!()
        }
        async fn jwk(&self, _kid: &KeyId) -> Result<Jwk, KmsError> {
            unimplemented!()
        }
        async fn jwks(&self, _realm: RealmId) -> Result<JwkSet, KmsError> {
            unimplemented!()
        }
        async fn active_signing_kid(
            &self,
            _realm: RealmId,
            _algo: JwsAlgorithm,
        ) -> Result<KeyId, KmsError> {
            unimplemented!()
        }
        async fn load_private(&self, _kid: &KeyId) -> Result<PrivateMaterial, KmsError> {
            unimplemented!()
        }
        async fn load_public(&self, _kid: &KeyId) -> Result<PublicMaterial, KmsError> {
            unimplemented!()
        }
    }

    fn sample_assertion() -> SamlAssertion {
        let t = chrono::Utc.with_ymd_and_hms(2026, 5, 14, 12, 0, 0).unwrap();
        SamlAssertion {
            id: "_a1".into(),
            issuer: "https://idp.example".into(),
            subject_name_id: "ada@acme.test".into(),
            subject_name_id_format: NameIdFormat::EmailAddress,
            audience: vec!["sp.example".into()],
            issue_instant: t,
            not_before: t - chrono::Duration::seconds(30),
            not_on_or_after: t + chrono::Duration::minutes(5),
            destination: Some(Url::parse("https://sp.example/acs").unwrap()),
            attributes: vec![SamlAttribute {
                name: "email".into(),
                name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri".into(),
                friendly_name: None,
                values: vec!["ada@acme.test".into()],
            }],
            authn_context_class_ref: Some("urn:oasis:names:tc:SAML:2.0:ac:classes:Password".into()),
            authn_instant: t,
            session_index: Some("s1".into()),
        }
    }

    fn rsa_kms() -> (TestKms, RealmId, KeyId) {
        (TestKms::new(), RealmId::new(), KeyId::new())
    }

    #[tokio::test]
    async fn sign_assertion_embeds_signature_with_value() {
        let (kms, realm, kid) = rsa_kms();
        let a = sample_assertion();
        let unsigned = serialize_assertion(&a);
        let signed = sign_assertion(
            &kms,
            realm,
            &kid,
            &a.id,
            &unsigned,
            KeyInfoMaterial::RsaKeyValue {
                modulus_b64: "MIIBcert-modulus".into(),
                exponent_b64: "AQAB".into(),
            },
        )
        .await
        .expect("sign");
        assert!(signed.contains("<ds:Signature"));
        assert!(signed.contains("<ds:SignatureValue>"));
        assert!(signed.contains("<ds:DigestValue>"));
        // The signature MUST land after </saml:Issuer> and before
        // <saml:Subject> — schema position rule.
        let issuer_close = signed.find("</saml:Issuer>").unwrap();
        let subject_open = signed.find("<saml:Subject>").unwrap();
        let sig_open = signed.find("<ds:Signature").unwrap();
        assert!(issuer_close < sig_open);
        assert!(sig_open < subject_open);
    }

    #[tokio::test]
    async fn signed_info_reference_uri_carries_assertion_id_with_hash() {
        let (kms, realm, kid) = rsa_kms();
        let a = sample_assertion();
        let unsigned = serialize_assertion(&a);
        let signed = sign_assertion(
            &kms,
            realm,
            &kid,
            &a.id,
            &unsigned,
            KeyInfoMaterial::RsaKeyValue {
                modulus_b64: "m".into(),
                exponent_b64: "e".into(),
            },
        )
        .await
        .unwrap();
        // Reference URI must be `#<assertion-id>`.
        assert!(signed.contains("URI=\"#_a1\""));
    }

    #[test]
    fn key_info_material_renders_x509_block() {
        let x = KeyInfoMaterial::X509Certificate {
            cert_b64: "MIIBcert".into(),
        };
        let xml = x.render();
        assert!(xml.starts_with("<ds:KeyInfo>"));
        assert!(xml.contains("<ds:X509Certificate>MIIBcert</ds:X509Certificate>"));
    }

    #[test]
    fn key_info_material_renders_rsa_key_value_block() {
        let r = KeyInfoMaterial::RsaKeyValue {
            modulus_b64: "Z29uZW0=".into(),
            exponent_b64: "AQAB".into(),
        };
        let xml = r.render();
        assert!(xml.contains("<ds:RSAKeyValue>"));
        assert!(xml.contains("<ds:Modulus>Z29uZW0=</ds:Modulus>"));
        assert!(xml.contains("<ds:Exponent>AQAB</ds:Exponent>"));
    }
}
