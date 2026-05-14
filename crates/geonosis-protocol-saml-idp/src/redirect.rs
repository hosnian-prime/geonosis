//! HTTP-Redirect binding decoder for `SAMLRequest` / `SAMLResponse`.
//!
//! Per SAML 2.0 Bindings §3.4.4: the Redirect-binding payload is
//! `RAW DEFLATE` (RFC 1951, no zlib header) + base64 (NOT URL-
//! safe) + URL-encoded. The handler chain is:
//!
//! ```text
//! query string `SAMLRequest=...` → url-decoded by axum::extract::Query
//!                                → base64-decoded here
//!                                → DEFLATE-decompressed here
//!                                → raw XML for the parser
//! ```
//!
//! The POST binding (already wired in `handlers::saml`) skips the
//! DEFLATE step — the payload is base64'd XML directly.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use flate2::read::DeflateDecoder;
use std::io::Read as _;
use thiserror::Error;

/// XML-DSig algorithm URI for RSA-SHA256. The only inbound
/// signature algorithm v0.1.x verifies for the Redirect binding.
pub const REDIRECT_SIG_ALG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

#[derive(Debug, Error)]
pub enum RedirectDecodeError {
    #[error("base64: {0}")]
    Base64(String),
    #[error("deflate: {0}")]
    Deflate(String),
    #[error("decoded XML exceeded the {limit}-byte cap")]
    TooLarge { limit: usize },
}

#[derive(Debug, Error)]
pub enum RedirectSigError {
    #[error("missing Signature query parameter")]
    MissingSignature,
    #[error("missing SigAlg query parameter")]
    MissingSigAlg,
    #[error("unsupported SigAlg: {0}")]
    UnsupportedAlg(String),
    #[error("signature decode: {0}")]
    DecodeSignature(String),
    #[error("no SP cert verified the signature")]
    NoMatch,
    #[error("cert load: {0}")]
    CertLoad(String),
}

/// Inputs to [`verify_redirect_signature`] — the literal,
/// URL-decoded query parameters the SP signed. Per
/// SAML 2.0 Bindings §3.4.4.1 the signed bytes are
/// `SAMLRequest=...&RelayState=...&SigAlg=...` joined by `&` with
/// each value URL-encoded **exactly as it appeared on the wire**.
/// Callers SHOULD preserve the raw query string slice rather than
/// re-encoding after axum decodes it.
pub struct RedirectSignatureCheck<'a> {
    /// The URL-encoded `SAMLRequest=...` segment (with its `=`).
    pub saml_request_pair: &'a str,
    /// The URL-encoded `RelayState=...` segment, if a RelayState
    /// was supplied; `None` when the SP didn't send one.
    pub relay_state_pair: Option<&'a str>,
    /// The URL-encoded `SigAlg=...` segment.
    pub sig_alg_pair: &'a str,
    /// `Signature` query value (base64-encoded).
    pub signature_b64: &'a str,
    /// `SigAlg` query value (alg URI).
    pub sig_alg: &'a str,
}

/// Verify a Redirect-binding signature against the SP's signing
/// certs. Returns Ok on the first matching cert; bubbles
/// `RedirectSigError::NoMatch` if none verifies. v0.1.x supports
/// `rsa-sha256` only; other algorithms are rejected with a clear
/// `UnsupportedAlg` error so SPs configured for SHA-1 fail
/// loudly instead of silently passing.
pub fn verify_redirect_signature(
    check: &RedirectSignatureCheck<'_>,
    cert_pems: &[String],
) -> Result<(), RedirectSigError> {
    if check.signature_b64.is_empty() {
        return Err(RedirectSigError::MissingSignature);
    }
    if check.sig_alg.is_empty() {
        return Err(RedirectSigError::MissingSigAlg);
    }
    if check.sig_alg != REDIRECT_SIG_ALG_RSA_SHA256 {
        return Err(RedirectSigError::UnsupportedAlg(check.sig_alg.into()));
    }
    let sig_bytes = B64
        .decode(check.signature_b64.as_bytes())
        .map_err(|e| RedirectSigError::DecodeSignature(e.to_string()))?;

    // Reconstruct the signed bytes per the spec: SAMLRequest=...
    // (& RelayState=...)? & SigAlg=...
    let mut signed = String::new();
    signed.push_str(check.saml_request_pair);
    if let Some(rs) = check.relay_state_pair {
        signed.push('&');
        signed.push_str(rs);
    }
    signed.push('&');
    signed.push_str(check.sig_alg_pair);

    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::sha2::Sha256;
    use rsa::signature::Verifier;

    let signed_bytes = signed.as_bytes();
    for pem in cert_pems {
        let pk = load_rsa_public_from_cert_pem(pem)
            .map_err(|e| RedirectSigError::CertLoad(e.to_string()))?;
        let vk = VerifyingKey::<Sha256>::new(pk);
        let sig = match Signature::try_from(sig_bytes.as_slice()) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if vk.verify(signed_bytes, &sig).is_ok() {
            return Ok(());
        }
    }
    Err(RedirectSigError::NoMatch)
}

/// Load an RSA public key from a PEM-encoded X.509 cert (with or
/// without the `-----BEGIN CERTIFICATE-----` headers).
fn load_rsa_public_from_cert_pem(pem: &str) -> Result<rsa::RsaPublicKey, String> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs8::DecodePublicKey;

    let trimmed = pem.trim();
    let body: String = trimmed
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>()
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let bytes = B64
        .decode(body.as_bytes())
        .map_err(|e| format!("base64: {e}"))?;
    if trimmed.contains("BEGIN CERTIFICATE") {
        let (_, cert) =
            x509_parser::parse_x509_certificate(&bytes).map_err(|e| format!("x509: {e}"))?;
        let spki_der = cert.public_key().raw;
        if let Ok(k) = rsa::RsaPublicKey::from_public_key_der(spki_der) {
            return Ok(k);
        }
        rsa::RsaPublicKey::from_pkcs1_der(&cert.public_key().subject_public_key.data)
            .map_err(|e| format!("rsa public: {e}"))
    } else {
        rsa::RsaPublicKey::from_public_key_der(&bytes).map_err(|e| format!("spki: {e}"))
    }
}

/// Decode a `SAMLRequest` (or `SAMLResponse`) supplied via the
/// HTTP-Redirect binding. `decompressed_cap` bounds the inflated
/// payload to a sane size (SAML AuthnRequests are 300–700 bytes
/// typical; the cap defeats a DEFLATE-bomb input from a hostile
/// SP).
pub fn decode_redirect_payload(
    b64: &str,
    decompressed_cap: usize,
) -> Result<Vec<u8>, RedirectDecodeError> {
    let compressed = B64
        .decode(b64.as_bytes())
        .map_err(|e| RedirectDecodeError::Base64(e.to_string()))?;
    let mut dec = DeflateDecoder::new(compressed.as_slice());
    // Allocate up-front so the read loop stops at the cap without
    // letting the inflater grow without bound.
    let mut out = Vec::with_capacity(compressed.len().saturating_mul(4));
    let mut buf = [0u8; 4096];
    loop {
        let n = dec
            .read(&mut buf)
            .map_err(|e| RedirectDecodeError::Deflate(e.to_string()))?;
        if n == 0 {
            break;
        }
        if out.len() + n > decompressed_cap {
            return Err(RedirectDecodeError::TooLarge {
                limit: decompressed_cap,
            });
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write as _;

    fn encode(xml: &str) -> String {
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(xml.as_bytes()).unwrap();
        let compressed = enc.finish().unwrap();
        B64.encode(&compressed)
    }

    #[test]
    fn round_trips_a_typical_authn_request() {
        let xml = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_x\" Version=\"2.0\" IssueInstant=\"2026-05-14T12:00:00Z\"/>";
        let encoded = encode(xml);
        let decoded = decode_redirect_payload(&encoded, 64 * 1024).unwrap();
        assert_eq!(decoded, xml.as_bytes());
    }

    #[test]
    fn rejects_non_base64_input() {
        let err = decode_redirect_payload("not-base64!!!", 64 * 1024).unwrap_err();
        assert!(matches!(err, RedirectDecodeError::Base64(_)));
    }

    #[test]
    fn rejects_invalid_deflate_stream() {
        // Valid base64 of bytes that aren't a DEFLATE stream.
        let bogus = B64.encode(b"hello world");
        let err = decode_redirect_payload(&bogus, 64 * 1024).unwrap_err();
        assert!(matches!(err, RedirectDecodeError::Deflate(_)));
    }

    #[test]
    fn enforces_decompressed_cap_against_zip_bomb() {
        // Highly-compressible 1 MiB payload encodes to a few hundred
        // bytes. A 1 KiB cap forces the TooLarge error.
        let big = "A".repeat(1024 * 1024);
        let encoded = encode(&big);
        let err = decode_redirect_payload(&encoded, 1024).unwrap_err();
        assert!(matches!(err, RedirectDecodeError::TooLarge { limit: 1024 }));
    }

    #[test]
    fn verify_redirect_signature_rejects_unsupported_alg() {
        let check = RedirectSignatureCheck {
            saml_request_pair: "SAMLRequest=foo",
            relay_state_pair: None,
            sig_alg_pair: "SigAlg=sha1",
            signature_b64: "AAAA",
            sig_alg: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        };
        let err = verify_redirect_signature(&check, &[]).unwrap_err();
        assert!(matches!(err, RedirectSigError::UnsupportedAlg(_)));
    }

    #[test]
    fn verify_redirect_signature_rejects_missing_signature() {
        let check = RedirectSignatureCheck {
            saml_request_pair: "SAMLRequest=foo",
            relay_state_pair: None,
            sig_alg_pair: "SigAlg=x",
            signature_b64: "",
            sig_alg: REDIRECT_SIG_ALG_RSA_SHA256,
        };
        let err = verify_redirect_signature(&check, &[]).unwrap_err();
        assert!(matches!(err, RedirectSigError::MissingSignature));
    }

    #[test]
    fn verify_redirect_signature_rejects_missing_sigalg() {
        let check = RedirectSignatureCheck {
            saml_request_pair: "SAMLRequest=foo",
            relay_state_pair: None,
            sig_alg_pair: "SigAlg=",
            signature_b64: "AAAA",
            sig_alg: "",
        };
        let err = verify_redirect_signature(&check, &[]).unwrap_err();
        assert!(matches!(err, RedirectSigError::MissingSigAlg));
    }

    #[test]
    fn verify_redirect_signature_bubbles_no_match_with_empty_cert_list() {
        let check = RedirectSignatureCheck {
            saml_request_pair: "SAMLRequest=foo",
            relay_state_pair: None,
            sig_alg_pair: "SigAlg=x",
            signature_b64: &B64.encode(b"sig"),
            sig_alg: REDIRECT_SIG_ALG_RSA_SHA256,
        };
        let err = verify_redirect_signature(&check, &[]).unwrap_err();
        assert!(matches!(err, RedirectSigError::NoMatch));
    }
}
