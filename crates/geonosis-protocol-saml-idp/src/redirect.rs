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

#[derive(Debug, Error)]
pub enum RedirectDecodeError {
    #[error("base64: {0}")]
    Base64(String),
    #[error("deflate: {0}")]
    Deflate(String),
    #[error("decoded XML exceeded the {limit}-byte cap")]
    TooLarge { limit: usize },
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
}
