//! SAML 2.0 `<AuthnRequest>` parser.
//!
//! Per `docs/20-saml-idp.md` §"Authn request validation" v0.1
//! enforces:
//!
//! - `Issuer` matches the registered SP's `entity_id`.
//! - `Destination` matches our `/protocol/saml/sso` URL exactly.
//! - `AssertionConsumerServiceURL` is in the SP's whitelisted
//!   `acs_urls`.
//! - `IssueInstant` within ±5 min (replay window).
//! - `ID` is unique within the replay window.
//! - Signature (if SP demands it).
//!
//! This module owns the **shape extraction** — pulling the typed
//! [`ParsedAuthnRequest`] out of the wire XML. Issuer-resolution
//! against persisted SP config, replay-dedupe, and signature
//! verification all happen at the call site (the SSO handler);
//! this parser is policy-free.
//!
//! Implementation: a hand-rolled cursor over the deserialised
//! XML tree via `quick-xml`'s event reader. Real SAML
//! AuthnRequests are 300-700 bytes typical, so we trade
//! parser cleverness for verifiable correctness.

use chrono::{DateTime, Utc};
use quick_xml::events::Event;
use quick_xml::Reader;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("xml: {0}")]
    Xml(String),
    #[error("missing required attribute: {0}")]
    MissingAttr(&'static str),
    #[error("missing required element: {0}")]
    MissingElement(&'static str),
    #[error("invalid IssueInstant: {0}")]
    InvalidInstant(String),
    #[error("not an AuthnRequest")]
    NotAuthnRequest,
}

/// Parsed SAML 2.0 `<samlp:AuthnRequest>` ready for policy checks
/// at the SSO handler.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedAuthnRequest {
    pub id: String,
    pub issue_instant: DateTime<Utc>,
    pub issuer: String,
    pub destination: Option<String>,
    pub assertion_consumer_service_url: Option<String>,
    pub protocol_binding: Option<String>,
    pub force_authn: bool,
    pub is_passive: bool,
    pub name_id_policy_format: Option<String>,
}

/// Decode + parse a SAML AuthnRequest. `xml_bytes` is the
/// already-decoded XML (the caller handled base64 / DEFLATE).
pub fn parse_authn_request(xml_bytes: &[u8]) -> Result<ParsedAuthnRequest, ParseError> {
    let mut reader = Reader::from_reader(xml_bytes);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut out: Option<ParsedAuthnRequest> = None;
    let mut current_text: Option<String> = None;
    let mut in_issuer = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => return Err(ParseError::Xml(format!("at pos {}: {e}", reader.buffer_position()))),
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let qname = e.name();
                let local = local_name(qname.as_ref()).to_vec();
                let local = local.as_slice();
                if local == b"AuthnRequest" {
                    out = Some(start_authn_request(&e)?);
                } else if local == b"Issuer" {
                    in_issuer = true;
                    current_text = Some(String::new());
                } else if local == b"NameIDPolicy" {
                    if let Some(ref mut r) = out {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"Format" {
                                r.name_id_policy_format = Some(
                                    String::from_utf8_lossy(&attr.value).into_owned(),
                                );
                            }
                        }
                    }
                }
            }
            Ok(Event::Text(e)) => {
                if in_issuer {
                    if let Some(ref mut s) = current_text {
                        s.push_str(&e.unescape().map_err(|err| {
                            ParseError::Xml(format!("text decode: {err}"))
                        })?);
                    }
                }
            }
            Ok(Event::End(e)) => {
                let qname = e.name();
                if local_name(qname.as_ref()) == b"Issuer" {
                    in_issuer = false;
                    if let (Some(ref mut r), Some(text)) = (out.as_mut(), current_text.take()) {
                        r.issuer = text;
                    }
                }
            }
            _ => {}
        }
        buf.clear();
    }

    let req = out.ok_or(ParseError::NotAuthnRequest)?;
    if req.issuer.is_empty() {
        return Err(ParseError::MissingElement("Issuer"));
    }
    Ok(req)
}

fn start_authn_request(e: &quick_xml::events::BytesStart) -> Result<ParsedAuthnRequest, ParseError> {
    let mut id: Option<String> = None;
    let mut issue_instant: Option<DateTime<Utc>> = None;
    let mut destination: Option<String> = None;
    let mut acs_url: Option<String> = None;
    let mut binding: Option<String> = None;
    let mut force = false;
    let mut passive = false;
    for attr in e.attributes().flatten() {
        let key = attr.key.as_ref();
        let val = String::from_utf8_lossy(&attr.value).into_owned();
        match key {
            b"ID" => id = Some(val),
            b"IssueInstant" => {
                let parsed = DateTime::parse_from_rfc3339(&val)
                    .map_err(|e| ParseError::InvalidInstant(e.to_string()))?;
                issue_instant = Some(parsed.with_timezone(&Utc));
            }
            b"Destination" => destination = Some(val),
            b"AssertionConsumerServiceURL" => acs_url = Some(val),
            b"ProtocolBinding" => binding = Some(val),
            b"ForceAuthn" => force = val == "true" || val == "1",
            b"IsPassive" => passive = val == "true" || val == "1",
            _ => {}
        }
    }
    Ok(ParsedAuthnRequest {
        id: id.ok_or(ParseError::MissingAttr("ID"))?,
        issue_instant: issue_instant.ok_or(ParseError::MissingAttr("IssueInstant"))?,
        issuer: String::new(),
        destination,
        assertion_consumer_service_url: acs_url,
        protocol_binding: binding,
        force_authn: force,
        is_passive: passive,
        name_id_policy_format: None,
    })
}

/// Strip the `ns:` prefix from a qualified element name. SAML
/// AuthnRequests can use `samlp:` / `saml2p:` / no prefix
/// depending on the SP library; we only care about the local name.
fn local_name(name: &[u8]) -> &[u8] {
    match name.iter().position(|b| *b == b':') {
        Some(idx) => &name[idx + 1..],
        None => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_AUTHN_REQUEST: &str = r#"<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_abc123"
                    Version="2.0"
                    IssueInstant="2026-05-14T12:00:00Z"
                    Destination="https://idp.example/realms/acme/protocol/saml/sso"
                    AssertionConsumerServiceURL="https://sp.example/acs"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>https://sp.example</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>
</samlp:AuthnRequest>"#;

    #[test]
    fn parses_standard_authn_request() {
        let r = parse_authn_request(SAMPLE_AUTHN_REQUEST.as_bytes()).unwrap();
        assert_eq!(r.id, "_abc123");
        assert_eq!(r.issuer, "https://sp.example");
        assert_eq!(
            r.destination.as_deref(),
            Some("https://idp.example/realms/acme/protocol/saml/sso")
        );
        assert_eq!(
            r.assertion_consumer_service_url.as_deref(),
            Some("https://sp.example/acs")
        );
        assert_eq!(
            r.protocol_binding.as_deref(),
            Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
        );
        assert!(!r.force_authn);
        assert!(!r.is_passive);
        assert_eq!(
            r.name_id_policy_format.as_deref(),
            Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        );
    }

    #[test]
    fn rejects_missing_id() {
        let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" IssueInstant="2026-05-14T12:00:00Z"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">x</saml:Issuer></samlp:AuthnRequest>"#;
        let err = parse_authn_request(xml.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::MissingAttr("ID")));
    }

    #[test]
    fn rejects_missing_issuer() {
        let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x" Version="2.0" IssueInstant="2026-05-14T12:00:00Z"/>"#;
        let err = parse_authn_request(xml.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::MissingElement("Issuer")));
    }

    #[test]
    fn parses_force_authn_and_is_passive_flags() {
        let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x" Version="2.0" IssueInstant="2026-05-14T12:00:00Z" ForceAuthn="true" IsPassive="true"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">x</saml:Issuer></samlp:AuthnRequest>"#;
        let r = parse_authn_request(xml.as_bytes()).unwrap();
        assert!(r.force_authn);
        assert!(r.is_passive);
    }

    #[test]
    fn rejects_invalid_issue_instant() {
        let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x" Version="2.0" IssueInstant="not-a-date"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">x</saml:Issuer></samlp:AuthnRequest>"#;
        let err = parse_authn_request(xml.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidInstant(_)));
    }
}
