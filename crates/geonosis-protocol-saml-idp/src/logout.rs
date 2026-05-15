//! SAML 2.0 `<LogoutRequest>` + `<LogoutResponse>` per the SLO
//! profile (docs/20-saml-idp.md §SLO).
//!
//! v0.1 ships:
//! - SP-initiated front-channel logout (SP POSTs LogoutRequest → we
//!   revoke the realm session + return LogoutResponse).
//! - LogoutResponse XML serialiser with a signed-by-IdP variant for
//!   SPs that require signed responses.
//!
//! v0.1 does NOT yet propagate the logout to other SPs the user was
//! logged into during the session — multi-SP fan-out (front-channel
//! iframe and back-channel POST) lands in v0.1.x alongside the
//! per-SP session-participation tracking.

use chrono::{DateTime, SecondsFormat, Utc};
use quick_xml::events::Event;
use quick_xml::Reader;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LogoutParseError {
    #[error("xml: {0}")]
    Xml(String),
    #[error("missing required attribute: {0}")]
    MissingAttr(&'static str),
    #[error("missing required element: {0}")]
    MissingElement(&'static str),
    #[error("not a LogoutRequest")]
    NotLogoutRequest,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedLogoutRequest {
    pub id: String,
    pub issue_instant: DateTime<Utc>,
    pub issuer: String,
    pub destination: Option<String>,
    pub name_id: Option<String>,
    pub session_index: Option<String>,
}

pub fn parse_logout_request(xml_bytes: &[u8]) -> Result<ParsedLogoutRequest, LogoutParseError> {
    let mut reader = Reader::from_reader(xml_bytes);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut out: Option<ParsedLogoutRequest> = None;
    let mut current: Option<String> = None;
    let mut in_issuer = false;
    let mut in_name_id = false;
    let mut in_session_index = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => {
                return Err(LogoutParseError::Xml(format!(
                    "at pos {}: {e}",
                    reader.buffer_position()
                )))
            }
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let qname = e.name();
                let local = local_name(qname.as_ref()).to_vec();
                let local = local.as_slice();
                if local == b"LogoutRequest" {
                    out = Some(start_logout_request(&e)?);
                } else if local == b"Issuer" {
                    in_issuer = true;
                    current = Some(String::new());
                } else if local == b"NameID" {
                    in_name_id = true;
                    current = Some(String::new());
                } else if local == b"SessionIndex" {
                    in_session_index = true;
                    current = Some(String::new());
                }
            }
            Ok(Event::Text(e)) if in_issuer || in_name_id || in_session_index => {
                if let Some(ref mut s) = current {
                    s.push_str(
                        &e.unescape()
                            .map_err(|err| LogoutParseError::Xml(format!("text decode: {err}")))?,
                    );
                }
            }
            Ok(Event::End(e)) => {
                let qname = e.name();
                let local = local_name(qname.as_ref()).to_vec();
                let local = local.as_slice();
                if local == b"Issuer" {
                    in_issuer = false;
                    if let (Some(ref mut r), Some(t)) = (out.as_mut(), current.take()) {
                        r.issuer = t;
                    }
                } else if local == b"NameID" {
                    in_name_id = false;
                    if let (Some(ref mut r), Some(t)) = (out.as_mut(), current.take()) {
                        r.name_id = Some(t);
                    }
                } else if local == b"SessionIndex" {
                    in_session_index = false;
                    if let (Some(ref mut r), Some(t)) = (out.as_mut(), current.take()) {
                        r.session_index = Some(t);
                    }
                }
            }
            _ => {}
        }
        buf.clear();
    }

    let req = out.ok_or(LogoutParseError::NotLogoutRequest)?;
    if req.issuer.is_empty() {
        return Err(LogoutParseError::MissingElement("Issuer"));
    }
    Ok(req)
}

fn start_logout_request(
    e: &quick_xml::events::BytesStart,
) -> Result<ParsedLogoutRequest, LogoutParseError> {
    let mut id: Option<String> = None;
    let mut issue_instant: Option<DateTime<Utc>> = None;
    let mut destination: Option<String> = None;
    for attr in e.attributes().flatten() {
        let key = attr.key.as_ref();
        let val = String::from_utf8_lossy(&attr.value).into_owned();
        match key {
            b"ID" => id = Some(val),
            b"IssueInstant" => {
                let parsed = DateTime::parse_from_rfc3339(&val)
                    .map_err(|e| LogoutParseError::Xml(format!("IssueInstant: {e}")))?;
                issue_instant = Some(parsed.with_timezone(&Utc));
            }
            b"Destination" => destination = Some(val),
            _ => {}
        }
    }
    Ok(ParsedLogoutRequest {
        id: id.ok_or(LogoutParseError::MissingAttr("ID"))?,
        issue_instant: issue_instant.ok_or(LogoutParseError::MissingAttr("IssueInstant"))?,
        issuer: String::new(),
        destination,
        name_id: None,
        session_index: None,
    })
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\r' => out.push_str("&#13;"),
            _ => out.push(c),
        }
    }
    out
}

fn local_name(name: &[u8]) -> &[u8] {
    match name.iter().position(|b| *b == b':') {
        Some(idx) => &name[idx + 1..],
        None => name,
    }
}

/// Serialise a SAML 2.0 `<LogoutResponse>` in the same canonical
/// layout the assertion serializer uses. Status = Success.
pub fn serialize_logout_response(
    response_id: &str,
    issue_instant: DateTime<Utc>,
    issuer: &str,
    destination: &str,
    in_response_to: &str,
) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(512);
    out.push_str("<samlp:LogoutResponse");
    write!(out, " xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"").unwrap();
    write!(out, " xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"").unwrap();
    write!(out, " ID=\"{}\"", xml_escape(response_id)).unwrap();
    write!(out, " Version=\"2.0\"").unwrap();
    write!(
        out,
        " IssueInstant=\"{}\"",
        issue_instant.to_rfc3339_opts(SecondsFormat::Millis, true)
    )
    .unwrap();
    write!(out, " Destination=\"{}\"", xml_escape(destination)).unwrap();
    write!(out, " InResponseTo=\"{}\">", xml_escape(in_response_to)).unwrap();
    write!(out, "<saml:Issuer>{}</saml:Issuer>", xml_escape(issuer)).unwrap();
    out.push_str("<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>");
    out.push_str("</samlp:LogoutResponse>");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_LOGOUT: &str = r#"<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                     ID="_logout1"
                     Version="2.0"
                     IssueInstant="2026-05-14T12:00:00Z"
                     Destination="https://idp.example/realms/acme/protocol/saml/slo">
  <saml:Issuer>https://sp.example</saml:Issuer>
  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">ada@acme.test</saml:NameID>
  <samlp:SessionIndex>session-1</samlp:SessionIndex>
</samlp:LogoutRequest>"#;

    #[test]
    fn parses_logout_request_with_name_id_and_session_index() {
        let r = parse_logout_request(SAMPLE_LOGOUT.as_bytes()).unwrap();
        assert_eq!(r.id, "_logout1");
        assert_eq!(r.issuer, "https://sp.example");
        assert_eq!(r.name_id.as_deref(), Some("ada@acme.test"));
        assert_eq!(r.session_index.as_deref(), Some("session-1"));
        assert_eq!(
            r.destination.as_deref(),
            Some("https://idp.example/realms/acme/protocol/saml/slo")
        );
    }

    #[test]
    fn rejects_logout_missing_issuer() {
        let xml = r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x" Version="2.0" IssueInstant="2026-05-14T12:00:00Z"/>"#;
        let err = parse_logout_request(xml.as_bytes()).unwrap_err();
        assert!(matches!(err, LogoutParseError::MissingElement("Issuer")));
    }

    #[test]
    fn logout_response_carries_issuer_destination_and_status() {
        let t = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 5, 14, 12, 0, 0).unwrap();
        let xml = serialize_logout_response(
            "_r1",
            t,
            "https://idp.example",
            "https://sp.example/slo",
            "_logout1",
        );
        assert!(xml.contains("ID=\"_r1\""));
        assert!(xml.contains("InResponseTo=\"_logout1\""));
        assert!(xml.contains("Destination=\"https://sp.example/slo\""));
        assert!(
            xml.contains("samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"")
        );
        assert!(xml.contains("<saml:Issuer>https://idp.example</saml:Issuer>"));
    }
}
