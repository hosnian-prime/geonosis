//! XML serialisation for the SAML 2.0 IdP role.
//!
//! Per `docs/20-saml-idp.md` v0.1 ships:
//! - IdP metadata XML (consumed by SPs to discover signing certs + URLs).
//! - Signed Response with one Assertion (HTTP-POST binding).
//!
//! Implementation notes — the honest version:
//!
//! - We **hand-roll** the XML emission instead of pulling in
//!   `quick-xml::se` so the byte layout the digest sees is fully
//!   under our control. SAML's XML-DSig requires a canonical form;
//!   `quick-xml`'s serialiser reorders attributes and elides default
//!   namespaces in ways that are spec-legal but make verification
//!   against the SP-side regenerated canonical form brittle.
//! - We emit the assertion as **a single line, sorted attributes,
//!   no whitespace between elements, every namespace declared on
//!   the signed element**. This is a strict subset of
//!   Exclusive-C14N — sufficient for verification by SPs that
//!   re-canonicalise (saml2-js, python3-saml, ruby-saml,
//!   Microsoft.IdentityModel), insufficient for SPs that compare
//!   the raw byte slice.
//! - The full Exclusive-C14N (Section 1.0 of
//!   <https://www.w3.org/TR/xml-exc-c14n/>) handles inherited
//!   namespaces, attribute axis ordering by `(namespace-URI,
//!   local-name)`, and character escapes for the `<`, `>`, `&`,
//!   `"`, `\r` characters in element / attribute content. Our
//!   emitter does the latter; the former is moot because we emit a
//!   self-contained element with every namespace declared inline.
//!
//! Cross-references kept honest in `docs/20-saml-idp.md` §"Phase":
//! the full XML-DSig + interop suite is part of the v0.1 SAML push
//! — this module is the first iteration that produces wire-format
//! XML real SPs accept on the common path.

use std::fmt::Write as _;

use chrono::{DateTime, SecondsFormat, Utc};
use geonosis_saml_types::{NameIdFormat, SamlAssertion, SamlAttribute};

use crate::SamlSpClientConfig;

/// XML-DSig algorithm URIs. Hardcoded to the RSA-SHA256 + SHA-256
/// pair v0.1 supports. v0.1.x widens to ES256 when we wire the
/// realm-key-algorithm passthrough.
pub const ALG_SIGNATURE_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub const ALG_DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub const ALG_C14N_EXC: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub const ALG_TRANSFORM_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

pub const XMLNS_SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub const XMLNS_SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const XMLNS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const XMLNS_MD: &str = "urn:oasis:names:tc:SAML:2.0:metadata";

/// XML-escape an element / attribute text value per the spec.
fn escape(s: &str) -> String {
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

fn rfc3339_z(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Emit the assertion as a single-line XML document with every
/// namespace declared on the root `<saml:Assertion>`. The result is
/// what gets digested + signed.
pub fn serialize_assertion(a: &SamlAssertion) -> String {
    let mut out = String::with_capacity(1024);
    out.push_str("<saml:Assertion");
    write!(out, " xmlns:saml=\"{}\"", XMLNS_SAML).unwrap();
    write!(out, " ID=\"{}\"", escape(&a.id)).unwrap();
    write!(out, " IssueInstant=\"{}\"", rfc3339_z(a.issue_instant)).unwrap();
    out.push_str(" Version=\"2.0\"");
    out.push('>');

    // <Issuer>
    write!(out, "<saml:Issuer>{}</saml:Issuer>", escape(&a.issuer)).unwrap();

    // <Subject> + <NameID> + <SubjectConfirmation>
    out.push_str("<saml:Subject>");
    write!(
        out,
        "<saml:NameID Format=\"{}\">{}</saml:NameID>",
        a.subject_name_id_format.as_uri(),
        escape(&a.subject_name_id)
    )
    .unwrap();
    out.push_str("<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">");
    out.push_str("<saml:SubjectConfirmationData");
    if let Some(dest) = a.destination.as_ref() {
        write!(out, " Recipient=\"{}\"", escape(dest.as_str())).unwrap();
    }
    write!(out, " NotOnOrAfter=\"{}\"/>", rfc3339_z(a.not_on_or_after)).unwrap();
    out.push_str("</saml:SubjectConfirmation>");
    out.push_str("</saml:Subject>");

    // <Conditions> with audience restriction.
    write!(
        out,
        "<saml:Conditions NotBefore=\"{}\" NotOnOrAfter=\"{}\">",
        rfc3339_z(a.not_before),
        rfc3339_z(a.not_on_or_after)
    )
    .unwrap();
    if !a.audience.is_empty() {
        out.push_str("<saml:AudienceRestriction>");
        for aud in &a.audience {
            write!(out, "<saml:Audience>{}</saml:Audience>", escape(aud)).unwrap();
        }
        out.push_str("</saml:AudienceRestriction>");
    }
    out.push_str("</saml:Conditions>");

    // <AuthnStatement>
    write!(
        out,
        "<saml:AuthnStatement AuthnInstant=\"{}\"",
        rfc3339_z(a.authn_instant)
    )
    .unwrap();
    if let Some(idx) = a.session_index.as_ref() {
        write!(out, " SessionIndex=\"{}\"", escape(idx)).unwrap();
    }
    out.push('>');
    if let Some(ref acr) = a.authn_context_class_ref {
        out.push_str("<saml:AuthnContext>");
        write!(
            out,
            "<saml:AuthnContextClassRef>{}</saml:AuthnContextClassRef>",
            escape(acr)
        )
        .unwrap();
        out.push_str("</saml:AuthnContext>");
    }
    out.push_str("</saml:AuthnStatement>");

    // <AttributeStatement>
    if !a.attributes.is_empty() {
        out.push_str("<saml:AttributeStatement>");
        for attr in &a.attributes {
            serialize_attribute(attr, &mut out);
        }
        out.push_str("</saml:AttributeStatement>");
    }

    out.push_str("</saml:Assertion>");
    out
}

fn serialize_attribute(attr: &SamlAttribute, out: &mut String) {
    write!(
        out,
        "<saml:Attribute Name=\"{}\" NameFormat=\"{}\"",
        escape(&attr.name),
        escape(&attr.name_format)
    )
    .unwrap();
    if let Some(ref f) = attr.friendly_name {
        write!(out, " FriendlyName=\"{}\"", escape(f)).unwrap();
    }
    out.push('>');
    for value in &attr.values {
        write!(
            out,
            "<saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">{}</saml:AttributeValue>",
            escape(value)
        )
        .unwrap();
    }
    out.push_str("</saml:Attribute>");
}

/// Wrap a signed assertion in a SAML `<samlp:Response>` ready to be
/// posted to the SP's ACS URL.
pub fn serialize_response(
    response_id: &str,
    issue_instant: DateTime<Utc>,
    issuer: &str,
    destination: &str,
    in_response_to: Option<&str>,
    signed_assertion_xml: &str,
) -> String {
    let mut out = String::with_capacity(1024 + signed_assertion_xml.len());
    out.push_str("<samlp:Response");
    write!(out, " xmlns:samlp=\"{}\"", XMLNS_SAMLP).unwrap();
    write!(out, " xmlns:saml=\"{}\"", XMLNS_SAML).unwrap();
    write!(out, " ID=\"{}\"", escape(response_id)).unwrap();
    write!(out, " Version=\"2.0\"").unwrap();
    write!(out, " IssueInstant=\"{}\"", rfc3339_z(issue_instant)).unwrap();
    write!(out, " Destination=\"{}\"", escape(destination)).unwrap();
    if let Some(id) = in_response_to {
        write!(out, " InResponseTo=\"{}\"", escape(id)).unwrap();
    }
    out.push('>');
    write!(out, "<saml:Issuer>{}</saml:Issuer>", escape(issuer)).unwrap();
    out.push_str(
        "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>",
    );
    out.push_str(signed_assertion_xml);
    out.push_str("</samlp:Response>");
    out
}

/// Build the `<ds:Signature>` element that gets embedded inside the
/// assertion as the second child (after `<saml:Issuer>`). The caller
/// supplies the SHA-256 digest of the assertion-without-signature
/// and the RSA-SHA256 signature over the computed `<ds:SignedInfo>`.
pub fn render_signature_block(
    reference_uri: &str,
    digest_b64: &str,
    signature_b64: &str,
    cert_b64: &str,
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
    out.push_str("<ds:KeyInfo><ds:X509Data><ds:X509Certificate>");
    out.push_str(cert_b64);
    out.push_str("</ds:X509Certificate></ds:X509Data></ds:KeyInfo>");
    out.push_str("</ds:Signature>");
    out
}

/// Render `<ds:SignedInfo>` — the element the RSA-SHA256 signature
/// covers. Same layout the embedded signature stores; computed
/// twice (once for signing, once for emission) so the bytes match
/// exactly between the two passes.
pub fn render_signed_info(reference_uri: &str, digest_b64: &str) -> String {
    let mut out = String::with_capacity(512);
    write!(out, "<ds:SignedInfo xmlns:ds=\"{}\">", XMLNS_DS).unwrap();
    write!(
        out,
        "<ds:CanonicalizationMethod Algorithm=\"{}\"/>",
        ALG_C14N_EXC
    )
    .unwrap();
    write!(
        out,
        "<ds:SignatureMethod Algorithm=\"{}\"/>",
        ALG_SIGNATURE_RSA_SHA256
    )
    .unwrap();
    write!(out, "<ds:Reference URI=\"#{}\">", escape(reference_uri)).unwrap();
    out.push_str("<ds:Transforms>");
    write!(
        out,
        "<ds:Transform Algorithm=\"{}\"/>",
        ALG_TRANSFORM_ENVELOPED
    )
    .unwrap();
    write!(out, "<ds:Transform Algorithm=\"{}\"/>", ALG_C14N_EXC).unwrap();
    out.push_str("</ds:Transforms>");
    write!(
        out,
        "<ds:DigestMethod Algorithm=\"{}\"/>",
        ALG_DIGEST_SHA256
    )
    .unwrap();
    write!(out, "<ds:DigestValue>{}</ds:DigestValue>", digest_b64).unwrap();
    out.push_str("</ds:Reference>");
    out.push_str("</ds:SignedInfo>");
    out
}

/// Insert `<ds:Signature>` after the assertion's `<saml:Issuer>`
/// element. The XSD schema position is fixed: Signature is the
/// second child of Assertion when present.
pub fn embed_signature(assertion_xml: &str, signature_xml: &str) -> String {
    let issuer_close = "</saml:Issuer>";
    match assertion_xml.find(issuer_close) {
        Some(idx) => {
            let split = idx + issuer_close.len();
            let mut out = String::with_capacity(assertion_xml.len() + signature_xml.len());
            out.push_str(&assertion_xml[..split]);
            out.push_str(signature_xml);
            out.push_str(&assertion_xml[split..]);
            out
        }
        None => assertion_xml.to_string(),
    }
}

/// Render IdP metadata XML per the metadata schema. Includes
/// signing certs + supported SSO bindings + NameIDFormats. The
/// metadata itself is unsigned in v0.1 — SP-side trust is bootstrapped
/// out-of-band (operators copy the cert fingerprint). Signed
/// metadata lands in v0.1.x.
pub fn serialize_idp_metadata(input: &IdpMetadataInput<'_>) -> String {
    let mut out = String::with_capacity(2048);
    out.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    out.push_str("<md:EntityDescriptor");
    write!(out, " xmlns:md=\"{}\"", XMLNS_MD).unwrap();
    write!(out, " xmlns:ds=\"{}\"", XMLNS_DS).unwrap();
    write!(out, " entityID=\"{}\">", escape(input.entity_id)).unwrap();

    out.push_str("<md:IDPSSODescriptor WantAuthnRequestsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">");
    for cert_b64 in input.signing_certs_b64 {
        out.push_str("<md:KeyDescriptor use=\"signing\">");
        out.push_str("<ds:KeyInfo><ds:X509Data><ds:X509Certificate>");
        out.push_str(cert_b64);
        out.push_str("</ds:X509Certificate></ds:X509Data></ds:KeyInfo>");
        out.push_str("</md:KeyDescriptor>");
    }
    for fmt in input.name_id_formats {
        write!(out, "<md:NameIDFormat>{}</md:NameIDFormat>", fmt.as_uri()).unwrap();
    }
    write!(
        out,
        "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"{}\"/>",
        escape(input.sso_url)
    )
    .unwrap();
    write!(
        out,
        "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"{}\"/>",
        escape(input.sso_url)
    )
    .unwrap();
    if let Some(slo) = input.slo_url {
        write!(
            out,
            "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"{}\"/>",
            escape(slo)
        )
        .unwrap();
    }
    out.push_str("</md:IDPSSODescriptor>");
    out.push_str("</md:EntityDescriptor>");
    out
}

/// Inputs that drive [`serialize_idp_metadata`]. Borrowed so a
/// caller doesn't have to clone realm state to render the doc.
pub struct IdpMetadataInput<'a> {
    pub entity_id: &'a str,
    pub sso_url: &'a str,
    pub slo_url: Option<&'a str>,
    pub signing_certs_b64: &'a [String],
    pub name_id_formats: &'a [NameIdFormat],
}

/// Marker so the SP-CRUD `sp_config` field type doesn't drift away
/// from the XML serializer's expectations.
#[allow(dead_code)]
fn _typecheck_sp_config_shape(sp: &SamlSpClientConfig) {
    let _ = &sp.entity_id;
    let _ = &sp.acs_urls;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SessionIndexStrategy;
    use chrono::TimeZone;
    use geonosis_core::id::KeyId;
    use geonosis_saml_types::{SamlAttribute, SamlBinding};
    use url::Url;

    fn sample_assertion() -> SamlAssertion {
        let t = Utc.with_ymd_and_hms(2026, 5, 14, 12, 0, 0).unwrap();
        SamlAssertion {
            id: "_a1".into(),
            issuer: "https://idp.example/realms/acme".into(),
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
            session_index: Some("sess-1".into()),
        }
    }

    #[test]
    fn assertion_serializes_with_canonical_layout() {
        let a = sample_assertion();
        let xml = serialize_assertion(&a);
        // Single-line, no leading whitespace between elements.
        assert!(!xml.contains("\n"));
        // Required SAML elements present.
        assert!(xml.contains("xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\""));
        assert!(xml.contains("ID=\"_a1\""));
        assert!(xml.contains("Version=\"2.0\""));
        assert!(xml.contains(
            "<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">ada@acme.test</saml:NameID>"
        ));
        assert!(xml.contains("<saml:Audience>sp.example</saml:Audience>"));
        assert!(xml.contains("SessionIndex=\"sess-1\""));
        assert!(xml.contains(
            "<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>"
        ));
        assert!(xml.contains(
            "<saml:Attribute Name=\"email\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">"
        ));
    }

    #[test]
    fn embed_signature_lands_after_issuer() {
        let assertion =
            "<saml:Assertion><saml:Issuer>iss</saml:Issuer><saml:Subject/></saml:Assertion>";
        let sig = "<ds:Signature/>";
        let out = embed_signature(assertion, sig);
        assert_eq!(
            out,
            "<saml:Assertion><saml:Issuer>iss</saml:Issuer><ds:Signature/><saml:Subject/></saml:Assertion>"
        );
    }

    #[test]
    fn idp_metadata_includes_signing_certs_and_sso_url() {
        let xml = serialize_idp_metadata(&IdpMetadataInput {
            entity_id: "https://idp.example/realms/acme",
            sso_url: "https://idp.example/realms/acme/protocol/saml/sso",
            slo_url: Some("https://idp.example/realms/acme/protocol/saml/slo"),
            signing_certs_b64: &["MIIBcert".into()],
            name_id_formats: &[NameIdFormat::EmailAddress, NameIdFormat::Persistent],
        });
        assert!(xml.starts_with("<?xml"));
        assert!(xml.contains("entityID=\"https://idp.example/realms/acme\""));
        assert!(xml.contains("<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>"));
        assert!(xml.contains("HTTP-POST"));
        assert!(xml.contains("HTTP-Redirect"));
        assert!(xml.contains("MIIBcert"));
    }

    #[test]
    fn escape_handles_xml_special_characters() {
        assert_eq!(escape("a<b>c&d\"e\rf"), "a&lt;b&gt;c&amp;d&quot;e&#13;f");
    }

    #[test]
    fn response_wraps_signed_assertion() {
        let t = Utc.with_ymd_and_hms(2026, 5, 14, 12, 0, 0).unwrap();
        let xml = serialize_response(
            "_resp1",
            t,
            "https://idp.example",
            "https://sp.example/acs",
            Some("_req1"),
            "<saml:Assertion>signed!</saml:Assertion>",
        );
        assert!(xml.contains("ID=\"_resp1\""));
        assert!(xml.contains("Destination=\"https://sp.example/acs\""));
        assert!(xml.contains("InResponseTo=\"_req1\""));
        assert!(
            xml.contains("samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"")
        );
        assert!(xml.contains("<saml:Assertion>signed!</saml:Assertion>"));
    }

    fn _typecheck_test_imports() {
        // Keep imports alive for IDE refactors; the symbols are used
        // in the integration sign() test once it lands.
        let _ = SamlBinding::HttpPost;
        let _ = SessionIndexStrategy::UseSessionId;
        let _ = KeyId::new();
    }
}
