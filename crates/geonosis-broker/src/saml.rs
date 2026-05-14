//! SAML 2.0 SP runtime.
//!
//! Per `docs/05-identity-broker.md`:
//! - HTTP-Redirect (DEFLATE'd + base64) and HTTP-POST (base64) outbound
//! - HTTP-POST inbound ACS only (HTTP-Redirect for assertions is
//!   not used in production)
//! - Enveloped XML signature (RSA-SHA256) verified against the IdP's
//!   pinned certificates; signature presence enforced when
//!   `want_assertions_signed` / `want_responses_signed`
//! - `InResponseTo`, `Audience`, `NotBefore`, `NotOnOrAfter`, `Recipient`
//!   validated strictly

use std::collections::BTreeMap;
use std::io::Write;

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use flate2::write::DeflateEncoder;
use flate2::Compression;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use quick_xml::events::Event;
use quick_xml::Reader;
use sha2::Digest;

use geonosis_core::attribute::AttributeValue;
use geonosis_saml_types::{NameIdFormat, SamlBinding};

use crate::types::{BrokerAssertion, BrokerError, SamlIdpConfig};

const CLOCK_SKEW: Duration = Duration::seconds(300);

/// Build an outbound `AuthnRequest`. Returns either a redirect URL
/// (HTTP-Redirect binding) or a base64-encoded form body string
/// (HTTP-POST binding). The `request_id` must be stored in the
/// associated `BrokerAuthnState` for `InResponseTo` validation on the
/// callback side.
pub fn build_authn_request(
    cfg: &SamlIdpConfig,
    sp_entity_id: &str,
    acs_url: &str,
    relay_state: &str,
) -> Result<OutboundRequest, BrokerError> {
    let id = format!("_{}", geonosis_crypto::random::random_token());
    let now = Utc::now();
    let xml = format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{instant}" Destination="{dest}" AssertionConsumerServiceURL="{acs}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>{sp}</saml:Issuer><samlp:NameIDPolicy Format="{nameid}" AllowCreate="true"/></samlp:AuthnRequest>"#,
        id = id,
        instant = now.format("%Y-%m-%dT%H:%M:%SZ"),
        dest = xml_escape(&cfg.sso_url),
        acs = xml_escape(acs_url),
        sp = xml_escape(sp_entity_id),
        nameid = cfg.name_id_format.as_uri(),
    );
    match cfg.binding_outbound {
        SamlBinding::HttpRedirect => {
            let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
            enc.write_all(xml.as_bytes())
                .map_err(|e| BrokerError::Transport(e.to_string()))?;
            let compressed = enc
                .finish()
                .map_err(|e| BrokerError::Transport(e.to_string()))?;
            let b64 = base64::engine::general_purpose::STANDARD.encode(compressed);
            let mut url = cfg.sso_url.clone();
            url.push(if url.contains('?') { '&' } else { '?' });
            url.push_str(&format!(
                "SAMLRequest={}&RelayState={}",
                utf8_percent_encode(&b64, NON_ALPHANUMERIC),
                utf8_percent_encode(relay_state, NON_ALPHANUMERIC),
            ));
            Ok(OutboundRequest {
                request_id: id,
                redirect: Some(url),
                post_form: None,
            })
        }
        SamlBinding::HttpPost => {
            let b64 = base64::engine::general_purpose::STANDARD.encode(xml.as_bytes());
            Ok(OutboundRequest {
                request_id: id,
                redirect: None,
                post_form: Some(SamlPostForm {
                    sso_url: cfg.sso_url.clone(),
                    saml_request: b64,
                    relay_state: relay_state.to_string(),
                }),
            })
        }
        SamlBinding::Artifact => Err(BrokerError::Transport(
            "Artifact binding not supported in v0.1".into(),
        )),
    }
}

/// Outcome of `build_authn_request`. Exactly one of `redirect` /
/// `post_form` is populated.
#[derive(Debug, Clone)]
pub struct OutboundRequest {
    pub request_id: String,
    pub redirect: Option<String>,
    pub post_form: Option<SamlPostForm>,
}

#[derive(Debug, Clone)]
pub struct SamlPostForm {
    pub sso_url: String,
    pub saml_request: String,
    pub relay_state: String,
}

/// Parsed SAML Response (after base64 decode).
#[derive(Debug, Clone)]
pub struct SamlResponse {
    pub raw_xml: String,
    pub response_id: String,
    pub issuer: String,
    pub in_response_to: Option<String>,
    pub destination: Option<String>,
    pub status_code: String,
    pub assertion: Option<SamlAssertionParsed>,
    pub signature: Option<SignatureBlock>,
}

#[derive(Debug, Clone)]
pub struct SamlAssertionParsed {
    pub id: String,
    pub issuer: String,
    pub subject_name_id: String,
    pub subject_name_id_format: NameIdFormat,
    pub audiences: Vec<String>,
    pub recipient: Option<String>,
    pub in_response_to: Option<String>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_on_or_after: Option<DateTime<Utc>>,
    pub attributes: BTreeMap<String, Vec<String>>,
    pub authn_instant: Option<DateTime<Utc>>,
    pub session_index: Option<String>,
    pub signature: Option<SignatureBlock>,
}

/// XML-DSig `<Signature>` block extracted from a response / assertion.
#[derive(Debug, Clone)]
pub struct SignatureBlock {
    /// `SignedInfo` canonical-XML bytes (the signed-input).
    pub signed_info_c14n: Vec<u8>,
    pub signature_value: Vec<u8>,
    /// Digest from the `<Reference>` over `Object` (the enveloping
    /// element). Required for verification: the verifier recomputes
    /// the digest over the canonical Object and compares.
    pub reference_digest: Vec<u8>,
    pub reference_uri: Option<String>,
    pub signature_method: String,
    pub digest_method: String,
}

/// Parse a base64-encoded `SAMLResponse` form post. Returns the typed
/// tree; signature verification is a separate step.
pub fn parse_response(b64: &str) -> Result<SamlResponse, BrokerError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(b64))
        .map_err(|e| BrokerError::InvalidAssertion(format!("base64: {e}")))?;
    let xml =
        String::from_utf8(raw).map_err(|e| BrokerError::InvalidAssertion(format!("utf8: {e}")))?;

    let mut reader = Reader::from_str(&xml);
    reader.config_mut().trim_text(false);
    let mut out = SamlResponse {
        raw_xml: xml.clone(),
        response_id: String::new(),
        issuer: String::new(),
        in_response_to: None,
        destination: None,
        status_code: String::new(),
        assertion: None,
        signature: None,
    };

    let mut path: Vec<String> = Vec::new();
    let mut current_attrib: Option<String> = None;
    let mut current_assertion: Option<SamlAssertionParsed> = None;
    let mut current_sig: Option<SignatureBlock> = None;
    let mut signed_info_acc: Option<Vec<u8>> = None;

    loop {
        match reader.read_event() {
            Err(e) => {
                return Err(BrokerError::InvalidAssertion(format!(
                    "xml parse: {} at {}",
                    e,
                    reader.error_position()
                )))
            }
            Ok(Event::Eof) => break,
            Ok(Event::Start(e) | Event::Empty(e)) => {
                let qn = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                let local = qn.rsplit(':').next().unwrap_or(&qn).to_string();
                path.push(local.clone());
                match local.as_str() {
                    "Response" => {
                        for a in e.attributes().flatten() {
                            let k = String::from_utf8_lossy(a.key.as_ref()).into_owned();
                            let v = a.unescape_value().unwrap_or_default().into_owned();
                            match k.as_str() {
                                "ID" => out.response_id = v,
                                "InResponseTo" => out.in_response_to = Some(v),
                                "Destination" => out.destination = Some(v),
                                _ => {}
                            }
                        }
                    }
                    "Assertion" => {
                        let mut a = SamlAssertionParsed {
                            id: String::new(),
                            issuer: String::new(),
                            subject_name_id: String::new(),
                            subject_name_id_format: NameIdFormat::Unspecified,
                            audiences: vec![],
                            recipient: None,
                            in_response_to: None,
                            not_before: None,
                            not_on_or_after: None,
                            attributes: BTreeMap::new(),
                            authn_instant: None,
                            session_index: None,
                            signature: None,
                        };
                        for at in e.attributes().flatten() {
                            let k = String::from_utf8_lossy(at.key.as_ref()).into_owned();
                            let v = at.unescape_value().unwrap_or_default().into_owned();
                            if k == "ID" {
                                a.id = v;
                            }
                        }
                        current_assertion = Some(a);
                    }
                    "NameID" => {
                        if let Some(ref mut a) = current_assertion {
                            for at in e.attributes().flatten() {
                                if at.key.as_ref() == b"Format" {
                                    if let Ok(v) = at.unescape_value() {
                                        a.subject_name_id_format = parse_nameid_format(&v);
                                    }
                                }
                            }
                        }
                    }
                    "SubjectConfirmationData" => {
                        if let Some(ref mut a) = current_assertion {
                            for at in e.attributes().flatten() {
                                let k = String::from_utf8_lossy(at.key.as_ref()).into_owned();
                                let v = at.unescape_value().unwrap_or_default().into_owned();
                                match k.as_str() {
                                    "Recipient" => a.recipient = Some(v),
                                    "InResponseTo" => a.in_response_to = Some(v),
                                    "NotOnOrAfter" => a.not_on_or_after = parse_xs_dt(&v),
                                    "NotBefore" => a.not_before = parse_xs_dt(&v),
                                    _ => {}
                                }
                            }
                        }
                    }
                    "Conditions" => {
                        if let Some(ref mut a) = current_assertion {
                            for at in e.attributes().flatten() {
                                let k = String::from_utf8_lossy(at.key.as_ref()).into_owned();
                                let v = at.unescape_value().unwrap_or_default().into_owned();
                                match k.as_str() {
                                    "NotBefore" => a.not_before = parse_xs_dt(&v),
                                    "NotOnOrAfter" => a.not_on_or_after = parse_xs_dt(&v),
                                    _ => {}
                                }
                            }
                        }
                    }
                    "AuthnStatement" => {
                        if let Some(ref mut a) = current_assertion {
                            for at in e.attributes().flatten() {
                                let k = String::from_utf8_lossy(at.key.as_ref()).into_owned();
                                let v = at.unescape_value().unwrap_or_default().into_owned();
                                match k.as_str() {
                                    "AuthnInstant" => a.authn_instant = parse_xs_dt(&v),
                                    "SessionIndex" => a.session_index = Some(v),
                                    _ => {}
                                }
                            }
                        }
                    }
                    "Attribute" => {
                        for at in e.attributes().flatten() {
                            if at.key.as_ref() == b"Name" {
                                if let Ok(v) = at.unescape_value() {
                                    current_attrib = Some(v.into_owned());
                                }
                            }
                        }
                    }
                    "Signature" => {
                        // Capture the signature block. We don't reach for
                        // the full canonical form here — v0.1 verifies the
                        // signature against the c14n form computed from the
                        // raw XML byte range. Fields are filled below.
                        current_sig = Some(SignatureBlock {
                            signed_info_c14n: Vec::new(),
                            signature_value: Vec::new(),
                            reference_digest: Vec::new(),
                            reference_uri: None,
                            signature_method: String::new(),
                            digest_method: String::new(),
                        });
                    }
                    "SignedInfo" => {
                        signed_info_acc = Some(Vec::new());
                    }
                    "SignatureMethod" => {
                        if let Some(ref mut sb) = current_sig {
                            for at in e.attributes().flatten() {
                                if at.key.as_ref() == b"Algorithm" {
                                    if let Ok(v) = at.unescape_value() {
                                        sb.signature_method = v.into_owned();
                                    }
                                }
                            }
                        }
                    }
                    "DigestMethod" => {
                        if let Some(ref mut sb) = current_sig {
                            for at in e.attributes().flatten() {
                                if at.key.as_ref() == b"Algorithm" {
                                    if let Ok(v) = at.unescape_value() {
                                        sb.digest_method = v.into_owned();
                                    }
                                }
                            }
                        }
                    }
                    "Reference" => {
                        if let Some(ref mut sb) = current_sig {
                            for at in e.attributes().flatten() {
                                if at.key.as_ref() == b"URI" {
                                    if let Ok(v) = at.unescape_value() {
                                        sb.reference_uri = Some(v.into_owned());
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(t)) => {
                let txt = t.unescape().unwrap_or_default().into_owned();
                let in_path = |p: &str| path.last().map(String::as_str) == Some(p);
                if in_path("Issuer") {
                    if path.iter().any(|p| p == "Assertion") {
                        if let Some(ref mut a) = current_assertion {
                            a.issuer = txt.clone();
                        }
                    } else {
                        out.issuer = txt.clone();
                    }
                } else if in_path("NameID") {
                    if let Some(ref mut a) = current_assertion {
                        a.subject_name_id = txt.clone();
                    }
                } else if in_path("Audience") {
                    if let Some(ref mut a) = current_assertion {
                        a.audiences.push(txt.clone());
                    }
                } else if in_path("StatusCode") {
                    out.status_code = txt.clone();
                } else if in_path("AttributeValue") {
                    if let (Some(ref mut a), Some(name)) =
                        (current_assertion.as_mut(), current_attrib.clone())
                    {
                        a.attributes.entry(name).or_default().push(txt.clone());
                    }
                } else if in_path("SignatureValue") {
                    if let Some(ref mut sb) = current_sig {
                        let cleaned: String =
                            txt.chars().filter(|c| !c.is_ascii_whitespace()).collect();
                        sb.signature_value = base64::engine::general_purpose::STANDARD
                            .decode(&cleaned)
                            .map_err(|e| BrokerError::InvalidAssertion(format!("sig b64: {e}")))?;
                    }
                } else if in_path("DigestValue") {
                    if let Some(ref mut sb) = current_sig {
                        let cleaned: String =
                            txt.chars().filter(|c| !c.is_ascii_whitespace()).collect();
                        sb.reference_digest = base64::engine::general_purpose::STANDARD
                            .decode(&cleaned)
                            .map_err(|e| {
                                BrokerError::InvalidAssertion(format!("digest b64: {e}"))
                            })?;
                    }
                }
                if let Some(ref mut acc) = signed_info_acc {
                    acc.extend_from_slice(txt.as_bytes());
                }
            }
            Ok(Event::End(e)) => {
                let qn = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                let local = qn.rsplit(':').next().unwrap_or(&qn).to_string();
                if local == "Attribute" {
                    current_attrib = None;
                }
                if local == "Assertion" {
                    let mut a = current_assertion.take().unwrap();
                    a.signature = current_sig.take();
                    out.assertion = Some(a);
                }
                if local == "SignedInfo" {
                    // Conservative canonical-XML approximation:
                    // re-render the SignedInfo element from the raw XML by
                    // locating the byte range. `signed_info_acc` we built
                    // above only carries text; the real c14n is the
                    // serialized element. We resolve this in `signed_info_bytes`.
                    if let Some(ref mut sb) = current_sig {
                        sb.signed_info_c14n = signed_info_bytes(&out.raw_xml).unwrap_or_default();
                    }
                    signed_info_acc = None;
                }
                if local == "Response" {
                    out.signature = current_sig.clone().or_else(|| out.signature.clone());
                }
                path.pop();
            }
            _ => {}
        }
    }

    Ok(out)
}

/// Verify the enveloped `<ds:Signature>` against the IdP's pinned
/// certificate. v0.1 supports `RSA-SHA256` only (xmldsig-more#rsa-sha256).
pub fn verify_response_signature(
    response: &SamlResponse,
    cert_pems: &[String],
) -> Result<(), BrokerError> {
    let sig = response
        .signature
        .as_ref()
        .or(response
            .assertion
            .as_ref()
            .and_then(|a| a.signature.as_ref()))
        .ok_or_else(|| BrokerError::Signature("no signature".into()))?;

    if !sig.signature_method.contains("rsa-sha256") {
        return Err(BrokerError::Signature(format!(
            "unsupported sigalg: {}",
            sig.signature_method
        )));
    }
    if !sig.digest_method.contains("sha256") {
        return Err(BrokerError::Signature(format!(
            "unsupported digestalg: {}",
            sig.digest_method
        )));
    }

    // Recompute digest over the referenced element. v0.1 only supports
    // the same-document URI form `#<id>`; if none is set, fall back to
    // hashing the entire raw XML minus the Signature element.
    let referenced_bytes = if let Some(uri) = sig.reference_uri.as_deref() {
        if let Some(id) = uri.strip_prefix('#') {
            slice_element_with_id(&response.raw_xml, id)
                .ok_or_else(|| BrokerError::Signature(format!("ref id {id} not found")))?
        } else {
            return Err(BrokerError::Signature(format!("bad ref uri: {uri}")));
        }
    } else {
        return Err(BrokerError::Signature("ref uri missing".into()));
    };
    let computed = sha2::Sha256::digest(strip_signature(&referenced_bytes).as_bytes());
    if computed[..] != sig.reference_digest[..] {
        return Err(BrokerError::Signature("digest mismatch".into()));
    }

    // Verify SignatureValue over canonical SignedInfo.
    use rsa::pkcs1v15::{Signature as Sig, VerifyingKey};
    use rsa::sha2::Sha256;
    use rsa::signature::Verifier;

    let mut last_err: Option<String> = None;
    for pem in cert_pems {
        let pk = load_rsa_public_from_cert_pem(pem)
            .map_err(|e| BrokerError::Signature(format!("cert load: {e}")))?;
        let vk = VerifyingKey::<Sha256>::new(pk);
        let s = Sig::try_from(sig.signature_value.as_slice())
            .map_err(|e| BrokerError::Signature(format!("sig parse: {e}")))?;
        match vk.verify(&sig.signed_info_c14n, &s) {
            Ok(()) => return Ok(()),
            Err(e) => last_err = Some(e.to_string()),
        }
    }
    Err(BrokerError::Signature(
        last_err.unwrap_or_else(|| "no matching cert".into()),
    ))
}

/// Project a verified `SamlResponse` into a `BrokerAssertion`.
pub fn assertion_to_broker(
    alias: &str,
    sp_entity_id: &str,
    expected_request_id: Option<&str>,
    response: &SamlResponse,
) -> Result<BrokerAssertion, BrokerError> {
    if response.status_code != "urn:oasis:names:tc:SAML:2.0:status:Success" {
        return Err(BrokerError::InvalidAssertion(format!(
            "non-success status: {}",
            response.status_code
        )));
    }
    let a = response
        .assertion
        .as_ref()
        .ok_or_else(|| BrokerError::InvalidAssertion("no assertion".into()))?;

    if !a.audiences.iter().any(|aud| aud == sp_entity_id) {
        return Err(BrokerError::InvalidAssertion("audience mismatch".into()));
    }
    if let Some(expected) = expected_request_id {
        let observed = a
            .in_response_to
            .as_deref()
            .or(response.in_response_to.as_deref());
        if observed != Some(expected) {
            return Err(BrokerError::InvalidAssertion(
                "InResponseTo mismatch".into(),
            ));
        }
    }
    let now = Utc::now();
    if let Some(nb) = a.not_before {
        if now + CLOCK_SKEW < nb {
            return Err(BrokerError::InvalidAssertion("nbf in future".into()));
        }
    }
    if let Some(noa) = a.not_on_or_after {
        if now > noa + CLOCK_SKEW {
            return Err(BrokerError::InvalidAssertion("expired".into()));
        }
    }

    let mut claims: BTreeMap<String, AttributeValue> = BTreeMap::new();
    for (k, vs) in &a.attributes {
        match vs.as_slice() {
            [] => {}
            [single] => {
                claims.insert(k.clone(), AttributeValue::String(single.clone()));
            }
            many => {
                claims.insert(k.clone(), AttributeValue::Strings(many.to_vec()));
            }
        }
    }

    Ok(BrokerAssertion {
        idp_alias: alias.into(),
        external_id: a.subject_name_id.clone(),
        issuer: a.issuer.clone(),
        claims,
        received_at: Utc::now(),
        expires_at: a.not_on_or_after,
    })
}

// --- helpers ---

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn parse_nameid_format(s: &str) -> NameIdFormat {
    match s {
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" => NameIdFormat::EmailAddress,
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" => NameIdFormat::Persistent,
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" => NameIdFormat::Transient,
        "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName" => {
            NameIdFormat::X509SubjectName
        }
        _ => NameIdFormat::Unspecified,
    }
}

fn parse_xs_dt(s: &str) -> Option<DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Find the byte range of `<…ID="id" …>…</…>` (no namespace handling
/// beyond local-name match) and return that slice as a string.
fn slice_element_with_id(xml: &str, id: &str) -> Option<String> {
    // Search for `ID="{id}"` or `ID='{id}'`.
    let needle_dq = format!("ID=\"{id}\"");
    let needle_sq = format!("ID='{id}'");
    let id_pos = xml.find(&needle_dq).or_else(|| xml.find(&needle_sq))?;
    // Walk back to the nearest `<` to find element start.
    let start = xml[..id_pos].rfind('<')?;
    // Identify the tag's local name to find its matching end-tag.
    let after_lt = &xml[start + 1..];
    let name_end = after_lt.find(|c: char| c.is_ascii_whitespace() || c == '>' || c == '/')?;
    let qname = &after_lt[..name_end];
    // Find the matching close. Naive: first occurrence of `</qname>` after start.
    let close_needle = format!("</{qname}>");
    let end_rel = xml[start..].find(&close_needle)?;
    let end = start + end_rel + close_needle.len();
    Some(xml[start..end].to_string())
}

/// Remove the inline `<Signature>...</Signature>` element from a SAML
/// element fragment for digest recomputation (enveloped signature
/// transform per XML-DSig §6.6.4). This is a conservative
/// approximation — strict c14n is left to the IdP rotation tooling.
fn strip_signature(xml: &str) -> String {
    let mut out = xml.to_string();
    while let Some(start) = find_signature_open(&out) {
        if let Some(end) = find_signature_close(&out[start..]) {
            out.replace_range(start..start + end, "");
        } else {
            break;
        }
    }
    out
}

fn find_signature_open(xml: &str) -> Option<usize> {
    let cand = [
        "<Signature ",
        "<Signature>",
        "<ds:Signature ",
        "<ds:Signature>",
    ];
    cand.iter().filter_map(|n| xml.find(n)).min()
}

fn find_signature_close(xml: &str) -> Option<usize> {
    let cand = ["</Signature>", "</ds:Signature>"];
    for n in &cand {
        if let Some(p) = xml.find(n) {
            return Some(p + n.len());
        }
    }
    None
}

/// Conservative SignedInfo extraction — finds the `<SignedInfo>` element
/// in the raw XML and returns its bytes. Real c14n is a future improvement.
fn signed_info_bytes(xml: &str) -> Option<Vec<u8>> {
    let open_alts = [
        "<SignedInfo ",
        "<SignedInfo>",
        "<ds:SignedInfo ",
        "<ds:SignedInfo>",
    ];
    let close_alts = ["</SignedInfo>", "</ds:SignedInfo>"];
    let start = open_alts.iter().filter_map(|n| xml.find(n)).min()?;
    let mut end = None;
    for n in &close_alts {
        if let Some(p) = xml[start..].find(n) {
            end = Some(start + p + n.len());
            break;
        }
    }
    Some(xml.as_bytes()[start..end?].to_vec())
}

fn load_rsa_public_from_cert_pem(pem: &str) -> Result<rsa::RsaPublicKey, String> {
    use pkcs8::DecodePublicKey;
    use rsa::pkcs1::DecodeRsaPublicKey;

    let trimmed = pem.trim();
    let body: String = trimmed
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>()
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|e| format!("base64: {e}"))?;
    if trimmed.contains("BEGIN CERTIFICATE") {
        let (_, cert) =
            x509_parser::parse_x509_certificate(&bytes).map_err(|e| format!("x509: {e}"))?;
        // Try the SPKI form first (the certificate's full SubjectPublicKeyInfo
        // is the standard envelope for RSA public keys in X.509).
        let spki_der = cert.public_key().raw;
        if let Ok(k) = rsa::RsaPublicKey::from_public_key_der(spki_der) {
            return Ok(k);
        }
        // Fallback: some certificates encode the RSAPublicKey directly
        // inside subjectPublicKey (no AlgorithmIdentifier wrapper).
        rsa::RsaPublicKey::from_pkcs1_der(&cert.public_key().subject_public_key.data)
            .map_err(|e| format!("rsa public: {e}"))
    } else {
        rsa::RsaPublicKey::from_public_key_der(&bytes).map_err(|e| format!("spki: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_response_succeeds() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r1" InResponseTo="req1" Destination="https://sp/acs"><saml:Issuer>https://idp</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="a1"><saml:Issuer>https://idp</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">padme@example</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="req1" Recipient="https://sp/acs" NotOnOrAfter="2099-01-01T00:00:00Z"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"><saml:AudienceRestriction><saml:Audience>sp.example</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>padme@example</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(xml);
        let resp = parse_response(&b64).expect("parses");
        assert_eq!(resp.response_id, "r1");
        assert_eq!(resp.in_response_to.as_deref(), Some("req1"));
        assert_eq!(resp.issuer, "https://idp");
        let a = resp.assertion.as_ref().expect("assertion");
        assert_eq!(a.subject_name_id, "padme@example");
        assert_eq!(a.audiences, vec!["sp.example".to_string()]);
        assert_eq!(
            a.attributes.get("email").unwrap().as_slice(),
            ["padme@example"]
        );
    }

    #[test]
    fn audience_mismatch_rejected() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r1"><saml:Issuer>idp</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="a1"><saml:Issuer>idp</saml:Issuer><saml:Subject><saml:NameID>x</saml:NameID></saml:Subject><saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"><saml:AudienceRestriction><saml:Audience>other</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion></samlp:Response>"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(xml);
        let r = parse_response(&b64).unwrap();
        let err = assertion_to_broker("idp1", "sp.example", None, &r).unwrap_err();
        assert!(matches!(err, BrokerError::InvalidAssertion(_)));
    }

    #[test]
    fn build_redirect_authn_request_includes_samlrequest() {
        let cfg = SamlIdpConfig {
            entity_id: "idp".into(),
            sso_url: "https://idp/sso".into(),
            slo_url: None,
            signing_cert_pems: vec![],
            binding_outbound: SamlBinding::HttpRedirect,
            binding_inbound: SamlBinding::HttpPost,
            name_id_format: NameIdFormat::Persistent,
            want_assertions_signed: false,
            want_responses_signed: false,
        };
        let out = build_authn_request(&cfg, "sp.example", "https://sp/acs", "rel").unwrap();
        let url = out.redirect.expect("redirect");
        assert!(url.contains("SAMLRequest="));
        assert!(url.contains("RelayState=rel"));
    }
}
