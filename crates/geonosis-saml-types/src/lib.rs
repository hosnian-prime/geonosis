//! Shared SAML 2.0 schema types used by the broker (`spi-sp`) and the
//! IdP role (`spi-idp`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SamlBinding {
    HttpRedirect,
    HttpPost,
    Artifact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NameIdFormat {
    Unspecified,
    EmailAddress,
    Persistent,
    Transient,
    X509SubjectName,
}

impl NameIdFormat {
    pub fn as_uri(self) -> &'static str {
        match self {
            Self::Unspecified => "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            Self::EmailAddress => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            Self::Persistent => "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            Self::Transient => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
            Self::X509SubjectName => "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
        }
    }
}

/// Lightweight typed representation of a SAML 2.0 Assertion (no XML
/// signature surface — that lives in the protocol crate).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAssertion {
    pub id: String,
    pub issuer: String,
    pub subject_name_id: String,
    pub subject_name_id_format: NameIdFormat,
    pub audience: Vec<String>,
    pub issue_instant: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub not_on_or_after: DateTime<Utc>,
    pub destination: Option<Url>,
    pub attributes: Vec<SamlAttribute>,
    pub authn_context_class_ref: Option<String>,
    pub authn_instant: DateTime<Utc>,
    pub session_index: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAttribute {
    pub name: String,
    pub name_format: String,
    pub friendly_name: Option<String>,
    pub values: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_id_format_uris() {
        assert_eq!(
            NameIdFormat::Persistent.as_uri(),
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
        );
        assert_eq!(
            NameIdFormat::EmailAddress.as_uri(),
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        );
    }
}
