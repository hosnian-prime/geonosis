//! Cross-cutting enums used by multiple entities.

use serde::{Deserialize, Serialize};

/// TLS posture for a realm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SslRequirement {
    /// HTTPS not required (development only).
    None,
    /// HTTPS required for non-loopback requests (default).
    #[default]
    ExternalRequests,
    /// HTTPS required for every request.
    All,
}

/// JOSE signing algorithm names. Values match the `alg` JWS header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum JwsAlgorithm {
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    ES256,
    ES384,
    ES512,
    EdDSA,
    HS256,
    HS384,
    HS512,
}

impl JwsAlgorithm {
    /// JWS `alg` header value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
            Self::RS512 => "RS512",
            Self::PS256 => "PS256",
            Self::PS384 => "PS384",
            Self::PS512 => "PS512",
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::ES512 => "ES512",
            Self::EdDSA => "EdDSA",
            Self::HS256 => "HS256",
            Self::HS384 => "HS384",
            Self::HS512 => "HS512",
        }
    }

    /// True for asymmetric algorithms suitable for production token signing.
    /// HMAC variants are restricted to internal use (e.g. client-secret-jwt).
    pub const fn is_asymmetric(self) -> bool {
        !matches!(self, Self::HS256 | Self::HS384 | Self::HS512)
    }
}

/// Bound-token mechanism (RFC 9449 / RFC 8705).
///
/// `Dpop` and `Mtls` are accepted on the public surface but only enforced in
/// v0.2; v0.1 records the realm preference for compatibility forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SenderConstraint {
    #[default]
    None,
    Dpop,
    Mtls,
}

/// Authentication strength achieved by a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum AuthnLevel {
    Anonymous = 0,
    Single = 1,
    Mfa = 2,
    HardwareBound = 3,
}

/// RFC 8176 Authentication Method Reference values + extensions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Amr {
    #[serde(rename = "pwd")]
    Pwd,
    #[serde(rename = "otp")]
    Otp,
    #[serde(rename = "wbn")]
    Wbn,
    #[serde(rename = "sms")]
    Sms,
    #[serde(rename = "email")]
    Email,
    #[serde(rename = "mfa")]
    Mfa,
    #[serde(rename = "pop")]
    Pop,
    #[serde(untagged)]
    Custom(String),
}

impl Amr {
    pub fn as_token_value(&self) -> String {
        match self {
            Self::Pwd => "pwd".into(),
            Self::Otp => "otp".into(),
            Self::Wbn => "wbn".into(),
            Self::Sms => "sms".into(),
            Self::Email => "email".into(),
            Self::Mfa => "mfa".into(),
            Self::Pop => "pop".into(),
            Self::Custom(s) => s.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jws_alg_str_roundtrip() {
        for alg in [
            JwsAlgorithm::RS256,
            JwsAlgorithm::ES256,
            JwsAlgorithm::EdDSA,
        ] {
            assert_eq!(
                alg.as_str(),
                serde_json::from_str::<JwsAlgorithm>(&format!("\"{}\"", alg.as_str()))
                    .unwrap()
                    .as_str()
            );
        }
    }

    #[test]
    fn asymmetric_classification() {
        assert!(JwsAlgorithm::RS256.is_asymmetric());
        assert!(JwsAlgorithm::ES256.is_asymmetric());
        assert!(JwsAlgorithm::EdDSA.is_asymmetric());
        assert!(!JwsAlgorithm::HS256.is_asymmetric());
    }

    #[test]
    fn authn_level_orders() {
        assert!(AuthnLevel::Mfa > AuthnLevel::Single);
        assert!(AuthnLevel::HardwareBound > AuthnLevel::Mfa);
    }

    #[test]
    fn amr_custom_serializes_as_string() {
        let a = Amr::Custom("biometric".into());
        let j = serde_json::to_string(&a).unwrap();
        assert_eq!(j, "\"biometric\"");
    }
}
