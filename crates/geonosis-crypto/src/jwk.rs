//! JSON Web Key (RFC 7517) + JWK Set rendering.

use serde::{Deserialize, Serialize};

use geonosis_core::common::JwsAlgorithm;

/// A JWK as exposed on `/jwks` (public material only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kid: String,
    pub kty: String,
    pub r#use: String,
    pub alg: String,
    /// Algorithm-specific fields. We keep this as a flat extension on the
    /// outer struct via `#[serde(flatten)]` for round-tripping.
    #[serde(flatten)]
    pub params: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// Type-erased public-key material that callers hold without committing
/// to a specific algorithm.
#[derive(Debug, Clone)]
pub struct PublicJwk(pub Jwk);

impl Jwk {
    pub fn alg_typed(&self) -> Option<JwsAlgorithm> {
        Some(match self.alg.as_str() {
            "RS256" => JwsAlgorithm::RS256,
            "RS384" => JwsAlgorithm::RS384,
            "RS512" => JwsAlgorithm::RS512,
            "PS256" => JwsAlgorithm::PS256,
            "PS384" => JwsAlgorithm::PS384,
            "PS512" => JwsAlgorithm::PS512,
            "ES256" => JwsAlgorithm::ES256,
            "ES384" => JwsAlgorithm::ES384,
            "ES512" => JwsAlgorithm::ES512,
            "EdDSA" => JwsAlgorithm::EdDSA,
            "HS256" => JwsAlgorithm::HS256,
            "HS384" => JwsAlgorithm::HS384,
            "HS512" => JwsAlgorithm::HS512,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwk_set_serializes_under_keys_root() {
        let set = JwkSet {
            keys: vec![Jwk {
                kid: "k1".into(),
                kty: "RSA".into(),
                r#use: "sig".into(),
                alg: "RS256".into(),
                params: serde_json::Map::new(),
            }],
        };
        let j = serde_json::to_value(&set).unwrap();
        assert!(j.get("keys").is_some());
    }

    #[test]
    fn alg_typed_recognises_es256() {
        let j = Jwk {
            kid: "k".into(),
            kty: "EC".into(),
            r#use: "sig".into(),
            alg: "ES256".into(),
            params: serde_json::Map::new(),
        };
        assert_eq!(j.alg_typed(), Some(JwsAlgorithm::ES256));
    }
}
