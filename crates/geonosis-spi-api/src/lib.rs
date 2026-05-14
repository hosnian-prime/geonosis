//! Authoring SDK for Geonosis SPI plugin developers.
//!
//! Plugin crates depend on this crate (NOT on `geonosis-spi-host` or
//! `geonosis-server`). It re-exports the public shape of the plugin
//! contract and provides ergonomic builders.
//!
//! v0.1: Rust authoring only. v0.2 adds TinyGo and JS (componentize-js).
//!
//! The WIT contracts live at the workspace root under `wit/`. Plugin
//! authors point `wit-bindgen` at those files; the SDK here provides
//! Rust shapes that match the WIT records, plus the convenience
//! `MapperOutput` / `AuthnDecision` types most plugins reuse.

pub use geonosis_core::attribute::{AttributeValue, RequiredAction};
pub use geonosis_core::common::Amr;
pub use geonosis_core::scope::ScopeName;
pub use geonosis_core::secret::Secret;
pub use geonosis_core::subject::Subject;

use serde::{Deserialize, Serialize};

/// Common result type returned from a custom authenticator step.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AuthnDecision {
    Success { amr: Vec<Amr> },
    Failure { reason: String },
    Challenge { template: String, locals: serde_json::Value },
    Skip,
}

/// Common result type for `geonosis:mapper@0.1.0`. Mappers transform claim
/// maps; nodes implementing this trait MUST be deterministic and side-
/// effect-free (so they can run inside the request critical path).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapperOutput {
    /// New claims to merge into the target token / userinfo.
    pub claims: serde_json::Map<String, serde_json::Value>,
}

/// Stable wire shape for the `geonosis:types/plugin-error` record.
/// Plugin authors return one of these from any fallible export; the
/// host translates it back into `RuntimeError::Plugin` with the
/// `kind` exposed in metrics labels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginError {
    pub kind: String,
    pub message: String,
    pub retryable: bool,
}

impl PluginError {
    pub fn new(kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            message: message.into(),
            retryable: false,
        }
    }

    pub fn retryable(mut self) -> Self {
        self.retryable = true;
        self
    }
}

/// JSON-encoded claim-set helper. Plugin code:
///
/// ```ignore
/// let claims: ClaimSet = ClaimSet::decode(&input_bytes)?;
/// claims.set("groups", vec!["admins"]);
/// let out = claims.encode();
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClaimSet(pub serde_json::Map<String, serde_json::Value>);

impl ClaimSet {
    pub fn decode(bytes: &[u8]) -> Result<Self, PluginError> {
        serde_json::from_slice::<serde_json::Value>(bytes)
            .map_err(|e| PluginError::new("decode", e.to_string()))
            .and_then(|v| match v {
                serde_json::Value::Object(m) => Ok(Self(m)),
                other => Err(PluginError::new(
                    "decode",
                    format!("expected object, got {other:?}"),
                )),
            })
    }

    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(&self.0).expect("claim-set serialization")
    }

    pub fn set(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.0.insert(key.into(), value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authn_decision_serializes_with_kind_tag() {
        let d = AuthnDecision::Success {
            amr: vec![Amr::Pwd],
        };
        let j = serde_json::to_value(&d).unwrap();
        assert_eq!(j.get("kind").and_then(|v| v.as_str()), Some("success"));
    }
}
