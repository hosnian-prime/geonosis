//! Authoring SDK for Geonosis SPI plugin developers.
//!
//! Plugin crates depend on this crate (NOT on `geonosis-spi-host` or
//! `geonosis-server`). It re-exports the public shape of the plugin
//! contract and provides ergonomic builders.
//!
//! v0.1: Rust authoring only. v0.2 adds TinyGo and JS (componentize-js).

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
