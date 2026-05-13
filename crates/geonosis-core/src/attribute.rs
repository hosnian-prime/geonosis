//! User / role / org attribute value type.

use serde::{Deserialize, Serialize};

/// A polymorphic attribute value attached to users, roles, agents, orgs.
///
/// Values are serialized to JSON when persisted; the variants preserve
/// type information for the User Profile validator pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttributeValue {
    String(String),
    Strings(Vec<String>),
    Integer(i64),
    Bool(bool),
    Float(f64),
    Null,
}

impl AttributeValue {
    pub fn as_str(&self) -> Option<&str> {
        if let Self::String(s) = self {
            Some(s)
        } else {
            None
        }
    }
}

/// A flagged required-action that gates login until performed by the user.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequiredAction {
    UpdatePassword,
    ConfigureOtp,
    ConfigureWebauthn,
    VerifyEmail,
    UpdateProfile,
    AcceptTerms,
    DeleteAccount,
    /// Open-ended action key registered by an SPI.
    #[serde(untagged)]
    Custom(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_value_string_serde() {
        let v = AttributeValue::String("hello".into());
        let j = serde_json::to_string(&v).unwrap();
        assert_eq!(j, "\"hello\"");
    }

    #[test]
    fn attribute_value_multivalued_serde() {
        let v = AttributeValue::Strings(vec!["a".into(), "b".into()]);
        let j = serde_json::to_string(&v).unwrap();
        assert_eq!(j, "[\"a\",\"b\"]");
    }

    #[test]
    fn required_action_kebab_case() {
        let j = serde_json::to_string(&RequiredAction::UpdatePassword).unwrap();
        assert_eq!(j, "\"update-password\"");
    }
}
