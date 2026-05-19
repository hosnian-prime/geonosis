//! Declarative user-profile schema.
//!
//! Per `docs/16-user-profile.md`: each realm carries exactly one
//! `UserProfile` — a declared list of attribute declarations and a
//! policy for everything else. Built-in attributes (`username`, `email`,
//! `firstName`, `lastName`) ship in the default schema.
//!
//! Validators are pure functions where possible (`Length`, `Regex`,
//! `Email`, …) and a `Custom` variant that dispatches to a WASM
//! `geonosis:user-profile-validator@0.1.0` component bound by URN.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::id::RealmId;

/// One profile schema per realm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub realm_id: RealmId,
    /// Ordered list — first match wins in the form-builder. Built-in
    /// attributes appear first by convention.
    pub attributes: Vec<UserAttributeDecl>,
    /// Optional grouping for the admin UI form layout.
    pub groups: Vec<UserAttributeGroup>,
    /// How to treat attributes that arrive on a user but were not
    /// declared above. Default `Reject` matches doc §16.
    pub unmanaged_policy: UnmanagedAttributePolicy,
    pub updated_at: DateTime<Utc>,
}

impl UserProfile {
    /// Built-in default schema. Matches doc §16 Built-in attribute table.
    pub fn default_for(realm_id: RealmId) -> Self {
        Self {
            realm_id,
            attributes: vec![
                UserAttributeDecl::builtin("username", "Username", true, false),
                UserAttributeDecl::builtin("email", "Email", true, false),
                UserAttributeDecl::builtin("firstName", "First name", false, false),
                UserAttributeDecl::builtin("lastName", "Last name", false, false),
            ],
            groups: vec![],
            unmanaged_policy: UnmanagedAttributePolicy::Reject,
            updated_at: Utc::now(),
        }
    }

    pub fn find(&self, name: &str) -> Option<&UserAttributeDecl> {
        self.attributes.iter().find(|a| a.name == name)
    }

    /// Validate user attributes against the schema's built-in validators.
    /// Returns a list of `(attribute_name, error_message)` violations.
    /// `Custom` (WASM) validators are skipped — they require the SPI
    /// runtime which is not available in the core crate.
    /// Built-in attribute names that are top-level User fields, not in
    /// the `attributes` map. Skip these during attribute validation.
    const BUILTIN_NAMES: &[&str] = &["username", "email", "firstName", "lastName"];

    /// Validate user attributes against the schema's built-in validators.
    /// Returns a list of `(attribute_name, error_message)` violations.
    /// Built-in attributes (`username`, `email`, etc.) are skipped since
    /// they are top-level `User` fields, not in the `attributes` map.
    /// `Custom` (WASM) validators are also skipped.
    pub fn validate_attributes(
        &self,
        attrs: &BTreeMap<String, crate::AttributeValue>,
    ) -> Vec<(String, String)> {
        let mut violations = Vec::new();
        for decl in &self.attributes {
            // Skip built-in attributes handled as top-level User fields.
            if Self::BUILTIN_NAMES.contains(&decl.name.as_str()) {
                continue;
            }
            let value = attrs.get(&decl.name);
            if decl.required
                && value.map_or(true, |v| {
                    matches!(v, crate::AttributeValue::Null)
                })
            {
                violations.push((decl.name.clone(), "required".into()));
                continue;
            }
            let Some(val) = value else { continue };
            let val_str = val.as_str().unwrap_or("").to_string();
            for validator in &decl.validators {
                if let Some(err) = validate_one(validator, &val_str) {
                    violations.push((decl.name.clone(), err));
                    break;
                }
            }
        }
        violations
    }
}

fn validate_one(v: &AttributeValidator, value: &str) -> Option<String> {
    match v {
        AttributeValidator::Length { min, max } => {
            let len = value.len() as u32;
            if let Some(m) = min {
                if len < *m {
                    return Some(format!("too short (min {m})"));
                }
            }
            if let Some(m) = max {
                if len > *m {
                    return Some(format!("too long (max {m})"));
                }
            }
            None
        }
        AttributeValidator::Email => {
            if !value.contains('@') || !value.contains('.') {
                Some("invalid email".into())
            } else {
                None
            }
        }
        AttributeValidator::Options { allowed } => {
            if !allowed.iter().any(|a| a == value) {
                Some(format!("value not in allowed list"))
            } else {
                None
            }
        }
        // Pattern, Uri, Integer, DoubleNotNan, Custom — skipped in v0.1
        // (regex requires a regex crate dep; Custom requires WASM runtime).
        _ => None,
    }
}

/// One attribute declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAttributeDecl {
    pub name: String,
    pub display_name: String,
    pub required: bool,
    pub multivalued: bool,
    /// Validators applied in order. Short-circuit on first error.
    pub validators: Vec<AttributeValidator>,
    /// View / edit permissions split by actor kind (admin vs end-user).
    pub permissions: AttributePermissions,
    /// Optional group key referencing `UserProfile.groups[].name`.
    pub group: Option<String>,
    /// Free-form annotations consumed by themes / UI components.
    pub annotations: BTreeMap<String, String>,
}

impl UserAttributeDecl {
    /// Construct a minimally configured built-in attribute.
    pub fn builtin(name: &str, display: &str, required: bool, multivalued: bool) -> Self {
        Self {
            name: name.into(),
            display_name: display.into(),
            required,
            multivalued,
            validators: vec![],
            permissions: AttributePermissions::default(),
            group: None,
            annotations: BTreeMap::new(),
        }
    }
}

/// Built-in + custom attribute validators.
///
/// `Custom` defers to a WASM `geonosis:user-profile-validator@0.1.0`
/// component selected by URN. The host invokes it through the
/// `NamedAttach` dispatch mode (doc 07 §Dispatch modes).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AttributeValidator {
    Length {
        min: Option<u32>,
        max: Option<u32>,
    },
    Pattern {
        regex: String,
        error_key: Option<String>,
    },
    Email,
    Uri,
    Integer {
        min: Option<i64>,
        max: Option<i64>,
    },
    DoubleNotNan,
    Options {
        allowed: Vec<String>,
    },
    /// Defers to a WASM validator component. The URN must resolve to a
    /// `SpiBinding` with interface `geonosis:user-profile-validator@0.1.0`.
    Custom {
        provider_urn: String,
    },
}

/// Permission split between admin actor and self (end-user) actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributePermissions {
    pub view: AttributeActorSet,
    pub edit: AttributeActorSet,
}

impl Default for AttributePermissions {
    fn default() -> Self {
        Self {
            view: AttributeActorSet {
                admin: true,
                user: true,
            },
            edit: AttributeActorSet {
                admin: true,
                user: true,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AttributeActorSet {
    pub admin: bool,
    pub user: bool,
}

/// What to do with attributes carried by a user but not declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnmanagedAttributePolicy {
    /// Reject the write entirely — the v0.1 default.
    Reject,
    /// Accept and persist as-is, but never expose on /userinfo.
    Allow,
    /// Accept and persist; admin can see and edit, end-user cannot.
    Hidden,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAttributeGroup {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_schema_carries_four_builtins() {
        let p = UserProfile::default_for(RealmId::new());
        assert_eq!(p.attributes.len(), 4);
        assert!(p.find("username").unwrap().required);
        assert!(p.find("email").unwrap().required);
        assert_eq!(p.unmanaged_policy, UnmanagedAttributePolicy::Reject);
    }

    #[test]
    fn validator_serializes_tagged() {
        let v = AttributeValidator::Length {
            min: Some(3),
            max: Some(64),
        };
        let j = serde_json::to_string(&v).unwrap();
        assert!(j.contains(r#""kind":"length""#));
    }

    #[test]
    fn custom_validator_carries_urn() {
        let v = AttributeValidator::Custom {
            provider_urn: "urn:geonosis:plugin:dept-code".into(),
        };
        let j = serde_json::to_string(&v).unwrap();
        let back: AttributeValidator = serde_json::from_str(&j).unwrap();
        if let AttributeValidator::Custom { provider_urn } = back {
            assert_eq!(provider_urn, "urn:geonosis:plugin:dept-code");
        } else {
            panic!("variant lost");
        }
    }

    #[test]
    fn unmanaged_policy_serializes_kebab_case() {
        let j = serde_json::to_string(&UnmanagedAttributePolicy::Reject).unwrap();
        assert_eq!(j, "\"reject\"");
    }
}
