//! Built-in `MapperBinding` runtimes.
//!
//! Per `docs/05-identity-broker.md` §"Mappers" four mappers ship out
//! of the box:
//! - `claim-to-attribute` — copy a claim into a user attribute
//! - `claim-to-role` — assign a role when a claim matches a predicate
//! - `username-template` — synthesize a username from claims
//! - `email-verified-passthrough` — accept the IdP's `email_verified`
//!
//! Each mapper consumes the verified `BrokerAssertion` and applies its
//! effect to a `DraftUser`. WASM mappers (the `geonosis:mapper@0.1.0`
//! SPI interface) plug into the same pipeline via `host.apply_to_draft`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use geonosis_core::attribute::AttributeValue;

use crate::types::BrokerAssertion;

/// Configuration of one mapper binding. Operators wire several of these
/// onto an `IdentityProvider`; we run them in priority order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapperBinding {
    pub name: String,
    pub priority: i32,
    #[serde(flatten)]
    pub kind: MapperKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum MapperKind {
    ClaimToAttribute {
        claim: String,
        attribute: String,
        /// If true, overwrite the attribute when already present.
        #[serde(default = "default_true")]
        overwrite: bool,
    },
    ClaimToRole {
        claim: String,
        /// Required value(s) for the claim. When `match_any` matches
        /// the predicate against any list entry; otherwise the claim
        /// must exactly equal one of the strings.
        values: Vec<String>,
        #[serde(default)]
        match_any: bool,
        role: String,
    },
    UsernameTemplate {
        /// String with `${claim}` placeholders.
        template: String,
    },
    EmailVerifiedPassthrough,
}

fn default_true() -> bool {
    true
}

/// The shape mappers contribute to. Returned to the flow executor as
/// the draft `User` row + role assignments.
#[derive(Debug, Clone, Default)]
pub struct DraftUser {
    pub username: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub attributes: BTreeMap<String, AttributeValue>,
    pub roles: Vec<String>,
}

/// Apply every mapper to the assertion in priority order. The
/// `DraftUser` is seeded with whatever the OIDC adapter already
/// extracted (preferred_username, email, etc).
pub fn apply_all(
    bindings: &[MapperBinding],
    assertion: &BrokerAssertion,
    draft: &mut DraftUser,
) {
    let mut sorted: Vec<&MapperBinding> = bindings.iter().collect();
    sorted.sort_by(|a, b| a.priority.cmp(&b.priority));
    for binding in sorted {
        apply_one(&binding.kind, assertion, draft);
    }
}

fn apply_one(kind: &MapperKind, assertion: &BrokerAssertion, draft: &mut DraftUser) {
    match kind {
        MapperKind::ClaimToAttribute {
            claim,
            attribute,
            overwrite,
        } => {
            if let Some(v) = assertion.claims.get(claim) {
                if *overwrite || !draft.attributes.contains_key(attribute) {
                    draft.attributes.insert(attribute.clone(), v.clone());
                }
            }
        }
        MapperKind::ClaimToRole {
            claim,
            values,
            match_any,
            role,
        } => {
            if claim_matches(assertion, claim, values, *match_any) {
                if !draft.roles.contains(role) {
                    draft.roles.push(role.clone());
                }
            }
        }
        MapperKind::UsernameTemplate { template } => {
            let resolved = expand_template(template, assertion);
            if !resolved.is_empty() {
                draft.username = Some(resolved);
            }
        }
        MapperKind::EmailVerifiedPassthrough => {
            if let Some(AttributeValue::Bool(v)) = assertion.claims.get("email_verified") {
                draft.email_verified = *v;
            }
        }
    }
}

fn claim_matches(assertion: &BrokerAssertion, claim: &str, values: &[String], match_any: bool) -> bool {
    match assertion.claims.get(claim) {
        Some(AttributeValue::String(s)) => values.iter().any(|v| v == s),
        Some(AttributeValue::Strings(arr)) => {
            if match_any {
                arr.iter().any(|item| values.iter().any(|v| v == item))
            } else {
                arr.iter().all(|item| values.iter().any(|v| v == item))
            }
        }
        Some(AttributeValue::Bool(b)) => values.iter().any(|v| v == &b.to_string()),
        _ => false,
    }
}

fn expand_template(template: &str, assertion: &BrokerAssertion) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        if let Some(end) = after.find('}') {
            let key = &after[..end];
            if let Some(v) = assertion.claims.get(key) {
                out.push_str(&render_attribute_value(v));
            }
            rest = &after[end + 1..];
        } else {
            out.push_str(&rest[start..]);
            break;
        }
    }
    out.push_str(rest);
    out
}

fn render_attribute_value(v: &AttributeValue) -> String {
    match v {
        AttributeValue::String(s) => s.clone(),
        AttributeValue::Strings(arr) => arr.first().cloned().unwrap_or_default(),
        AttributeValue::Integer(i) => i.to_string(),
        AttributeValue::Bool(b) => b.to_string(),
        AttributeValue::Float(f) => f.to_string(),
        AttributeValue::Null => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn assertion_with(claims: BTreeMap<String, AttributeValue>) -> BrokerAssertion {
        BrokerAssertion {
            idp_alias: "x".into(),
            external_id: "ext".into(),
            issuer: "iss".into(),
            claims,
            received_at: Utc::now(),
            expires_at: None,
        }
    }

    #[test]
    fn claim_to_attribute_copies_value() {
        let mut claims = BTreeMap::new();
        claims.insert("department".into(), AttributeValue::String("eng".into()));
        let a = assertion_with(claims);
        let mut draft = DraftUser::default();
        apply_all(
            &[MapperBinding {
                name: "dept".into(),
                priority: 0,
                kind: MapperKind::ClaimToAttribute {
                    claim: "department".into(),
                    attribute: "dept".into(),
                    overwrite: true,
                },
            }],
            &a,
            &mut draft,
        );
        assert!(matches!(draft.attributes.get("dept"), Some(AttributeValue::String(s)) if s == "eng"));
    }

    #[test]
    fn claim_to_role_assigns_when_matches() {
        let mut claims = BTreeMap::new();
        claims.insert(
            "groups".into(),
            AttributeValue::Strings(vec!["admins".into(), "all".into()]),
        );
        let a = assertion_with(claims);
        let mut draft = DraftUser::default();
        apply_all(
            &[MapperBinding {
                name: "admin".into(),
                priority: 0,
                kind: MapperKind::ClaimToRole {
                    claim: "groups".into(),
                    values: vec!["admins".into()],
                    match_any: true,
                    role: "realm-admin".into(),
                },
            }],
            &a,
            &mut draft,
        );
        assert_eq!(draft.roles, vec!["realm-admin".to_string()]);
    }

    #[test]
    fn username_template_expands_claims() {
        let mut claims = BTreeMap::new();
        claims.insert(
            "preferred_username".into(),
            AttributeValue::String("padme".into()),
        );
        let a = assertion_with(claims);
        let mut draft = DraftUser::default();
        apply_all(
            &[MapperBinding {
                name: "u".into(),
                priority: 0,
                kind: MapperKind::UsernameTemplate {
                    template: "${preferred_username}@google".into(),
                },
            }],
            &a,
            &mut draft,
        );
        assert_eq!(draft.username.as_deref(), Some("padme@google"));
    }

    #[test]
    fn email_verified_passthrough_copies_bool() {
        let mut claims = BTreeMap::new();
        claims.insert("email_verified".into(), AttributeValue::Bool(true));
        let a = assertion_with(claims);
        let mut draft = DraftUser::default();
        apply_all(
            &[MapperBinding {
                name: "ev".into(),
                priority: 0,
                kind: MapperKind::EmailVerifiedPassthrough,
            }],
            &a,
            &mut draft,
        );
        assert!(draft.email_verified);
    }

    #[test]
    fn mappers_run_in_priority_order() {
        let mut claims = BTreeMap::new();
        claims.insert("name".into(), AttributeValue::String("A".into()));
        let a = assertion_with(claims);
        let mut draft = DraftUser::default();
        apply_all(
            &[
                MapperBinding {
                    name: "low".into(),
                    priority: 1,
                    kind: MapperKind::ClaimToAttribute {
                        claim: "name".into(),
                        attribute: "x".into(),
                        overwrite: true,
                    },
                },
                MapperBinding {
                    name: "high".into(),
                    priority: 0,
                    kind: MapperKind::ClaimToAttribute {
                        claim: "name".into(),
                        attribute: "x".into(),
                        overwrite: false,
                    },
                },
            ],
            &a,
            &mut draft,
        );
        assert!(matches!(draft.attributes.get("x"), Some(AttributeValue::String(s)) if s == "A"));
    }
}
