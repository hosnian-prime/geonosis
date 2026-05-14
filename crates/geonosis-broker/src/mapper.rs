//! Built-in `MapperBinding` runtimes.
//!
//! Per `docs/05-identity-broker.md` §"Mappers" five mappers ship out
//! of the box:
//! - `claim-to-attribute` — copy a claim into a user attribute
//! - `claim-to-role` — assign a role when a claim matches a predicate
//! - `claim-to-org` — propose an organization membership when a claim
//!   matches; the first-broker-login flow promotes the proposal to an
//!   `OrgMembership` after domain / policy checks
//! - `username-template` — synthesize a username from claims
//! - `email-verified-passthrough` — accept the IdP's `email_verified`
//!
//! Each mapper consumes the verified `BrokerAssertion` and applies its
//! effect to a `DraftUser`. WASM mappers (the `geonosis:mapper@0.1.0`
//! SPI interface) plug into the same pipeline via `host.apply_to_draft`.
//!
//! ## Why this is an enum, not a trait + registry
//!
//! Unlike `Authenticator` (URN → trait) and `BrokerAdapter` (URN →
//! multi-hook trait), mappers are **config-driven, not URN-dispatched
//! providers**. A `MapperBinding` row stores both WHICH built-in
//! transformation to apply (`MapperKind` variant) AND its parameters
//! (`claim` name, `attribute` name, regex pattern, etc.). Admins
//! configure mappers; they don't install separate runtime
//! implementations for each one.
//!
//! WASM mappers (`geonosis:mapper@0.1.0` SPI) take a different path:
//! the WASM runtime invokes them via `host.apply_to_draft`, not
//! through this enum. A single mapper PIPELINE composes built-in
//! enum-variant mappers AND WASM mappers — they don't share a trait
//! because they don't share a call-site shape.
//!
//! This is the third intentional shape in the broker/server registry
//! family: see `geonosis-server/src/authenticators.rs` §"Pattern note"
//! for the cross-reference.

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
    /// Propose an organization membership when a broker claim matches.
    /// The first-broker-login flow consumes the proposed alias(es) and
    /// performs the actual `OrgMembership` upsert after policy checks
    /// (domain verification, auto-join allow-list, ...).
    ClaimToOrg {
        claim: String,
        values: Vec<String>,
        #[serde(default)]
        match_any: bool,
        org_alias: String,
        /// Optional default org-scoped role alias the user receives.
        #[serde(default)]
        role: Option<String>,
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
/// the draft `User` row + role assignments + proposed org memberships.
#[derive(Debug, Clone, Default)]
pub struct DraftUser {
    pub username: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub attributes: BTreeMap<String, AttributeValue>,
    pub roles: Vec<String>,
    /// Org alias → optional initial role. Flow executor calls
    /// `storage.get_organization_by_alias` and upserts membership.
    pub org_assignments: Vec<DraftOrgAssignment>,
}

#[derive(Debug, Clone)]
pub struct DraftOrgAssignment {
    pub org_alias: String,
    pub role: Option<String>,
}

/// Apply every mapper to the assertion in priority order. The
/// `DraftUser` is seeded with whatever the OIDC adapter already
/// extracted (preferred_username, email, etc).
pub fn apply_all(bindings: &[MapperBinding], assertion: &BrokerAssertion, draft: &mut DraftUser) {
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
            if claim_matches(assertion, claim, values, *match_any) && !draft.roles.contains(role) {
                draft.roles.push(role.clone());
            }
        }
        MapperKind::ClaimToOrg {
            claim,
            values,
            match_any,
            org_alias,
            role,
        } => {
            if claim_matches(assertion, claim, values, *match_any) {
                let already = draft
                    .org_assignments
                    .iter()
                    .any(|a| a.org_alias == *org_alias);
                if !already {
                    draft.org_assignments.push(DraftOrgAssignment {
                        org_alias: org_alias.clone(),
                        role: role.clone(),
                    });
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

fn claim_matches(
    assertion: &BrokerAssertion,
    claim: &str,
    values: &[String],
    match_any: bool,
) -> bool {
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
        assert!(
            matches!(draft.attributes.get("dept"), Some(AttributeValue::String(s)) if s == "eng")
        );
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
    fn claim_to_org_pushes_assignment() {
        let mut claims = BTreeMap::new();
        claims.insert(
            "groups".into(),
            AttributeValue::Strings(vec!["acme-employees".into()]),
        );
        let a = assertion_with(claims);
        let mut draft = DraftUser::default();
        apply_all(
            &[MapperBinding {
                name: "acme".into(),
                priority: 0,
                kind: MapperKind::ClaimToOrg {
                    claim: "groups".into(),
                    values: vec!["acme-employees".into()],
                    match_any: true,
                    org_alias: "acme".into(),
                    role: Some("member".into()),
                },
            }],
            &a,
            &mut draft,
        );
        assert_eq!(draft.org_assignments.len(), 1);
        assert_eq!(draft.org_assignments[0].org_alias, "acme");
        assert_eq!(draft.org_assignments[0].role.as_deref(), Some("member"));
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
