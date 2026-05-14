//! User entity.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::attribute::{AttributeValue, RequiredAction};
use crate::credential::CredentialRef;
use crate::id::{OrganizationId, RealmId, UserId};

/// A human user (not an Agent — see `agent.rs`).
///
/// `Default` constructs a placeholder with fresh ULID identifiers and
/// `enabled = true`. Production callers fill in `realm_id` and
/// `username`; tests can use `..Default::default()` to opt-in to the
/// safe defaults for the rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub realm_id: RealmId,
    /// NFKC-folded, ICU-lowercased. Storage layer enforces canonical form.
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<PersonName>,
    pub credentials: Vec<CredentialRef>,
    pub federation: Option<FederationLink>,
    pub attributes: BTreeMap<String, AttributeValue>,
    pub required_actions: Vec<RequiredAction>,
    /// If set, login MUST traverse the named flow alias regardless of
    /// realm default. Used for admin-imposed step-ups.
    pub required_flow: Option<String>,
    /// Denormalized cache of organization memberships for hot-path token
    /// claim emission. Source of truth is `OrgMembership`.
    pub organizations: Vec<OrganizationId>,
    pub enabled: bool,
    /// Monotonic count of failed credential attempts in the current
    /// `BruteForcePolicy::failure_reset_window`. Resets to 0 on success
    /// or on window expiry.
    #[serde(default)]
    pub failed_attempts: u32,
    /// Soft lock — the account is reject-by-policy until this instant.
    /// `None` means not locked.
    #[serde(default)]
    pub locked_until: Option<DateTime<Utc>>,
    /// Timestamp of the most recent failed attempt; used by the
    /// brute-force runtime to apply the "quick-login" minimum wait and
    /// to expire counters once `failure_reset_window` has elapsed.
    #[serde(default)]
    pub last_failed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Default for User {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            id: UserId::new(),
            realm_id: RealmId::new(),
            username: String::new(),
            email: None,
            email_verified: false,
            name: None,
            credentials: vec![],
            federation: None,
            attributes: Default::default(),
            required_actions: vec![],
            required_flow: None,
            organizations: vec![],
            enabled: true,
            failed_attempts: 0,
            locked_until: None,
            last_failed_at: None,
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersonName {
    pub given: Option<String>,
    pub family: Option<String>,
    pub middle: Option<String>,
    pub display: Option<String>,
}

impl PersonName {
    pub fn display_or_concat(&self) -> Option<String> {
        if let Some(d) = &self.display {
            return Some(d.clone());
        }
        match (&self.given, &self.family) {
            (Some(g), Some(f)) => Some(format!("{g} {f}")),
            (Some(g), None) => Some(g.clone()),
            (None, Some(f)) => Some(f.clone()),
            (None, None) => None,
        }
    }
}

/// Link back to the user-storage provider that owns authoritative state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationLink {
    /// Provider URN, e.g. `builtin:user-storage:ldap:corp-ad`.
    pub source_urn: String,
    pub external_id: String,
    pub external_dn: Option<String>,
    pub last_synced_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn person_name_display() {
        let p = PersonName {
            given: Some("Padmé".into()),
            family: Some("Amidala".into()),
            ..PersonName::default()
        };
        assert_eq!(p.display_or_concat().as_deref(), Some("Padmé Amidala"));
    }
}
