//! Translate an LDAP search entry into a `geonosis_core::User`.
//!
//! Stays runtime-agnostic — `ldap-runtime` callers turn an `ldap3::SearchEntry`
//! into `EntryAttributes` once and then hand it here. Keeping the
//! mapper pure means we can unit-test the AD `userAccountControl` bit
//! handling and the `entryUUID`/`objectGUID` translation without a
//! live server.

use std::collections::BTreeMap;

use chrono::Utc;

use geonosis_core::id::RealmId;
use geonosis_core::user::{FederationLink, PersonName, User};

use crate::config::{provider_urn, AttributeMap};

/// `userAccountControl` bit `0x0002` (ACCOUNTDISABLE) — set means
/// "AD has disabled this user."
pub const AD_ACCOUNT_DISABLED: u32 = 0x0002;

/// Multi-valued attributes flattened to first non-empty value (LDAP
/// returns lists; auth-time mapping wants scalars).
#[derive(Debug, Clone, Default)]
pub struct EntryAttributes {
    pub dn: String,
    pub values: BTreeMap<String, Vec<String>>,
}

impl EntryAttributes {
    pub fn first(&self, attr: &str) -> Option<&str> {
        // LDAP attribute names are case-insensitive — clients often
        // upper-case (`mail` vs `Mail`); normalize on lookup.
        self.values
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(attr))
            .and_then(|(_, v)| v.iter().find(|s| !s.is_empty()).map(String::as_str))
    }

    pub fn all(&self, attr: &str) -> Vec<&str> {
        self.values
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(attr))
            .map(|(_, v)| v.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }
}

pub fn entry_to_user(
    realm_id: RealmId,
    alias: &str,
    map: &AttributeMap,
    entry: &EntryAttributes,
) -> Option<User> {
    let username = entry.first(&map.username)?.to_string();
    let external_id = entry.first(&map.uid).map(str::to_string)?;
    let email = map
        .email
        .as_deref()
        .and_then(|a| entry.first(a))
        .map(str::to_string);
    let given = map
        .first_name
        .as_deref()
        .and_then(|a| entry.first(a))
        .map(str::to_string);
    let family = map
        .last_name
        .as_deref()
        .and_then(|a| entry.first(a))
        .map(str::to_string);

    let enabled = match map.user_account_control.as_deref().and_then(|a| entry.first(a)) {
        Some(s) => s.parse::<u32>().map(|v| (v & AD_ACCOUNT_DISABLED) == 0).unwrap_or(true),
        None => true,
    };

    let now = Utc::now();
    Some(User {
        realm_id,
        username,
        email,
        email_verified: false,
        name: Some(PersonName {
            given,
            family,
            ..PersonName::default()
        }),
        attributes: BTreeMap::new(),
        federation: Some(FederationLink {
            source_urn: provider_urn(alias),
            external_id,
            external_dn: Some(entry.dn.clone()),
            last_synced_at: Some(now),
        }),
        enabled,
        created_at: now,
        updated_at: now,
        ..User::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AttributeMap;
    use std::collections::BTreeMap;

    fn ad_map() -> AttributeMap {
        AttributeMap {
            username: "sAMAccountName".into(),
            email: Some("mail".into()),
            first_name: Some("givenName".into()),
            last_name: Some("sn".into()),
            uid: "objectGUID".into(),
            user_account_control: Some("userAccountControl".into()),
            extras: BTreeMap::new(),
        }
    }

    fn entry(vals: &[(&str, &str)]) -> EntryAttributes {
        EntryAttributes {
            dn: "CN=Padmé,DC=example".into(),
            values: vals
                .iter()
                .map(|(k, v)| ((*k).into(), vec![(*v).into()]))
                .collect(),
        }
    }

    #[test]
    fn case_insensitive_attribute_lookup() {
        let e = entry(&[("MAIL", "padme@example")]);
        assert_eq!(e.first("mail"), Some("padme@example"));
    }

    #[test]
    fn ad_disabled_bit_disables_user() {
        let e = entry(&[
            ("sAMAccountName", "padme"),
            ("objectGUID", "abc"),
            ("userAccountControl", "514"), // 512 (normal) | 2 (disabled)
        ]);
        let u = entry_to_user(RealmId::new(), "corp-ad", &ad_map(), &e).unwrap();
        assert!(!u.enabled);
    }

    #[test]
    fn normal_uac_keeps_user_enabled() {
        let e = entry(&[
            ("sAMAccountName", "padme"),
            ("objectGUID", "abc"),
            ("userAccountControl", "512"),
        ]);
        let u = entry_to_user(RealmId::new(), "corp-ad", &ad_map(), &e).unwrap();
        assert!(u.enabled);
    }

    #[test]
    fn missing_uid_skips_user() {
        // Without objectGUID we cannot mint a FederationLink — bail.
        let e = entry(&[("sAMAccountName", "padme")]);
        assert!(entry_to_user(RealmId::new(), "corp-ad", &ad_map(), &e).is_none());
    }

    #[test]
    fn federation_link_carries_dn_and_urn() {
        let e = entry(&[("sAMAccountName", "padme"), ("objectGUID", "abc")]);
        let u = entry_to_user(RealmId::new(), "corp-ad", &ad_map(), &e).unwrap();
        let link = u.federation.unwrap();
        assert_eq!(link.source_urn, "builtin:user-storage:ldap:corp-ad");
        assert_eq!(link.external_dn.as_deref(), Some("CN=Padmé,DC=example"));
    }
}
