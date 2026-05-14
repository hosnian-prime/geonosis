//! Typed LDAP federation configuration.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use geonosis_core::id::{FederationId, RealmId};
use geonosis_core::secret::Secret;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapFederationConfig {
    pub id: FederationId,
    pub realm_id: RealmId,
    pub alias: String,
    /// Round-robin list of `ldap://` / `ldaps://` URLs.
    pub urls: Vec<String>,
    pub bind_dn: Option<String>,
    pub bind_password: Option<Secret<String>>,
    pub base_dn: String,
    pub user_object_classes: Vec<String>,
    /// LDAP filter with `{username}` placeholder, e.g.
    /// `(&(objectClass=user)(sAMAccountName={username}))`.
    pub user_filter: String,
    pub page_size: usize,
    pub referrals: ReferralPolicy,
    pub tls: TlsPolicy,
    pub attribute_map: AttributeMap,
    pub write_policy: WritePolicy,
    pub sync_policy: SyncPolicy,
    pub group_sync: Option<GroupSyncConfig>,
    /// SPI binding priority — lower binds higher in the chain.
    pub priority: i32,
    pub bind_timeout_ms: u64,
    pub search_timeout_ms: u64,
    /// Connections per source; doc default = 8.
    pub pool_size: u32,
    pub enabled: bool,
}

impl LdapFederationConfig {
    pub fn bind_timeout(&self) -> Duration {
        Duration::from_millis(self.bind_timeout_ms.max(100))
    }

    pub fn search_timeout(&self) -> Duration {
        Duration::from_millis(self.search_timeout_ms.max(100))
    }

    /// Render the user-lookup filter with the supplied username
    /// substituted into the `{username}` placeholder. The substitution
    /// is RFC 4515 escaped to defeat filter injection.
    pub fn render_user_filter(&self, username: &str) -> String {
        self.user_filter.replace("{username}", &escape_filter(username))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReferralPolicy {
    Follow,
    Ignore,
    Throw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsPolicy {
    None,
    StartTls,
    Ldaps,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttributeMap {
    pub username: String,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    /// LDAP attribute carrying the immutable external identifier
    /// (`entryUUID` on RFC 4530 servers, `objectGUID` on AD).
    pub uid: String,
    /// Optional `userAccountControl`-style attribute the ADd
    /// `disabled-bit` is derived from. v0.1 reads it iff `Some(_)`.
    pub user_account_control: Option<String>,
    pub extras: BTreeMap<String, String>,
}

impl AttributeMap {
    /// Every LDAP attribute that has to be returned from a search.
    /// Used by the `search` module to ask for the minimum set.
    pub fn request_attrs(&self) -> Vec<String> {
        let mut out = vec![self.uid.clone(), self.username.clone()];
        for v in [&self.email, &self.first_name, &self.last_name].into_iter().flatten() {
            out.push(v.clone());
        }
        if let Some(uac) = &self.user_account_control {
            out.push(uac.clone());
        }
        for v in self.extras.values() {
            out.push(v.clone());
        }
        out.sort();
        out.dedup();
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WritePolicy {
    ReadOnly,
    Writable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum SyncPolicy {
    /// Look up on demand at login (default).
    OnDemand,
    /// Background sync at a fixed cadence. v0.1 expresses cadence as
    /// minutes; cron expressions land in v0.1.x with the scheduler.
    Periodic {
        full_every_minutes: u32,
        incremental_every_minutes: u32,
        changed_attribute: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSyncConfig {
    pub group_object_classes: Vec<String>,
    pub group_filter: String,
    pub membership_attribute: String,
    pub group_name_attribute: String,
    pub create_missing_groups: bool,
}

/// Build the canonical URN advertised on the SPI registry.
pub fn provider_urn(alias: &str) -> String {
    format!("builtin:user-storage:ldap:{alias}")
}

/// RFC 4515 §3 LDAP filter escape — `*` `(` `)` `\` NUL become hex
/// escapes. Defeats filter injection from a user-supplied username.
pub fn escape_filter(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.as_bytes() {
        match *b {
            b'*' => out.push_str("\\2a"),
            b'(' => out.push_str("\\28"),
            b')' => out.push_str("\\29"),
            b'\\' => out.push_str("\\5c"),
            0x00 => out.push_str("\\00"),
            other if other.is_ascii() => out.push(other as char),
            // Non-ASCII bytes pass through; LDAPv3 expects UTF-8.
            other => out.push_str(&format!("\\{other:02x}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urn_includes_alias() {
        assert_eq!(provider_urn("corp-ad"), "builtin:user-storage:ldap:corp-ad");
    }

    #[test]
    fn filter_escape_blocks_injection() {
        // A username with `*` would otherwise widen the filter.
        assert_eq!(escape_filter("padme*"), "padme\\2a");
        assert_eq!(escape_filter("(admin)"), "\\28admin\\29");
    }

    #[test]
    fn render_user_filter_escapes_substitution() {
        let cfg = sample_config();
        let rendered = cfg.render_user_filter("padme*");
        assert!(rendered.ends_with("=padme\\2a))"));
        assert!(!rendered.contains("padme*"));
    }

    #[test]
    fn request_attrs_dedups() {
        let mut m = AttributeMap {
            username: "sAMAccountName".into(),
            email: Some("mail".into()),
            uid: "objectGUID".into(),
            ..AttributeMap::default()
        };
        m.extras.insert("extra".into(), "mail".into()); // collides with email.
        let v = m.request_attrs();
        assert_eq!(v.iter().filter(|a| a.as_str() == "mail").count(), 1);
    }

    fn sample_config() -> LdapFederationConfig {
        LdapFederationConfig {
            id: FederationId::new(),
            realm_id: RealmId::new(),
            alias: "corp-ad".into(),
            urls: vec!["ldaps://ad.example".into()],
            bind_dn: None,
            bind_password: None,
            base_dn: "DC=example,DC=corp".into(),
            user_object_classes: vec!["user".into()],
            user_filter: "(&(objectClass=user)(sAMAccountName={username}))".into(),
            page_size: 1000,
            referrals: ReferralPolicy::Ignore,
            tls: TlsPolicy::Ldaps,
            attribute_map: AttributeMap {
                username: "sAMAccountName".into(),
                email: Some("mail".into()),
                first_name: Some("givenName".into()),
                last_name: Some("sn".into()),
                uid: "objectGUID".into(),
                user_account_control: Some("userAccountControl".into()),
                extras: BTreeMap::new(),
            },
            write_policy: WritePolicy::ReadOnly,
            sync_policy: SyncPolicy::OnDemand,
            group_sync: None,
            priority: 100,
            bind_timeout_ms: 5_000,
            search_timeout_ms: 10_000,
            pool_size: 8,
            enabled: true,
        }
    }
}
