//! LDAP / Active Directory user federation provider.
//!
//! Per `docs/04-federation-ldap.md`:
//! - Three modes: pass-through bind, mirror-on-demand, full sync
//! - URN: `builtin:user-storage:ldap:{alias}`
//! - AD tombstone-as-disable handling
//!
//! The bind / search / sync surface is wired in `geonosis-server`. This
//! crate provides the strongly-typed config + mapping helpers; the actual
//! ldap3 invocations live behind feature `ldap-runtime`, deferred until
//! we land integration tests with a real LDAP fixture.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use geonosis_core::id::{FederationId, RealmId};
use geonosis_core::secret::Secret;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapFederationConfig {
    pub id: FederationId,
    pub realm_id: RealmId,
    pub alias: String,
    pub urls: Vec<String>,
    pub bind_dn: Option<String>,
    pub bind_password: Option<Secret<String>>,
    pub base_dn: String,
    pub user_object_classes: Vec<String>,
    pub user_filter: String,
    pub page_size: usize,
    pub tls: TlsPolicy,
    pub attribute_map: AttributeMap,
    pub write_policy: WritePolicy,
    pub sync_policy: SyncPolicy,
    pub priority: i32,
    pub enabled: bool,
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
    pub uid: String,
    pub extras: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WritePolicy {
    ReadOnly,
    Writable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SyncPolicy {
    /// Look up on demand at login.
    OnDemand,
    /// Background sync every N minutes.
    Periodic { minutes: u32 },
}

/// Build the canonical URN advertised on the SPI registry.
pub fn provider_urn(alias: &str) -> String {
    format!("builtin:user-storage:ldap:{alias}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urn_includes_alias() {
        assert_eq!(provider_urn("corp-ad"), "builtin:user-storage:ldap:corp-ad");
    }
}
