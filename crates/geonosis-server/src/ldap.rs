//! LDAP federation runtime — process-wide pool registry.
//!
//! Each `(realm_id, alias)` keeps a long-lived `LdapPool`. Config
//! updates are applied by `register_or_replace` which atomically
//! swaps the pool.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use geonosis_core::RealmId;
use geonosis_federation_ldap::{LdapFederationConfig, LdapPool};

#[derive(Default)]
pub struct LdapRuntime {
    inner: RwLock<HashMap<(RealmId, String), Arc<LdapPool>>>,
}

impl LdapRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pool(&self, realm: RealmId, alias: &str) -> Option<Arc<LdapPool>> {
        self.inner.read().get(&(realm, alias.to_string())).cloned()
    }

    pub fn register_or_replace(&self, cfg: LdapFederationConfig) -> Arc<LdapPool> {
        let key = (cfg.realm_id, cfg.alias.clone());
        let pool = Arc::new(LdapPool::new(cfg));
        self.inner.write().insert(key, pool.clone());
        pool
    }

    pub fn remove(&self, realm: RealmId, alias: &str) {
        self.inner.write().remove(&(realm, alias.to_string()));
    }

    pub fn aliases(&self, realm: RealmId) -> Vec<String> {
        let map = self.inner.read();
        map.keys()
            .filter(|(r, _)| *r == realm)
            .map(|(_, a)| a.clone())
            .collect()
    }
}
