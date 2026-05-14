//! Broker runtime singletons hung off `AppState`.
//!
//! `BrokerRuntime` owns the OIDC discovery cache, the shared reqwest
//! client, and the canonical redirect-URI builder. Handlers reach in
//! through `AppState.broker` and never construct one of these
//! themselves.

use url::Url;

use geonosis_broker::oidc::DiscoveryCache;
use geonosis_core::Realm;

pub struct BrokerRuntime {
    pub discovery: DiscoveryCache,
}

impl Default for BrokerRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl BrokerRuntime {
    pub fn new() -> Self {
        Self {
            discovery: DiscoveryCache::new(),
        }
    }

    /// Build the canonical `/realms/{slug}/broker/{alias}/endpoint`
    /// callback URL used as redirect_uri (OIDC) and ACS (SAML).
    pub fn redirect_uri(&self, public_base: &Url, realm: &Realm, alias: &str) -> String {
        format!(
            "{}/realms/{}/broker/{}/endpoint",
            public_base.as_str().trim_end_matches('/'),
            realm.slug,
            alias,
        )
    }
}
