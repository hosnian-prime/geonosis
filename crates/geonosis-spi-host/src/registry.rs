//! Provider registry.
//!
//! Stores `ProviderBinding` rows indexed by `(RealmId, WitInterfaceName)`,
//! priority-sorted descending. The registry itself does **not** dispatch
//! — it only knows about metadata + ordering + the `replaces` soft-disable
//! relation.
//!
//! Dispatch is two layers above:
//! 1. [`crate::router`] consumes the priority-sorted slice and applies
//!    the right shape per `DispatchMode` (first_match, named_select,
//!    chain, named_attach, fire_forget, first_decision).
//! 2. Interface-specific runtime wrappers (e.g. `WasmMapperRuntime`,
//!    upcoming `WasmAuthnRuntime`) take one provider at a time and
//!    actually call into the WASM component or built-in trait.
//!
//! Today (pre-B4) only the metadata layer is exercised by production
//! code. Once the WASM runtimes for the 7 remaining interfaces land,
//! every dispatcher (built-in + WASM) will consult `ProviderRegistry`
//! to decide what to invoke + in what order. That's why the registry
//! is rich (priority, capabilities, replaces) but unused at dispatch
//! time today: it's the data structure B4 dispatchers will read from.

use std::collections::HashMap;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use geonosis_core::id::{RealmId, SpiBindingId, WasmModuleId};

use crate::dispatch::WitInterfaceName;

/// Per-provider capability bitset. v0.1 user-storage providers commonly
/// declare `lookup` + `validate_credential`; mappers + event listeners
/// don't use this struct.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderCapabilities {
    pub lookup: bool,
    pub validate_credential: bool,
    pub write_users: bool,
    pub group_membership: bool,
    pub federated_groups: bool,
    pub passwordless: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderBinding {
    pub id: SpiBindingId,
    pub realm_id: RealmId,
    pub interface: WitInterfaceName,
    pub provider_urn: String,
    pub priority: i32,
    pub enabled: bool,
    pub config: serde_json::Value,
    /// URN of an existing built-in this binding replaces (soft-disable).
    pub replaces: Option<String>,
    pub capabilities: ProviderCapabilities,
    pub origin: ProviderOrigin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ProviderOrigin {
    Builtin,
    Wasm {
        module_id: WasmModuleId,
        alias: String,
    },
}

/// "I don't handle this" universal signal (LSP pivot point — every
/// user-storage provider returns this consistently for `NotFound`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupOutcome<T> {
    NotFound,
    Found(T),
}

#[derive(Default)]
pub struct ProviderRegistry {
    inner: RwLock<RegistryInner>,
}

#[derive(Default)]
struct RegistryInner {
    /// realm -> interface -> [bindings ordered by priority]
    by_iface: HashMap<(RealmId, WitInterfaceName), Vec<ProviderBinding>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, binding: ProviderBinding) {
        let key = (binding.realm_id, binding.interface.clone());
        let mut guard = self.inner.write();
        let v = guard.by_iface.entry(key).or_default();
        v.push(binding);
        // Stable-sort by descending priority — higher first.
        v.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    pub fn list(&self, realm: RealmId, interface: &WitInterfaceName) -> Vec<ProviderBinding> {
        self.inner
            .read()
            .by_iface
            .get(&(realm, interface.clone()))
            .cloned()
            .unwrap_or_default()
    }

    /// Return the first enabled binding for an interface that has not
    /// been `replaces`'d by a higher-priority sibling.
    pub fn first_enabled(
        &self,
        realm: RealmId,
        interface: &WitInterfaceName,
    ) -> Option<ProviderBinding> {
        let bindings = self.list(realm, interface);
        let replaced: std::collections::HashSet<String> = bindings
            .iter()
            .filter_map(|b| b.replaces.clone())
            .collect();
        bindings
            .into_iter()
            .find(|b| b.enabled && !replaced.contains(&b.provider_urn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn binding(urn: &str, priority: i32, replaces: Option<&str>, enabled: bool) -> ProviderBinding {
        ProviderBinding {
            id: SpiBindingId::new(),
            realm_id: RealmId::new(),
            interface: WitInterfaceName(WitInterfaceName::USER_STORAGE.into()),
            provider_urn: urn.into(),
            priority,
            enabled,
            config: json!({}),
            replaces: replaces.map(str::to_string),
            capabilities: ProviderCapabilities {
                lookup: true,
                validate_credential: true,
                ..Default::default()
            },
            origin: ProviderOrigin::Builtin,
        }
    }

    #[test]
    fn higher_priority_wins() {
        let r = ProviderRegistry::new();
        let realm = RealmId::new();
        let mut b1 = binding("builtin:user-storage:local", 100, None, true);
        b1.realm_id = realm;
        let mut b2 = binding("wasm:user-storage:rest", 200, None, true);
        b2.realm_id = realm;
        r.register(b1);
        r.register(b2);
        let chosen = r
            .first_enabled(realm, &WitInterfaceName(WitInterfaceName::USER_STORAGE.into()))
            .unwrap();
        assert_eq!(chosen.provider_urn, "wasm:user-storage:rest");
    }

    #[test]
    fn replaces_disables_lower_priority() {
        let r = ProviderRegistry::new();
        let realm = RealmId::new();
        let mut local = binding("builtin:user-storage:local", 100, None, true);
        local.realm_id = realm;
        let mut wasm_override = binding(
            "wasm:user-storage:rest",
            200,
            Some("builtin:user-storage:local"),
            true,
        );
        wasm_override.realm_id = realm;
        r.register(local);
        r.register(wasm_override);
        let chosen = r
            .first_enabled(realm, &WitInterfaceName(WitInterfaceName::USER_STORAGE.into()))
            .unwrap();
        assert_eq!(chosen.provider_urn, "wasm:user-storage:rest");
        // Local must be filtered out as "replaced".
        let all = r.list(realm, &WitInterfaceName(WitInterfaceName::USER_STORAGE.into()));
        let local_still_listed = all
            .iter()
            .any(|b| b.provider_urn == "builtin:user-storage:local");
        assert!(local_still_listed, "list reports both; first_enabled hides replaced");
    }

    #[test]
    fn disabled_provider_skipped() {
        let r = ProviderRegistry::new();
        let realm = RealmId::new();
        let mut b1 = binding("builtin:user-storage:local", 100, None, false);
        b1.realm_id = realm;
        r.register(b1);
        let chosen = r.first_enabled(realm, &WitInterfaceName(WitInterfaceName::USER_STORAGE.into()));
        assert!(chosen.is_none());
    }
}
