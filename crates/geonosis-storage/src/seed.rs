//! One-shot bootstrap helpers that persist the v0.1 built-in
//! entities for a fresh realm.
//!
//! Per `docs/06-auth-flows.md` §"Built-in flows shipped" every realm
//! needs the seven canonical flow aliases installed before any
//! `/authorize` request can succeed: without `browser` the
//! interactive login path bails immediately with "realm has no
//! browser flow". The flow definitions themselves live in
//! `geonosis_flow::builtin`; this module is the storage-side
//! installer that pairs them with each new `RealmId`.
//!
//! The function is idempotent at the alias granularity: an existing
//! `(realm, alias)` row is skipped rather than overwritten so an
//! operator who hand-edited `browser` does not lose their
//! customisation on a server restart that re-runs the seeder.

use geonosis_core::RealmId;
use geonosis_flow::builtin;

use crate::error::StorageError;
use crate::traits::Storage;

/// Persist every v0.1 built-in flow into `storage` under `realm_id`.
/// Existing aliases are left untouched; only missing ones are
/// inserted. Returns the number of flows newly persisted.
pub async fn seed_default_flows(
    storage: &dyn Storage,
    realm_id: RealmId,
) -> Result<usize, StorageError> {
    let mut inserted = 0;
    for flow in builtin::v0_1_flows(realm_id) {
        match storage.get_auth_flow_by_alias(realm_id, &flow.alias).await {
            Ok(_) => continue,
            Err(StorageError::NotFound) => {
                storage.save_auth_flow(flow).await?;
                inserted += 1;
            }
            Err(other) => return Err(other),
        }
    }
    Ok(inserted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStorage;
    use chrono::Utc;
    use geonosis_core::Realm;

    async fn fixture_realm(storage: &MemoryStorage) -> RealmId {
        let now = Utc::now();
        let realm = Realm {
            id: RealmId::new(),
            slug: "test".into(),
            display_name: "Test".into(),
            frontend_url: None,
            admin_frontend_url: None,
            enabled: true,
            ssl_required: geonosis_core::SslRequirement::None,
            login: Default::default(),
            registration: Default::default(),
            session_policy: Default::default(),
            token_policy: Default::default(),
            brute_force: Default::default(),
            password_policy: Default::default(),
            otp_policy: Default::default(),
            webauthn_policy: Default::default(),
            acr_policy: Default::default(),
            sender_constraint_default: geonosis_core::SenderConstraint::None,
            theme_binding: Default::default(),
            localization: Default::default(),
            events: Default::default(),
            default_groups: vec![],
            default_roles: Default::default(),
            organizations_enabled: true,
            organization_policy: Default::default(),
            created_at: now,
            updated_at: now,
        };
        let id = realm.id;
        storage.create_realm(realm).await.unwrap();
        id
    }

    #[tokio::test]
    async fn seeding_installs_seven_flows_on_a_fresh_realm() {
        let storage = MemoryStorage::new();
        let realm_id = fixture_realm(&storage).await;
        let inserted = seed_default_flows(&storage, realm_id).await.unwrap();
        assert_eq!(inserted, 7);
        let flows = storage.list_auth_flows(realm_id).await.unwrap();
        let mut aliases: Vec<_> = flows.into_iter().map(|f| f.alias).collect();
        aliases.sort();
        assert_eq!(
            aliases,
            vec![
                "browser",
                "client-authentication",
                "direct-grant",
                "first-broker-login",
                "registration",
                "reset-credentials",
                "step-up",
            ]
        );
    }

    #[tokio::test]
    async fn seeding_is_idempotent_and_preserves_overrides() {
        let storage = MemoryStorage::new();
        let realm_id = fixture_realm(&storage).await;
        // First pass installs all seven.
        let first = seed_default_flows(&storage, realm_id).await.unwrap();
        assert_eq!(first, 7);
        // Second pass is a no-op: every alias already exists, nothing
        // is reinserted (so any operator-edited flow stays intact).
        let second = seed_default_flows(&storage, realm_id).await.unwrap();
        assert_eq!(second, 0);
        let flows = storage.list_auth_flows(realm_id).await.unwrap();
        assert_eq!(flows.len(), 7);
    }
}
