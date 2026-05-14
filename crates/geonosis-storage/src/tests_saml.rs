//! SAML-related storage tests.
//!
//! Lives in its own file so the persistence + idempotency contract
//! around `saml_persistent_id` stays scrutable. The same surface is
//! tested against the in-memory backend here; the Postgres impl
//! shares the trait so the contract carries across.

#[cfg(test)]
mod tests {
    use crate::{MemoryStorage, SamlPersistentIdRow, Storage};
    use chrono::Utc;
    use geonosis_core::id::{RealmId, UserId};

    #[tokio::test]
    async fn persistent_name_id_round_trips() {
        let storage = MemoryStorage::new();
        let realm = RealmId::new();
        let user = UserId::new();
        let row = SamlPersistentIdRow {
            realm_id: realm,
            user_id: user,
            sp_entity_id: "https://sp.example".into(),
            name_id: "g_AAAAA".into(),
            created_at: Utc::now(),
        };
        storage.save_saml_persistent_id(row.clone()).await.unwrap();
        let got = storage
            .get_saml_persistent_id(realm, user, "https://sp.example")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.name_id, "g_AAAAA");
    }

    #[tokio::test]
    async fn persistent_name_id_save_is_idempotent_first_writer_wins() {
        // Concurrent SSO requests from the same SP MUST NOT shift
        // the downstream NameID. Second save_saml_persistent_id with
        // a different name_id is a no-op.
        let storage = MemoryStorage::new();
        let realm = RealmId::new();
        let user = UserId::new();
        let sp = "https://sp.example";
        let first = SamlPersistentIdRow {
            realm_id: realm,
            user_id: user,
            sp_entity_id: sp.into(),
            name_id: "first".into(),
            created_at: Utc::now(),
        };
        let second = SamlPersistentIdRow {
            name_id: "second".into(),
            ..first.clone()
        };
        storage.save_saml_persistent_id(first).await.unwrap();
        storage.save_saml_persistent_id(second).await.unwrap();
        let got = storage
            .get_saml_persistent_id(realm, user, sp)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.name_id, "first");
    }

    #[tokio::test]
    async fn persistent_name_id_returns_none_when_unset() {
        let storage = MemoryStorage::new();
        let got = storage
            .get_saml_persistent_id(RealmId::new(), UserId::new(), "https://sp.example")
            .await
            .unwrap();
        assert!(got.is_none());
    }
}
