//! Refresh-token rotation + family reuse detection.

use std::sync::Arc;

use chrono::Utc;
use thiserror::Error;

use geonosis_core::{RefreshToken, RefreshTokenId, TokenFamilyId};
use geonosis_crypto::refresh_token_hash;
use geonosis_storage::Storage;

#[derive(Debug, Error)]
pub enum RefreshRotateError {
    #[error("token not found")]
    NotFound,
    #[error("token expired")]
    Expired,
    #[error("token reuse — family burned")]
    Reuse,
    #[error("storage: {0}")]
    Storage(String),
}

#[derive(Debug)]
pub enum RefreshOutcome {
    /// Token verified; caller should mint a new pair using `prior`. The
    /// returned struct carries the new (family-id, replacement token) the
    /// caller must save after minting.
    Ok { prior: RefreshToken },
}

/// Validate and mark-used. Detects reuse by family.
pub async fn validate_refresh(
    storage: &Arc<dyn Storage>,
    presented_secret: &str,
    realm_hash_key: &[u8; 32],
) -> Result<RefreshOutcome, RefreshRotateError> {
    let id = RefreshTokenId(refresh_token_hash(presented_secret, realm_hash_key));
    let tok = match storage.get_refresh_token(&id).await {
        Ok(t) => t,
        Err(_) => return Err(RefreshRotateError::NotFound),
    };
    if tok.expires_at < Utc::now() {
        return Err(RefreshRotateError::Expired);
    }
    if tok.used {
        // Reuse detected — burn the entire family.
        storage
            .revoke_token_family(tok.family_id)
            .await
            .map_err(|e| RefreshRotateError::Storage(e.to_string()))?;
        return Err(RefreshRotateError::Reuse);
    }
    Ok(RefreshOutcome::Ok { prior: tok })
}

/// Mark the prior token as used and persist the replacement.
///
/// The caller (token endpoint) is responsible for constructing the
/// replacement `RefreshToken` (signing, expiry, etc.) and passing it in.
pub async fn rotate_refresh_token(
    storage: &Arc<dyn Storage>,
    prior: &RefreshToken,
    replacement: RefreshToken,
) -> Result<(), RefreshRotateError> {
    debug_assert_eq!(
        prior.family_id, replacement.family_id,
        "replacement must keep the same family_id (rotation, not new family)"
    );
    storage
        .mark_refresh_used(&prior.id)
        .await
        .map_err(|e| RefreshRotateError::Storage(e.to_string()))?;
    storage
        .save_refresh_token(replacement)
        .await
        .map_err(|e| RefreshRotateError::Storage(e.to_string()))?;
    Ok(())
}

/// Convenience helper for creating fresh `TokenFamilyId` at first issuance.
pub fn new_family() -> TokenFamilyId {
    TokenFamilyId::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use geonosis_core::{ClientId, RealmId, SessionId, UserId};
    use geonosis_storage::MemoryStorage;

    fn token(family: TokenFamilyId, key: &[u8; 32], secret: &str) -> RefreshToken {
        RefreshToken {
            id: RefreshTokenId(refresh_token_hash(secret, key)),
            family_id: family,
            realm_id: RealmId::new(),
            client_id: ClientId::new(),
            user_id: UserId::new(),
            session_id: SessionId::new_random(),
            scope: vec![],
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(60),
            used: false,
        }
    }

    #[tokio::test]
    async fn validate_succeeds_for_fresh_token() {
        let s: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let key = [3u8; 32];
        let fam = new_family();
        let secret = "secret-A";
        s.save_refresh_token(token(fam, &key, secret)).await.unwrap();
        let out = validate_refresh(&s, secret, &key).await.unwrap();
        match out {
            RefreshOutcome::Ok { prior } => assert_eq!(prior.family_id, fam),
        }
    }

    #[tokio::test]
    async fn reuse_detection_burns_family() {
        let s: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let key = [5u8; 32];
        let fam = new_family();
        // Two tokens in the same family — older one is marked used.
        let mut t1 = token(fam, &key, "secret-1");
        t1.used = true;
        let t2 = token(fam, &key, "secret-2");
        s.save_refresh_token(t1).await.unwrap();
        s.save_refresh_token(t2).await.unwrap();

        // Presenting the already-used token MUST burn the family.
        let err = validate_refresh(&s, "secret-1", &key).await.unwrap_err();
        assert!(matches!(err, RefreshRotateError::Reuse));

        // Now t2 should also be gone.
        let again = validate_refresh(&s, "secret-2", &key).await.unwrap_err();
        assert!(matches!(again, RefreshRotateError::NotFound));
    }

    #[tokio::test]
    async fn expired_token_rejected() {
        let s: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let key = [7u8; 32];
        let fam = new_family();
        let mut t = token(fam, &key, "old");
        t.expires_at = Utc::now() - Duration::seconds(60);
        s.save_refresh_token(t).await.unwrap();
        let err = validate_refresh(&s, "old", &key).await.unwrap_err();
        assert!(matches!(err, RefreshRotateError::Expired));
    }

    #[tokio::test]
    async fn rotation_preserves_family() {
        let s: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let key = [11u8; 32];
        let fam = new_family();
        let prior = token(fam, &key, "first");
        s.save_refresh_token(prior.clone()).await.unwrap();
        let replacement = token(fam, &key, "second");
        rotate_refresh_token(&s, &prior, replacement.clone()).await.unwrap();
        // Old is marked used.
        let p = s.get_refresh_token(&prior.id).await.unwrap();
        assert!(p.used);
        // New is fresh.
        let r = s.get_refresh_token(&replacement.id).await.unwrap();
        assert!(!r.used);
        assert_eq!(r.family_id, fam);
    }
}
