//! Storage trait.

use async_trait::async_trait;

use geonosis_core::{
    Client, ClientId, CodeGrant, CodeId, Realm, RealmId, RefreshToken, RefreshTokenId, Session,
    SessionId, TokenFamilyId, User, UserId,
};

use crate::error::StorageError;

/// Storage seam — every concrete backend implements this. v0.1 has one
/// in-memory backend; the Postgres backend lives behind the same trait.
#[async_trait]
pub trait Storage: Send + Sync {
    // ---- Realm ----
    async fn create_realm(&self, realm: Realm) -> Result<(), StorageError>;
    async fn get_realm(&self, id: RealmId) -> Result<Realm, StorageError>;
    async fn get_realm_by_slug(&self, slug: &str) -> Result<Realm, StorageError>;
    async fn update_realm(&self, realm: Realm) -> Result<(), StorageError>;
    async fn delete_realm(&self, id: RealmId) -> Result<(), StorageError>;
    async fn list_realms(&self) -> Result<Vec<Realm>, StorageError>;

    // ---- User ----
    async fn create_user(&self, user: User) -> Result<(), StorageError>;
    async fn get_user(&self, realm: RealmId, id: UserId) -> Result<User, StorageError>;
    async fn get_user_by_username(
        &self,
        realm: RealmId,
        username: &str,
    ) -> Result<User, StorageError>;
    async fn get_user_by_email(&self, realm: RealmId, email: &str) -> Result<User, StorageError>;
    async fn update_user(&self, user: User) -> Result<(), StorageError>;
    async fn delete_user(&self, realm: RealmId, id: UserId) -> Result<(), StorageError>;

    /// Credentials carry secrets — separate accessor so we can audit access.
    async fn store_password_hash(
        &self,
        realm: RealmId,
        user_id: UserId,
        phc_hash: String,
    ) -> Result<(), StorageError>;
    async fn get_password_hash(
        &self,
        realm: RealmId,
        user_id: UserId,
    ) -> Result<String, StorageError>;

    // ---- Client ----
    async fn create_client(&self, client: Client) -> Result<(), StorageError>;
    async fn get_client(&self, realm: RealmId, id: ClientId) -> Result<Client, StorageError>;
    async fn get_client_by_client_id(
        &self,
        realm: RealmId,
        client_id: &str,
    ) -> Result<Client, StorageError>;
    async fn update_client(&self, client: Client) -> Result<(), StorageError>;
    async fn delete_client(&self, realm: RealmId, id: ClientId) -> Result<(), StorageError>;
    async fn list_clients(&self, realm: RealmId) -> Result<Vec<Client>, StorageError>;

    /// Confidential clients store a hashed secret (BLAKE3-keyed). v0.1
    /// stores the realm-keyed hash; the plaintext secret is shown to admin
    /// at creation and never persisted.
    async fn store_client_secret_hash(
        &self,
        realm: RealmId,
        client_id: ClientId,
        secret_hash: String,
    ) -> Result<(), StorageError>;
    async fn get_client_secret_hash(
        &self,
        realm: RealmId,
        client_id: ClientId,
    ) -> Result<String, StorageError>;

    // ---- Session ----
    async fn create_session(&self, session: Session) -> Result<(), StorageError>;
    async fn get_session(&self, id: &SessionId) -> Result<Session, StorageError>;
    async fn update_session(&self, session: Session) -> Result<(), StorageError>;
    async fn delete_session(&self, id: &SessionId) -> Result<(), StorageError>;

    // ---- Code grant (single-use, 60s TTL) ----
    async fn save_code_grant(&self, grant: CodeGrant) -> Result<(), StorageError>;
    /// Atomically consume a code (deletes the row in the same query). Used
    /// at `/token` to enforce single-use semantics across pods.
    async fn consume_code(&self, code: &CodeId) -> Result<CodeGrant, StorageError>;

    // ---- Refresh token (rotation + family) ----
    async fn save_refresh_token(&self, token: RefreshToken) -> Result<(), StorageError>;
    async fn get_refresh_token(
        &self,
        id: &RefreshTokenId,
    ) -> Result<RefreshToken, StorageError>;
    async fn mark_refresh_used(&self, id: &RefreshTokenId) -> Result<(), StorageError>;
    /// Invalidate every token in a family — invoked when a previously-used
    /// refresh token is presented again (reuse detection).
    async fn revoke_token_family(&self, family: TokenFamilyId) -> Result<(), StorageError>;
}
