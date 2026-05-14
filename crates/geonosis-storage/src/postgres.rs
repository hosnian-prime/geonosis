//! Postgres backend for `Storage` (feature-gated).
//!
//! Design choices (documented inline):
//! - **RLS-first**: every tenanted query opens a transaction, calls
//!   `set_realm_scope`, and only then runs the real query. The
//!   application-layer `WHERE realm_id = $1` predicate is kept as
//!   defense-in-depth so an accidentally-unscoped query still filters.
//! - **Hybrid schema**: each table has indexed columns for the values
//!   we filter / sort on, plus a `config` JSONB column for the rest
//!   of the entity. Keeps v0.1 schema short; v0.2 promotes hot fields.
//! - **Atomic code consumption**: `consume_code` is `DELETE ...
//!   RETURNING *` so a re-presentation across pods can't double-spend.
//! - **Refresh-token family revocation**: one-shot
//!   `DELETE FROM refresh_token WHERE family_id = $1`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;
use sqlx::Row;

use geonosis_broker::{BrokerAuthnState, BrokerLink, IdentityProvider};
use geonosis_core::{
    Agent, Client, ClientId, CodeGrant, CodeId, Group, GroupId, OrgConsentPolicy, OrgDomain,
    OrgInvitation, OrgMembership, OrgRole, Organization, OrganizationId, Realm, RealmId,
    RefreshToken, RefreshTokenId, Role, RoleId, Session, SessionId, TokenFamilyId, User, UserId,
    UserProfile,
};
use geonosis_core::id::{AgentId, OrgInvitationId, OrgRoleId};
use geonosis_federation_ldap::LdapFederationConfig;

use crate::error::StorageError;
use crate::traits::{
    ConsentGrant, DeviceGrant, DeviceGrantStatus, FlowStateRow, OrgIdpBinding, ParRequest,
    SpiBindingRow, Storage, WasmModule, WasmModuleHeader,
};

pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

fn sqlx_err(e: sqlx::Error) -> StorageError {
    match &e {
        sqlx::Error::RowNotFound => StorageError::NotFound,
        sqlx::Error::Database(db) if db.constraint().is_some() => {
            StorageError::Conflict(db.message().to_string())
        }
        _ => StorageError::Backend(e.to_string()),
    }
}

fn json_err(e: serde_json::Error) -> StorageError {
    StorageError::Backend(format!("json: {e}"))
}

fn invalid_id(e: geonosis_core::id::IdParseError) -> StorageError {
    StorageError::Invalid(e.to_string())
}

/// Begin a transaction scoped to a specific realm. Every tenanted
/// method opens one of these so the `tenant_isolation` RLS policy can
/// match `current_setting('geonosis.realm_id', true)`.
async fn begin_realm<'a>(
    pool: &'a PgPool,
    realm: RealmId,
) -> Result<sqlx::Transaction<'a, sqlx::Postgres>, StorageError> {
    let mut tx = pool.begin().await.map_err(sqlx_err)?;
    sqlx::query("SELECT set_config('geonosis.realm_id', $1, true)")
        .bind(realm.to_string())
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
    Ok(tx)
}

fn client_kind_as_str(k: geonosis_core::ClientKind) -> &'static str {
    use geonosis_core::ClientKind::*;
    match k {
        Confidential => "confidential",
        Public => "public",
        BearerOnly => "bearer-only",
        ServiceAccount => "service-account",
        SamlServiceProvider => "saml-service-provider",
        ScimClient => "scim-client",
    }
}

fn realm_from_row(row: &sqlx::postgres::PgRow) -> Result<Realm, StorageError> {
    let config: serde_json::Value = row.try_get("config").map_err(sqlx_err)?;
    serde_json::from_value(config).map_err(json_err)
}

fn client_from_row(row: &sqlx::postgres::PgRow) -> Result<Client, StorageError> {
    let config: serde_json::Value = row.try_get("config").map_err(sqlx_err)?;
    serde_json::from_value(config).map_err(json_err)
}

fn user_from_row(row: &sqlx::postgres::PgRow) -> Result<User, StorageError> {
    let id_s: String = row.try_get("id").map_err(sqlx_err)?;
    let realm_id_s: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let username: String = row.try_get("username").map_err(sqlx_err)?;
    let email: Option<String> = row.try_get("email").map_err(sqlx_err)?;
    let email_verified: bool = row.try_get("email_verified").map_err(sqlx_err)?;
    let name: Option<serde_json::Value> = row.try_get("name").map_err(sqlx_err)?;
    let attributes: serde_json::Value = row.try_get("attributes").map_err(sqlx_err)?;
    let required_actions: serde_json::Value = row.try_get("required_actions").map_err(sqlx_err)?;
    let required_flow: Option<String> = row.try_get("required_flow").map_err(sqlx_err)?;
    let organizations: serde_json::Value = row.try_get("organizations").map_err(sqlx_err)?;
    let enabled: bool = row.try_get("enabled").map_err(sqlx_err)?;
    let failed_attempts: i32 = row.try_get("failed_attempts").map_err(sqlx_err)?;
    let locked_until: Option<DateTime<Utc>> = row.try_get("locked_until").map_err(sqlx_err)?;
    let last_failed_at: Option<DateTime<Utc>> = row.try_get("last_failed_at").map_err(sqlx_err)?;
    let created_at: DateTime<Utc> = row.try_get("created_at").map_err(sqlx_err)?;
    let updated_at: DateTime<Utc> = row.try_get("updated_at").map_err(sqlx_err)?;

    Ok(User {
        id: id_s.parse().map_err(invalid_id)?,
        realm_id: realm_id_s.parse().map_err(invalid_id)?,
        username,
        email,
        email_verified,
        name: name
            .map(serde_json::from_value::<geonosis_core::PersonName>)
            .transpose()
            .map_err(json_err)?,
        credentials: vec![],
        federation: None,
        attributes: serde_json::from_value(attributes).map_err(json_err)?,
        required_actions: serde_json::from_value(required_actions).map_err(json_err)?,
        required_flow,
        organizations: serde_json::from_value(organizations).map_err(json_err)?,
        enabled,
        failed_attempts: failed_attempts.max(0) as u32,
        locked_until,
        last_failed_at,
        created_at,
        updated_at,
    })
}

#[async_trait]
impl Storage for PostgresStorage {
    async fn ping(&self) -> Result<(), StorageError> {
        // Cheapest possible round-trip — the planner caches `SELECT 1`
        // and the pool keeps the connection warm. We rely on
        // sqlx::Pool's `test_before_acquire` (set in build_pool) to
        // also exercise the socket, so a transient network failure
        // surfaces here before any real query runs.
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
        Ok(())
    }

    // ---- Realm (no RLS — realm IS the tenant) ----
    async fn create_realm(&self, realm: Realm) -> Result<(), StorageError> {
        let config = serde_json::to_value(&realm).map_err(json_err)?;
        sqlx::query(
            "INSERT INTO realm (id, slug, display_name, enabled, config, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(realm.id.to_string())
        .bind(&realm.slug)
        .bind(&realm.display_name)
        .bind(realm.enabled)
        .bind(&config)
        .bind(realm.created_at)
        .bind(realm.updated_at)
        .execute(&self.pool)
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_realm(&self, id: RealmId) -> Result<Realm, StorageError> {
        let row = sqlx::query("SELECT config FROM realm WHERE id = $1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        realm_from_row(&row)
    }

    async fn get_realm_by_slug(&self, slug: &str) -> Result<Realm, StorageError> {
        let row = sqlx::query("SELECT config FROM realm WHERE slug = $1")
            .bind(slug)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        realm_from_row(&row)
    }

    async fn update_realm(&self, realm: Realm) -> Result<(), StorageError> {
        let config = serde_json::to_value(&realm).map_err(json_err)?;
        let rows = sqlx::query(
            "UPDATE realm SET slug = $2, display_name = $3, enabled = $4, config = $5,
                              updated_at = $6
             WHERE id = $1",
        )
        .bind(realm.id.to_string())
        .bind(&realm.slug)
        .bind(&realm.display_name)
        .bind(realm.enabled)
        .bind(&config)
        .bind(realm.updated_at)
        .execute(&self.pool)
        .await
        .map_err(sqlx_err)?
        .rows_affected();
        if rows == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    async fn delete_realm(&self, id: RealmId) -> Result<(), StorageError> {
        let rows = sqlx::query("DELETE FROM realm WHERE id = $1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?
            .rows_affected();
        if rows == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    async fn list_realms(&self) -> Result<Vec<Realm>, StorageError> {
        let rows = sqlx::query("SELECT config FROM realm")
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
        rows.iter().map(realm_from_row).collect()
    }

    // ---- User ----
    async fn create_user(&self, user: User) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, user.realm_id).await?;
        let name_json = user
            .name
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(json_err)?;
        sqlx::query(
            "INSERT INTO app_user (
                id, realm_id, username, username_lc, email, email_lc, email_verified,
                name, attributes, required_actions, required_flow, organizations, enabled,
                failed_attempts, locked_until, last_failed_at, created_at, updated_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)",
        )
        .bind(user.id.to_string())
        .bind(user.realm_id.to_string())
        .bind(&user.username)
        .bind(user.username.to_lowercase())
        .bind(user.email.as_deref())
        .bind(user.email.as_deref().map(str::to_lowercase))
        .bind(user.email_verified)
        .bind(name_json)
        .bind(serde_json::to_value(&user.attributes).map_err(json_err)?)
        .bind(serde_json::to_value(&user.required_actions).map_err(json_err)?)
        .bind(user.required_flow.as_deref())
        .bind(serde_json::to_value(&user.organizations).map_err(json_err)?)
        .bind(user.enabled)
        .bind(user.failed_attempts as i32)
        .bind(user.locked_until)
        .bind(user.last_failed_at)
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_user(&self, realm: RealmId, id: UserId) -> Result<User, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query("SELECT * FROM app_user WHERE id = $1 AND realm_id = $2")
            .bind(id.to_string())
            .bind(realm.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        let u = user_from_row(&row)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(u)
    }

    async fn get_user_by_username(
        &self,
        realm: RealmId,
        username: &str,
    ) -> Result<User, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query("SELECT * FROM app_user WHERE realm_id = $1 AND username_lc = $2")
            .bind(realm.to_string())
            .bind(username.to_lowercase())
            .fetch_optional(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        let u = user_from_row(&row)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(u)
    }

    async fn get_user_by_email(
        &self,
        realm: RealmId,
        email: &str,
    ) -> Result<User, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query("SELECT * FROM app_user WHERE realm_id = $1 AND email_lc = $2")
            .bind(realm.to_string())
            .bind(email.to_lowercase())
            .fetch_optional(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        let u = user_from_row(&row)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(u)
    }

    async fn update_user(&self, user: User) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, user.realm_id).await?;
        let name_json = user
            .name
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(json_err)?;
        let rows = sqlx::query(
            "UPDATE app_user SET
                username = $2, username_lc = $3, email = $4, email_lc = $5,
                email_verified = $6, name = $7, attributes = $8,
                required_actions = $9, required_flow = $10, organizations = $11,
                enabled = $12, failed_attempts = $13, locked_until = $14,
                last_failed_at = $15, updated_at = now()
             WHERE id = $1 AND realm_id = $16",
        )
        .bind(user.id.to_string())
        .bind(&user.username)
        .bind(user.username.to_lowercase())
        .bind(user.email.as_deref())
        .bind(user.email.as_deref().map(str::to_lowercase))
        .bind(user.email_verified)
        .bind(name_json)
        .bind(serde_json::to_value(&user.attributes).map_err(json_err)?)
        .bind(serde_json::to_value(&user.required_actions).map_err(json_err)?)
        .bind(user.required_flow.as_deref())
        .bind(serde_json::to_value(&user.organizations).map_err(json_err)?)
        .bind(user.enabled)
        .bind(user.failed_attempts as i32)
        .bind(user.locked_until)
        .bind(user.last_failed_at)
        .bind(user.realm_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .rows_affected();
        if rows == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn delete_user(&self, realm: RealmId, id: UserId) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query("DELETE FROM app_user WHERE id = $1 AND realm_id = $2")
            .bind(id.to_string())
            .bind(realm.to_string())
            .execute(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .rows_affected();
        if rows == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn store_password_hash(
        &self,
        realm: RealmId,
        user_id: UserId,
        phc_hash: String,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        sqlx::query(
            "INSERT INTO credential (id, realm_id, user_id, kind, secret_data)
             VALUES ($1, $2, $3, 'password', $4)
             ON CONFLICT (id) DO UPDATE SET secret_data = EXCLUDED.secret_data",
        )
        .bind(format!("c-pwd-{user_id}"))
        .bind(realm.to_string())
        .bind(user_id.to_string())
        .bind(phc_hash.as_bytes())
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_password_hash(
        &self,
        realm: RealmId,
        user_id: UserId,
    ) -> Result<String, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query(
            "SELECT secret_data FROM credential
             WHERE realm_id = $1 AND user_id = $2 AND kind = 'password' LIMIT 1",
        )
        .bind(realm.to_string())
        .bind(user_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .ok_or(StorageError::NotFound)?;
        let bytes: Vec<u8> = row.try_get("secret_data").map_err(sqlx_err)?;
        let s = String::from_utf8(bytes).map_err(|e| StorageError::Backend(e.to_string()))?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(s)
    }

    // ---- Client ----
    async fn create_client(&self, client: Client) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, client.realm_id).await?;
        let config = serde_json::to_value(&client).map_err(json_err)?;
        sqlx::query(
            "INSERT INTO client (id, realm_id, client_id, display_name, kind, config,
                                 enabled, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(client.id.to_string())
        .bind(client.realm_id.to_string())
        .bind(&client.client_id)
        .bind(client.display_name.as_deref())
        .bind(client_kind_as_str(client.kind))
        .bind(&config)
        .bind(client.enabled)
        .bind(client.created_at)
        .bind(client.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_client(&self, realm: RealmId, id: ClientId) -> Result<Client, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query("SELECT config FROM client WHERE id = $1 AND realm_id = $2")
            .bind(id.to_string())
            .bind(realm.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        let c = client_from_row(&row)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(c)
    }

    async fn get_client_by_client_id(
        &self,
        realm: RealmId,
        client_id: &str,
    ) -> Result<Client, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query("SELECT config FROM client WHERE realm_id = $1 AND client_id = $2")
            .bind(realm.to_string())
            .bind(client_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        let c = client_from_row(&row)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(c)
    }

    async fn update_client(&self, client: Client) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, client.realm_id).await?;
        let config = serde_json::to_value(&client).map_err(json_err)?;
        let rows = sqlx::query(
            "UPDATE client SET
                client_id = $2, display_name = $3, kind = $4, config = $5,
                enabled = $6, updated_at = now()
             WHERE id = $1 AND realm_id = $7",
        )
        .bind(client.id.to_string())
        .bind(&client.client_id)
        .bind(client.display_name.as_deref())
        .bind(client_kind_as_str(client.kind))
        .bind(&config)
        .bind(client.enabled)
        .bind(client.realm_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .rows_affected();
        if rows == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn delete_client(&self, realm: RealmId, id: ClientId) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query("DELETE FROM client WHERE id = $1 AND realm_id = $2")
            .bind(id.to_string())
            .bind(realm.to_string())
            .execute(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .rows_affected();
        if rows == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn list_clients(&self, realm: RealmId) -> Result<Vec<Client>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query("SELECT config FROM client WHERE realm_id = $1")
            .bind(realm.to_string())
            .fetch_all(&mut *tx)
            .await
            .map_err(sqlx_err)?;
        let out: Result<Vec<_>, _> = rows.iter().map(client_from_row).collect();
        tx.commit().await.map_err(sqlx_err)?;
        out
    }

    async fn store_client_secret_hash(
        &self,
        realm: RealmId,
        client_id: ClientId,
        secret_hash: String,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        sqlx::query("UPDATE client SET client_secret_hash = $1 WHERE id = $2 AND realm_id = $3")
            .bind(&secret_hash)
            .bind(client_id.to_string())
            .bind(realm.to_string())
            .execute(&mut *tx)
            .await
            .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_client_secret_hash(
        &self,
        realm: RealmId,
        client_id: ClientId,
    ) -> Result<String, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row =
            sqlx::query("SELECT client_secret_hash FROM client WHERE id = $1 AND realm_id = $2")
                .bind(client_id.to_string())
                .bind(realm.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(sqlx_err)?
                .ok_or(StorageError::NotFound)?;
        let h: Option<String> = row.try_get("client_secret_hash").map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        h.ok_or(StorageError::NotFound)
    }

    // ---- Session ----
    async fn create_session(&self, session: Session) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, session.realm_id).await?;
        sqlx::query(
            "INSERT INTO session (id, realm_id, user_id, authn_level, idp_alias,
                                  started_at, last_seen_at, expires_at, clients)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(&session.id.0)
        .bind(session.realm_id.to_string())
        .bind(session.user_id.to_string())
        .bind(authn_level_to_str(session.authn_level))
        .bind(session.idp_alias.as_deref())
        .bind(session.started_at)
        .bind(session.last_seen_at)
        .bind(session.expires_at)
        .bind(serde_json::to_value(&session.clients).map_err(json_err)?)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_session(&self, id: &SessionId) -> Result<Session, StorageError> {
        // Session lookup is realm-agnostic at this layer; RLS denies
        // cross-realm read once the caller binds a realm. Sessions get
        // a global lookup by id then the handler verifies realm_id.
        let row = sqlx::query("SELECT * FROM session WHERE id = $1")
            .bind(&id.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        session_from_row(&row)
    }

    async fn update_session(&self, session: Session) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, session.realm_id).await?;
        let rows = sqlx::query(
            "UPDATE session SET authn_level = $2, idp_alias = $3, last_seen_at = $4,
                                expires_at = $5, clients = $6
             WHERE id = $1",
        )
        .bind(&session.id.0)
        .bind(authn_level_to_str(session.authn_level))
        .bind(session.idp_alias.as_deref())
        .bind(session.last_seen_at)
        .bind(session.expires_at)
        .bind(serde_json::to_value(&session.clients).map_err(json_err)?)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .rows_affected();
        if rows == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn delete_session(&self, id: &SessionId) -> Result<(), StorageError> {
        let rows = sqlx::query("DELETE FROM session WHERE id = $1")
            .bind(&id.0)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?
            .rows_affected();
        if rows == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    // ---- Code grant ----
    async fn save_code_grant(&self, grant: CodeGrant) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, grant.realm_id).await?;
        sqlx::query(
            "INSERT INTO code_grant (
                code, realm_id, client_id, user_id, session_id, scope, redirect_uri,
                code_challenge, nonce, state, amr, auth_time, created_at, expires_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
        )
        .bind(&grant.code.0)
        .bind(grant.realm_id.to_string())
        .bind(grant.client_id.to_string())
        .bind(grant.user_id.to_string())
        .bind(&grant.session_id.0)
        .bind(serde_json::to_value(&grant.scope).map_err(json_err)?)
        .bind(grant.redirect_uri.as_str())
        .bind(
            grant
                .code_challenge
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(json_err)?,
        )
        .bind(grant.nonce.as_deref())
        .bind(grant.state.as_deref())
        .bind(serde_json::to_value(&grant.amr).map_err(json_err)?)
        .bind(grant.auth_time)
        .bind(grant.created_at)
        .bind(grant.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn consume_code(&self, code: &CodeId) -> Result<CodeGrant, StorageError> {
        let row = sqlx::query("DELETE FROM code_grant WHERE code = $1 RETURNING *")
            .bind(&code.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        code_grant_from_row(&row)
    }

    // ---- Refresh token ----
    async fn save_refresh_token(&self, token: RefreshToken) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, token.realm_id).await?;
        sqlx::query(
            "INSERT INTO refresh_token (
                id, family_id, realm_id, client_id, user_id, session_id, scope,
                issued_at, expires_at, used
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(&token.id.0)
        .bind(token.family_id.to_string())
        .bind(token.realm_id.to_string())
        .bind(token.client_id.to_string())
        .bind(token.user_id.to_string())
        .bind(&token.session_id.0)
        .bind(serde_json::to_value(&token.scope).map_err(json_err)?)
        .bind(token.issued_at)
        .bind(token.expires_at)
        .bind(token.used)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_refresh_token(
        &self,
        id: &RefreshTokenId,
    ) -> Result<RefreshToken, StorageError> {
        let row = sqlx::query("SELECT * FROM refresh_token WHERE id = $1")
            .bind(&id.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        refresh_from_row(&row)
    }

    async fn mark_refresh_used(&self, id: &RefreshTokenId) -> Result<(), StorageError> {
        let rows = sqlx::query("UPDATE refresh_token SET used = TRUE WHERE id = $1")
            .bind(&id.0)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?
            .rows_affected();
        if rows == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    async fn revoke_token_family(&self, family: TokenFamilyId) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM refresh_token WHERE family_id = $1")
            .bind(family.to_string())
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?;
        Ok(())
    }

    // ---- PAR ----
    async fn save_par_request(&self, par: ParRequest) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, par.realm_id).await?;
        sqlx::query(
            "INSERT INTO par_request (request_uri, realm_id, client_id, params,
                                      created_at, expires_at)
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(&par.request_uri)
        .bind(par.realm_id.to_string())
        .bind(par.client_id.to_string())
        .bind(serde_json::to_value(&par.params).map_err(json_err)?)
        .bind(par.created_at)
        .bind(par.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn consume_par_request(&self, request_uri: &str) -> Result<ParRequest, StorageError> {
        let row = sqlx::query("DELETE FROM par_request WHERE request_uri = $1 RETURNING *")
            .bind(request_uri)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        par_from_row(&row)
    }

    // ---- Device grant ----
    async fn save_device_grant(&self, grant: DeviceGrant) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, grant.realm_id).await?;
        sqlx::query(
            "INSERT INTO device_grant (device_code, user_code, realm_id, client_id, scope,
                                       interval_seconds, status, user_id, session_id,
                                       created_at, expires_at, last_polled_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(&grant.device_code)
        .bind(&grant.user_code)
        .bind(grant.realm_id.to_string())
        .bind(grant.client_id.to_string())
        .bind(serde_json::to_value(&grant.scope).map_err(json_err)?)
        .bind(grant.interval_seconds as i32)
        .bind(device_status_to_str(grant.status))
        .bind(grant.user_id.map(|u| u.to_string()))
        .bind(grant.session_id.as_ref().map(|s| s.0.clone()))
        .bind(grant.created_at)
        .bind(grant.expires_at)
        .bind(grant.last_polled_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_device_grant_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<DeviceGrant, StorageError> {
        let row = sqlx::query("SELECT * FROM device_grant WHERE device_code = $1")
            .bind(device_code)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        device_from_row(&row)
    }

    async fn get_device_grant_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<DeviceGrant, StorageError> {
        let row = sqlx::query("SELECT * FROM device_grant WHERE user_code = $1")
            .bind(user_code)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        device_from_row(&row)
    }

    async fn update_device_grant(&self, grant: DeviceGrant) -> Result<(), StorageError> {
        let rows = sqlx::query(
            "UPDATE device_grant SET status = $2, user_id = $3, session_id = $4,
                                     last_polled_at = $5
             WHERE device_code = $1",
        )
        .bind(&grant.device_code)
        .bind(device_status_to_str(grant.status))
        .bind(grant.user_id.map(|u| u.to_string()))
        .bind(grant.session_id.as_ref().map(|s| s.0.clone()))
        .bind(grant.last_polled_at)
        .execute(&self.pool)
        .await
        .map_err(sqlx_err)?
        .rows_affected();
        if rows == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    async fn delete_device_grant(&self, device_code: &str) -> Result<(), StorageError> {
        let rows = sqlx::query("DELETE FROM device_grant WHERE device_code = $1")
            .bind(device_code)
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?
            .rows_affected();
        if rows == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    // ---- Flow state ----
    async fn save_flow_state(&self, state: FlowStateRow) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, state.state.realm_id).await?;
        sqlx::query(
            "INSERT INTO flow_state (id, realm_id, flow_id, flow_version, current_node,
                                     history, context, authorize_params,
                                     started_at, last_activity_at, expires_at, csrf_token)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
             ON CONFLICT (id) DO UPDATE SET
                current_node = EXCLUDED.current_node,
                history = EXCLUDED.history,
                context = EXCLUDED.context,
                authorize_params = EXCLUDED.authorize_params,
                last_activity_at = EXCLUDED.last_activity_at,
                expires_at = EXCLUDED.expires_at",
        )
        .bind(state.state.id.to_string())
        .bind(state.state.realm_id.to_string())
        .bind(state.state.flow_id.to_string())
        .bind(state.state.flow_version)
        .bind(state.state.current_node.to_string())
        .bind(serde_json::to_value(&state.state.history).map_err(json_err)?)
        .bind(serde_json::to_value(&state.state.context).map_err(json_err)?)
        .bind(serde_json::to_value(&state.authorize_params).map_err(json_err)?)
        .bind(state.state.started_at)
        .bind(state.state.last_activity_at)
        .bind(state.state.expires_at)
        .bind(&state.state.csrf_token.0)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_flow_state(
        &self,
        id: &geonosis_core::FlowStateId,
    ) -> Result<FlowStateRow, StorageError> {
        let row = sqlx::query("SELECT * FROM flow_state WHERE id = $1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        flow_state_from_row(&row)
    }

    async fn delete_flow_state(
        &self,
        id: &geonosis_core::FlowStateId,
    ) -> Result<(), StorageError> {
        let rows = sqlx::query("DELETE FROM flow_state WHERE id = $1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?
            .rows_affected();
        if rows == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    // ---- Auth flow definitions ----
    async fn save_auth_flow(
        &self,
        flow: geonosis_flow::FlowDefinition,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, flow.realm_id).await?;
        let graph = serde_json::to_value(&flow).map_err(json_err)?;
        sqlx::query(
            "INSERT INTO auth_flow (id, realm_id, alias, display_name, version, graph, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, now())",
        )
        .bind(flow.id.to_string())
        .bind(flow.realm_id.to_string())
        .bind(&flow.alias)
        .bind(&flow.display_name)
        .bind(flow.version)
        .bind(&graph)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_auth_flow_by_alias(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<geonosis_flow::FlowDefinition, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query(
            "SELECT graph FROM auth_flow
             WHERE realm_id = $1 AND alias = $2
             ORDER BY version DESC LIMIT 1",
        )
        .bind(realm.to_string())
        .bind(alias)
        .fetch_optional(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .ok_or(StorageError::NotFound)?;
        let graph: serde_json::Value = row.try_get("graph").map_err(sqlx_err)?;
        let flow: geonosis_flow::FlowDefinition =
            serde_json::from_value(graph).map_err(json_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(flow)
    }

    async fn list_auth_flows(
        &self,
        realm: RealmId,
    ) -> Result<Vec<geonosis_flow::FlowDefinition>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        // DISTINCT ON keeps only the highest-version row per alias —
        // the latest revision the admin UI should render.
        let rows = sqlx::query(
            "SELECT DISTINCT ON (alias) graph FROM auth_flow
             WHERE realm_id = $1
             ORDER BY alias, version DESC",
        )
        .bind(realm.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        rows.iter()
            .map(|r| {
                let g: serde_json::Value = r.try_get("graph").map_err(sqlx_err)?;
                serde_json::from_value(g).map_err(json_err)
            })
            .collect()
    }

    async fn delete_auth_flow(
        &self,
        realm: RealmId,
        id: geonosis_core::FlowId,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let n = sqlx::query("DELETE FROM auth_flow WHERE id = $1 AND realm_id = $2")
            .bind(id.to_string())
            .bind(realm.to_string())
            .execute(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    // ---- Consent ----
    async fn save_consent_grant(&self, grant: ConsentGrant) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, grant.realm_id).await?;
        sqlx::query(
            "INSERT INTO consent_grant (id, realm_id, user_id, client_id, scopes,
                                        granted_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT (realm_id, user_id, client_id) DO UPDATE SET
                scopes = EXCLUDED.scopes,
                updated_at = EXCLUDED.updated_at",
        )
        .bind(grant.id.to_string())
        .bind(grant.realm_id.to_string())
        .bind(grant.user_id.to_string())
        .bind(grant.client_id.to_string())
        .bind(serde_json::to_value(&grant.scopes).map_err(json_err)?)
        .bind(grant.granted_at)
        .bind(grant.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_consent_grant(
        &self,
        realm: RealmId,
        user_id: UserId,
        client_id: ClientId,
    ) -> Result<ConsentGrant, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query(
            "SELECT * FROM consent_grant
             WHERE realm_id = $1 AND user_id = $2 AND client_id = $3",
        )
        .bind(realm.to_string())
        .bind(user_id.to_string())
        .bind(client_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .ok_or(StorageError::NotFound)?;
        let g = consent_from_row(&row)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(g)
    }

    async fn delete_consent_grant(
        &self,
        realm: RealmId,
        user_id: UserId,
        client_id: ClientId,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query(
            "DELETE FROM consent_grant
             WHERE realm_id = $1 AND user_id = $2 AND client_id = $3",
        )
        .bind(realm.to_string())
        .bind(user_id.to_string())
        .bind(client_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .rows_affected();
        if rows == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    // ---- IdP ----
    async fn create_idp(&self, idp: IdentityProvider) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, idp.realm_id).await?;
        let config = serde_json::to_value(&idp.config)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        sqlx::query(
            "INSERT INTO identity_provider (id, realm_id, alias, display_name, kind,
                adapter_urn, enabled, link_only, first_login_flow_alias, post_login_flow_alias, config)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(idp.id.to_string())
        .bind(idp.realm_id.to_string())
        .bind(&idp.alias)
        .bind(&idp.display_name)
        .bind(match idp.kind {
            geonosis_broker::IdpKind::Oidc => "oidc",
            geonosis_broker::IdpKind::Saml => "saml",
        })
        .bind(idp.adapter_urn.as_deref())
        .bind(idp.enabled)
        .bind(idp.link_only)
        .bind(&idp.first_login_flow_alias)
        .bind(idp.post_login_flow_alias.as_deref())
        .bind(config)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_idp_by_alias(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<IdentityProvider, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query(
            "SELECT * FROM identity_provider WHERE realm_id = $1 AND alias = $2",
        )
        .bind(realm.to_string())
        .bind(alias)
        .fetch_optional(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .ok_or(StorageError::NotFound)?;
        let idp = idp_from_row(&row)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(idp)
    }

    async fn list_idps(&self, realm: RealmId) -> Result<Vec<IdentityProvider>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query("SELECT * FROM identity_provider WHERE realm_id = $1")
            .bind(realm.to_string())
            .fetch_all(&mut *tx)
            .await
            .map_err(sqlx_err)?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(idp_from_row(r)?);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(out)
    }

    async fn delete_idp(&self, realm: RealmId, alias: &str) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let n = sqlx::query("DELETE FROM identity_provider WHERE realm_id = $1 AND alias = $2")
            .bind(realm.to_string())
            .bind(alias)
            .execute(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    // ---- BrokerAuthnState ----
    async fn save_broker_state(&self, state: BrokerAuthnState) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, state.realm_id).await?;
        sqlx::query(
            "INSERT INTO broker_authn_state (id, realm_id, idp_alias, state, nonce,
                pkce_verifier, return_to_flow_state, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(state.id.to_string())
        .bind(state.realm_id.to_string())
        .bind(&state.idp_alias)
        .bind(&state.state)
        .bind(state.nonce.as_deref())
        .bind(state.pkce_verifier.as_ref().map(|s| s.expose().clone()))
        .bind(state.return_to_flow_state.to_string())
        .bind(state.created_at)
        .bind(state.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn consume_broker_state(
        &self,
        realm: RealmId,
        state: &str,
    ) -> Result<BrokerAuthnState, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query(
            "DELETE FROM broker_authn_state WHERE realm_id = $1 AND state = $2 RETURNING *",
        )
        .bind(realm.to_string())
        .bind(state)
        .fetch_optional(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .ok_or(StorageError::NotFound)?;
        let s = broker_state_from_row(&row)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(s)
    }

    // ---- BrokerLink ----
    async fn upsert_broker_link(&self, link: BrokerLink) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, link.realm_id).await?;
        sqlx::query(
            "INSERT INTO broker_link (id, realm_id, user_id, idp_alias, external_id,
                external_username, created_at, last_login_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (realm_id, idp_alias, external_id) DO UPDATE SET
                user_id = EXCLUDED.user_id,
                external_username = EXCLUDED.external_username,
                last_login_at = EXCLUDED.last_login_at",
        )
        .bind(link.id.to_string())
        .bind(link.realm_id.to_string())
        .bind(link.user_id.to_string())
        .bind(&link.idp_alias)
        .bind(&link.external_id)
        .bind(link.external_username.as_deref())
        .bind(link.created_at)
        .bind(link.last_login_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn find_broker_link(
        &self,
        realm: RealmId,
        idp_alias: &str,
        external_id: &str,
    ) -> Result<Option<BrokerLink>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query(
            "SELECT * FROM broker_link WHERE realm_id = $1 AND idp_alias = $2 AND external_id = $3",
        )
        .bind(realm.to_string())
        .bind(idp_alias)
        .bind(external_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        let link = row.as_ref().map(broker_link_from_row).transpose()?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(link)
    }

    async fn list_broker_links(
        &self,
        realm: RealmId,
        user_id: UserId,
    ) -> Result<Vec<BrokerLink>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query("SELECT * FROM broker_link WHERE realm_id = $1 AND user_id = $2")
            .bind(realm.to_string())
            .bind(user_id.to_string())
            .fetch_all(&mut *tx)
            .await
            .map_err(sqlx_err)?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(broker_link_from_row(r)?);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(out)
    }

    // ---- LDAP federation ----
    async fn upsert_ldap_source(
        &self,
        source: LdapFederationConfig,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, source.realm_id).await?;
        let cfg = serde_json::to_value(&source)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        sqlx::query(
            "INSERT INTO ldap_federation (id, realm_id, alias, priority, enabled, config)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (realm_id, alias) DO UPDATE SET
                priority = EXCLUDED.priority,
                enabled = EXCLUDED.enabled,
                config = EXCLUDED.config,
                updated_at = now()",
        )
        .bind(source.id.to_string())
        .bind(source.realm_id.to_string())
        .bind(&source.alias)
        .bind(source.priority)
        .bind(source.enabled)
        .bind(cfg)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_ldap_source(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<LdapFederationConfig, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query(
            "SELECT config FROM ldap_federation WHERE realm_id = $1 AND alias = $2",
        )
        .bind(realm.to_string())
        .bind(alias)
        .fetch_optional(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .ok_or(StorageError::NotFound)?;
        let cfg: serde_json::Value = row.try_get("config").map_err(sqlx_err)?;
        let typed: LdapFederationConfig =
            serde_json::from_value(cfg).map_err(|e| StorageError::Backend(e.to_string()))?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(typed)
    }

    async fn list_ldap_sources(
        &self,
        realm: RealmId,
    ) -> Result<Vec<LdapFederationConfig>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query(
            "SELECT config FROM ldap_federation WHERE realm_id = $1 ORDER BY priority ASC",
        )
        .bind(realm.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let cfg: serde_json::Value = r.try_get("config").map_err(sqlx_err)?;
            let typed: LdapFederationConfig =
                serde_json::from_value(cfg).map_err(|e| StorageError::Backend(e.to_string()))?;
            out.push(typed);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(out)
    }

    async fn delete_ldap_source(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let n = sqlx::query("DELETE FROM ldap_federation WHERE realm_id = $1 AND alias = $2")
            .bind(realm.to_string())
            .bind(alias)
            .execute(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    // ---- WASM module store ----
    async fn upload_wasm_module(&self, m: WasmModule) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, m.realm_id).await?;
        sqlx::query(
            "INSERT INTO wasm_module (id, realm_id, alias, interface, sha256_hex,
                size_bytes, bytecode, uploaded_by, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (realm_id, alias) DO UPDATE SET
                interface = EXCLUDED.interface,
                sha256_hex = EXCLUDED.sha256_hex,
                size_bytes = EXCLUDED.size_bytes,
                bytecode = EXCLUDED.bytecode,
                uploaded_by = EXCLUDED.uploaded_by",
        )
        .bind(m.id.to_string())
        .bind(m.realm_id.to_string())
        .bind(&m.alias)
        .bind(&m.interface)
        .bind(&m.sha256_hex)
        .bind(m.size_bytes)
        .bind(&m.bytecode)
        .bind(m.uploaded_by.map(|u| u.to_string()))
        .bind(m.created_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_wasm_module(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<WasmModule, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query(
            "SELECT * FROM wasm_module WHERE realm_id = $1 AND alias = $2",
        )
        .bind(realm.to_string())
        .bind(alias)
        .fetch_optional(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .ok_or(StorageError::NotFound)?;
        let m = wasm_module_from_row(&row)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(m)
    }

    async fn list_wasm_modules(
        &self,
        realm: RealmId,
    ) -> Result<Vec<WasmModuleHeader>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query(
            "SELECT id, realm_id, alias, interface, sha256_hex, size_bytes, created_at
             FROM wasm_module WHERE realm_id = $1 ORDER BY alias ASC",
        )
        .bind(realm.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(wasm_module_header_from_row(r)?);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(out)
    }

    async fn delete_wasm_module(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let n = sqlx::query("DELETE FROM wasm_module WHERE realm_id = $1 AND alias = $2")
            .bind(realm.to_string())
            .bind(alias)
            .execute(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    // ---- SPI bindings ----
    async fn create_spi_binding(
        &self,
        b: SpiBindingRow,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, b.realm_id).await?;
        sqlx::query(
            "INSERT INTO spi_binding (id, realm_id, interface, provider_urn, priority,
                enabled, replaces, config, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(b.id.to_string())
        .bind(b.realm_id.to_string())
        .bind(&b.interface)
        .bind(&b.provider_urn)
        .bind(b.priority)
        .bind(b.enabled)
        .bind(b.replaces.as_deref())
        .bind(&b.config)
        .bind(b.created_at)
        .bind(b.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn list_spi_bindings(
        &self,
        realm: RealmId,
        interface: &str,
    ) -> Result<Vec<SpiBindingRow>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query(
            "SELECT * FROM spi_binding WHERE realm_id = $1 AND interface = $2
             ORDER BY priority ASC",
        )
        .bind(realm.to_string())
        .bind(interface)
        .fetch_all(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(spi_binding_from_row(r)?);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(out)
    }

    async fn update_spi_binding(
        &self,
        b: SpiBindingRow,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, b.realm_id).await?;
        let n = sqlx::query(
            "UPDATE spi_binding SET priority = $3, enabled = $4, replaces = $5,
                config = $6, updated_at = now()
             WHERE realm_id = $1 AND id = $2",
        )
        .bind(b.realm_id.to_string())
        .bind(b.id.to_string())
        .bind(b.priority)
        .bind(b.enabled)
        .bind(b.replaces.as_deref())
        .bind(&b.config)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn delete_spi_binding(
        &self,
        realm: RealmId,
        binding_id: geonosis_core::id::SpiBindingId,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let n = sqlx::query("DELETE FROM spi_binding WHERE realm_id = $1 AND id = $2")
            .bind(realm.to_string())
            .bind(binding_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    // ---- Phase-0 additions (Role / Group / UserProfile / Agent / Org-ext) ----
    // Table shapes live in migration 20260101_011_init_role_group_profile_agent.up.sql.
    // Every method opens a realm-scoped transaction so the
    // `tenant_isolation` RLS policy enforces realm boundaries even if a
    // future bug omitted the explicit WHERE realm_id predicate.

    async fn list_users(
        &self,
        realm: RealmId,
        limit: usize,
    ) -> Result<Vec<User>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query(
            "SELECT * FROM app_user WHERE realm_id = $1
             ORDER BY created_at LIMIT $2",
        )
        .bind(realm.to_string())
        .bind(limit.min(i64::MAX as usize) as i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        rows.iter().map(user_from_row).collect()
    }

    // ---- Role ----
    async fn create_role(&self, role: Role) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, role.realm_id).await?;
        sqlx::query(
            "INSERT INTO realm_role
               (id, realm_id, client_id, name, description, composites, attributes, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(role.id.to_string())
        .bind(role.realm_id.to_string())
        .bind(role.client_id.map(|c| c.to_string()))
        .bind(&role.name)
        .bind(role.description.as_deref())
        .bind(serde_json::to_value(&role.composites).map_err(json_err)?)
        .bind(serde_json::to_value(&role.attributes).map_err(json_err)?)
        .bind(role.created_at)
        .bind(role.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_role(&self, realm: RealmId, id: RoleId) -> Result<Role, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query("SELECT * FROM realm_role WHERE id = $1 AND realm_id = $2")
            .bind(id.to_string())
            .bind(realm.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        let r = role_from_row(&row)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(r)
    }

    async fn get_role_by_name(
        &self,
        realm: RealmId,
        client_id: Option<ClientId>,
        name: &str,
    ) -> Result<Role, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        // `client_id IS NULL` and `client_id = $x` must be handled as a
        // single SQL predicate; binding NULL alone does not match because
        // `NULL = NULL` is unknown in SQL.
        let row = sqlx::query(
            "SELECT * FROM realm_role
             WHERE realm_id = $1
               AND name = $2
               AND ((client_id IS NULL AND $3::text IS NULL) OR client_id = $3)",
        )
        .bind(realm.to_string())
        .bind(name)
        .bind(client_id.map(|c| c.to_string()))
        .fetch_optional(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .ok_or(StorageError::NotFound)?;
        let r = role_from_row(&row)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(r)
    }

    async fn list_roles(
        &self,
        realm: RealmId,
        client_id: Option<ClientId>,
    ) -> Result<Vec<Role>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query(
            "SELECT * FROM realm_role
             WHERE realm_id = $1
               AND ((client_id IS NULL AND $2::text IS NULL) OR client_id = $2)
             ORDER BY name",
        )
        .bind(realm.to_string())
        .bind(client_id.map(|c| c.to_string()))
        .fetch_all(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        rows.iter().map(role_from_row).collect()
    }

    async fn update_role(&self, role: Role) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, role.realm_id).await?;
        let n = sqlx::query(
            "UPDATE realm_role
               SET name = $3, description = $4, composites = $5, attributes = $6, updated_at = $7
             WHERE id = $1 AND realm_id = $2",
        )
        .bind(role.id.to_string())
        .bind(role.realm_id.to_string())
        .bind(&role.name)
        .bind(role.description.as_deref())
        .bind(serde_json::to_value(&role.composites).map_err(json_err)?)
        .bind(serde_json::to_value(&role.attributes).map_err(json_err)?)
        .bind(role.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn delete_role(&self, realm: RealmId, id: RoleId) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let n = sqlx::query("DELETE FROM realm_role WHERE id = $1 AND realm_id = $2")
            .bind(id.to_string())
            .bind(realm.to_string())
            .execute(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn assign_user_role(
        &self,
        realm: RealmId,
        user_id: UserId,
        role_id: RoleId,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        sqlx::query(
            "INSERT INTO user_role (realm_id, user_id, role_id)
             VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
        )
        .bind(realm.to_string())
        .bind(user_id.to_string())
        .bind(role_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn unassign_user_role(
        &self,
        realm: RealmId,
        user_id: UserId,
        role_id: RoleId,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        sqlx::query(
            "DELETE FROM user_role
             WHERE realm_id = $1 AND user_id = $2 AND role_id = $3",
        )
        .bind(realm.to_string())
        .bind(user_id.to_string())
        .bind(role_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn list_user_roles(
        &self,
        realm: RealmId,
        user_id: UserId,
    ) -> Result<Vec<Role>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query(
            "SELECT r.* FROM realm_role r
             JOIN user_role ur ON ur.role_id = r.id
             WHERE ur.realm_id = $1 AND ur.user_id = $2
             ORDER BY r.name",
        )
        .bind(realm.to_string())
        .bind(user_id.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        rows.iter().map(role_from_row).collect()
    }

    // ---- Group ----
    async fn create_group(&self, group: Group) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, group.realm_id).await?;
        sqlx::query(
            "INSERT INTO app_group
               (id, realm_id, parent_id, name, path, attributes, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(group.id.to_string())
        .bind(group.realm_id.to_string())
        .bind(group.parent_id.map(|p| p.to_string()))
        .bind(&group.name)
        .bind(&group.path)
        .bind(serde_json::to_value(&group.attributes).map_err(json_err)?)
        .bind(group.created_at)
        .bind(group.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_group(&self, realm: RealmId, id: GroupId) -> Result<Group, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query("SELECT * FROM app_group WHERE id = $1 AND realm_id = $2")
            .bind(id.to_string())
            .bind(realm.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        let g = group_from_row(&row)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(g)
    }

    async fn get_group_by_path(
        &self,
        realm: RealmId,
        path: &str,
    ) -> Result<Group, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query("SELECT * FROM app_group WHERE realm_id = $1 AND path = $2")
            .bind(realm.to_string())
            .bind(path)
            .fetch_optional(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        let g = group_from_row(&row)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(g)
    }

    async fn list_groups(&self, realm: RealmId) -> Result<Vec<Group>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query(
            "SELECT * FROM app_group WHERE realm_id = $1 ORDER BY path",
        )
        .bind(realm.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        rows.iter().map(group_from_row).collect()
    }

    async fn update_group(&self, group: Group) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, group.realm_id).await?;
        let n = sqlx::query(
            "UPDATE app_group
               SET parent_id = $3, name = $4, path = $5, attributes = $6, updated_at = $7
             WHERE id = $1 AND realm_id = $2",
        )
        .bind(group.id.to_string())
        .bind(group.realm_id.to_string())
        .bind(group.parent_id.map(|p| p.to_string()))
        .bind(&group.name)
        .bind(&group.path)
        .bind(serde_json::to_value(&group.attributes).map_err(json_err)?)
        .bind(group.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn delete_group(&self, realm: RealmId, id: GroupId) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let n = sqlx::query("DELETE FROM app_group WHERE id = $1 AND realm_id = $2")
            .bind(id.to_string())
            .bind(realm.to_string())
            .execute(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn assign_user_group(
        &self,
        realm: RealmId,
        user_id: UserId,
        group_id: GroupId,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        sqlx::query(
            "INSERT INTO user_group (realm_id, user_id, group_id)
             VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
        )
        .bind(realm.to_string())
        .bind(user_id.to_string())
        .bind(group_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn unassign_user_group(
        &self,
        realm: RealmId,
        user_id: UserId,
        group_id: GroupId,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        sqlx::query(
            "DELETE FROM user_group
             WHERE realm_id = $1 AND user_id = $2 AND group_id = $3",
        )
        .bind(realm.to_string())
        .bind(user_id.to_string())
        .bind(group_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn list_user_groups(
        &self,
        realm: RealmId,
        user_id: UserId,
    ) -> Result<Vec<Group>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query(
            "SELECT g.* FROM app_group g
             JOIN user_group ug ON ug.group_id = g.id
             WHERE ug.realm_id = $1 AND ug.user_id = $2
             ORDER BY g.path",
        )
        .bind(realm.to_string())
        .bind(user_id.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        rows.iter().map(group_from_row).collect()
    }

    async fn assign_group_role(
        &self,
        realm: RealmId,
        group_id: GroupId,
        role_id: RoleId,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        sqlx::query(
            "INSERT INTO group_role (realm_id, group_id, role_id)
             VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
        )
        .bind(realm.to_string())
        .bind(group_id.to_string())
        .bind(role_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn unassign_group_role(
        &self,
        realm: RealmId,
        group_id: GroupId,
        role_id: RoleId,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        sqlx::query(
            "DELETE FROM group_role
             WHERE realm_id = $1 AND group_id = $2 AND role_id = $3",
        )
        .bind(realm.to_string())
        .bind(group_id.to_string())
        .bind(role_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn list_group_roles(
        &self,
        realm: RealmId,
        group_id: GroupId,
    ) -> Result<Vec<Role>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query(
            "SELECT r.* FROM realm_role r
             JOIN group_role gr ON gr.role_id = r.id
             WHERE gr.realm_id = $1 AND gr.group_id = $2
             ORDER BY r.name",
        )
        .bind(realm.to_string())
        .bind(group_id.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        rows.iter().map(role_from_row).collect()
    }

    // ---- User profile schema ----
    async fn get_user_profile_schema(
        &self,
        realm: RealmId,
    ) -> Result<UserProfile, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query(
            "SELECT attributes, groups, unmanaged_policy, updated_at
             FROM user_profile_schema WHERE realm_id = $1",
        )
        .bind(realm.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        // Fall back to the default schema when the realm has never saved
        // a custom one (admin UI render / userinfo emission both need a
        // working schema before the first PUT).
        let Some(row) = row else {
            return Ok(UserProfile::default_for(realm));
        };
        let attributes: serde_json::Value = row.try_get("attributes").map_err(sqlx_err)?;
        let groups: serde_json::Value = row.try_get("groups").map_err(sqlx_err)?;
        let unmanaged_policy: String = row.try_get("unmanaged_policy").map_err(sqlx_err)?;
        let updated_at: DateTime<Utc> = row.try_get("updated_at").map_err(sqlx_err)?;
        Ok(UserProfile {
            realm_id: realm,
            attributes: serde_json::from_value(attributes).map_err(json_err)?,
            groups: serde_json::from_value(groups).map_err(json_err)?,
            unmanaged_policy: serde_json::from_value(
                serde_json::Value::String(unmanaged_policy),
            )
            .map_err(json_err)?,
            updated_at,
        })
    }

    async fn save_user_profile_schema(
        &self,
        profile: UserProfile,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, profile.realm_id).await?;
        let policy = serde_json::to_value(profile.unmanaged_policy)
            .map_err(json_err)?
            .as_str()
            .unwrap_or("reject")
            .to_string();
        sqlx::query(
            "INSERT INTO user_profile_schema
               (realm_id, attributes, groups, unmanaged_policy, updated_at)
             VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT (realm_id) DO UPDATE
               SET attributes = EXCLUDED.attributes,
                   groups = EXCLUDED.groups,
                   unmanaged_policy = EXCLUDED.unmanaged_policy,
                   updated_at = EXCLUDED.updated_at",
        )
        .bind(profile.realm_id.to_string())
        .bind(serde_json::to_value(&profile.attributes).map_err(json_err)?)
        .bind(serde_json::to_value(&profile.groups).map_err(json_err)?)
        .bind(policy)
        .bind(profile.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    // ---- Agent ----
    async fn create_agent(&self, agent: Agent) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, agent.realm_id).await?;
        sqlx::query(
            "INSERT INTO agent
               (id, realm_id, alias, display_name, kind, model_hint, vendor, version,
                parent_subject, capabilities, allowed_scopes, allowed_audiences,
                rate_limit, auth_method, public_jwk,
                created_at, expires_at, revoked_at, enabled)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)",
        )
        .bind(agent.id.to_string())
        .bind(agent.realm_id.to_string())
        .bind(&agent.alias)
        .bind(&agent.display_name)
        .bind(agent_kind_to_str(&agent.kind))
        .bind(agent.model_hint.as_deref())
        .bind(agent.vendor.as_deref())
        .bind(agent.version.as_deref())
        .bind(serde_json::to_value(&agent.parent_subject).map_err(json_err)?)
        .bind(serde_json::to_value(&agent.capabilities).map_err(json_err)?)
        .bind(serde_json::to_value(&agent.allowed_scopes).map_err(json_err)?)
        .bind(serde_json::to_value(&agent.allowed_audiences).map_err(json_err)?)
        .bind(serde_json::to_value(&agent.rate_limit).map_err(json_err)?)
        .bind(agent_auth_method_to_str(agent.auth_method))
        .bind(agent.public_jwk.as_ref())
        .bind(agent.created_at)
        .bind(agent.expires_at)
        .bind(agent.revoked_at)
        .bind(agent.enabled)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_agent(&self, realm: RealmId, id: AgentId) -> Result<Agent, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query("SELECT * FROM agent WHERE id = $1 AND realm_id = $2")
            .bind(id.to_string())
            .bind(realm.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        let a = agent_from_row(&row)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(a)
    }

    async fn get_agent_by_alias(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<Agent, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query("SELECT * FROM agent WHERE realm_id = $1 AND alias = $2")
            .bind(realm.to_string())
            .bind(alias)
            .fetch_optional(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        let a = agent_from_row(&row)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(a)
    }

    async fn list_agents(&self, realm: RealmId) -> Result<Vec<Agent>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query("SELECT * FROM agent WHERE realm_id = $1 ORDER BY alias")
            .bind(realm.to_string())
            .fetch_all(&mut *tx)
            .await
            .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        rows.iter().map(agent_from_row).collect()
    }

    async fn update_agent(&self, agent: Agent) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, agent.realm_id).await?;
        // `parent_subject` and `created_at` are immutable per doc §18 —
        // the handler enforces this; we omit them from UPDATE to keep
        // the contract enforced at the storage layer too.
        let n = sqlx::query(
            "UPDATE agent
               SET alias = $3, display_name = $4, kind = $5, model_hint = $6,
                   vendor = $7, version = $8, capabilities = $9,
                   allowed_scopes = $10, allowed_audiences = $11, rate_limit = $12,
                   auth_method = $13, public_jwk = $14,
                   expires_at = $15, revoked_at = $16, enabled = $17
             WHERE id = $1 AND realm_id = $2",
        )
        .bind(agent.id.to_string())
        .bind(agent.realm_id.to_string())
        .bind(&agent.alias)
        .bind(&agent.display_name)
        .bind(agent_kind_to_str(&agent.kind))
        .bind(agent.model_hint.as_deref())
        .bind(agent.vendor.as_deref())
        .bind(agent.version.as_deref())
        .bind(serde_json::to_value(&agent.capabilities).map_err(json_err)?)
        .bind(serde_json::to_value(&agent.allowed_scopes).map_err(json_err)?)
        .bind(serde_json::to_value(&agent.allowed_audiences).map_err(json_err)?)
        .bind(serde_json::to_value(&agent.rate_limit).map_err(json_err)?)
        .bind(agent_auth_method_to_str(agent.auth_method))
        .bind(agent.public_jwk.as_ref())
        .bind(agent.expires_at)
        .bind(agent.revoked_at)
        .bind(agent.enabled)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn revoke_agent(&self, realm: RealmId, id: AgentId) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let n = sqlx::query(
            "UPDATE agent SET revoked_at = $3, enabled = false
             WHERE id = $1 AND realm_id = $2",
        )
        .bind(id.to_string())
        .bind(realm.to_string())
        .bind(Utc::now())
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    // ---- Organization ----
    async fn create_organization(&self, org: Organization) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, org.realm_id).await?;
        sqlx::query(
            "INSERT INTO organization
               (id, realm_id, alias, display_name, description, branding, attributes,
                default_idp_alias, redirect_url, enabled, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(org.id.to_string())
        .bind(org.realm_id.to_string())
        .bind(&org.alias)
        .bind(&org.display_name)
        .bind(org.description.as_deref())
        .bind(serde_json::to_value(&org.branding).map_err(json_err)?)
        .bind(serde_json::to_value(&org.attributes).map_err(json_err)?)
        .bind(org.default_idp_alias.as_deref())
        .bind(org.redirect_url.as_ref().map(|u| u.to_string()))
        .bind(org.enabled)
        .bind(org.created_at)
        .bind(org.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_organization(
        &self,
        realm: RealmId,
        id: OrganizationId,
    ) -> Result<Organization, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query("SELECT * FROM organization WHERE id = $1 AND realm_id = $2")
            .bind(id.to_string())
            .bind(realm.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        let o = organization_from_row(&row)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(o)
    }

    async fn get_organization_by_alias(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<Organization, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query(
            "SELECT * FROM organization WHERE realm_id = $1 AND alias = $2",
        )
        .bind(realm.to_string())
        .bind(alias)
        .fetch_optional(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .ok_or(StorageError::NotFound)?;
        let o = organization_from_row(&row)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(o)
    }

    async fn list_organizations(
        &self,
        realm: RealmId,
    ) -> Result<Vec<Organization>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query(
            "SELECT * FROM organization WHERE realm_id = $1 ORDER BY alias",
        )
        .bind(realm.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        rows.iter().map(organization_from_row).collect()
    }

    async fn update_organization(&self, org: Organization) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, org.realm_id).await?;
        let n = sqlx::query(
            "UPDATE organization
               SET alias = $3, display_name = $4, description = $5, branding = $6,
                   attributes = $7, default_idp_alias = $8, redirect_url = $9,
                   enabled = $10, updated_at = $11
             WHERE id = $1 AND realm_id = $2",
        )
        .bind(org.id.to_string())
        .bind(org.realm_id.to_string())
        .bind(&org.alias)
        .bind(&org.display_name)
        .bind(org.description.as_deref())
        .bind(serde_json::to_value(&org.branding).map_err(json_err)?)
        .bind(serde_json::to_value(&org.attributes).map_err(json_err)?)
        .bind(org.default_idp_alias.as_deref())
        .bind(org.redirect_url.as_ref().map(|u| u.to_string()))
        .bind(org.enabled)
        .bind(org.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn delete_organization(
        &self,
        realm: RealmId,
        id: OrganizationId,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let n = sqlx::query(
            "DELETE FROM organization WHERE id = $1 AND realm_id = $2",
        )
        .bind(id.to_string())
        .bind(realm.to_string())
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn upsert_org_domain(&self, domain: OrgDomain) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, domain.realm_id).await?;
        sqlx::query(
            "INSERT INTO org_domain
               (id, organization_id, realm_id, domain, verified, verification_token, verified_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT (realm_id, domain) DO UPDATE
               SET verified = EXCLUDED.verified,
                   verification_token = EXCLUDED.verification_token,
                   verified_at = EXCLUDED.verified_at",
        )
        .bind(domain.id.to_string())
        .bind(domain.organization_id.to_string())
        .bind(domain.realm_id.to_string())
        .bind(&domain.domain)
        .bind(domain.verified)
        .bind(domain.verification_token.as_deref())
        .bind(domain.verified_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn list_org_domains(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
    ) -> Result<Vec<OrgDomain>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query(
            "SELECT * FROM org_domain
             WHERE realm_id = $1 AND organization_id = $2
             ORDER BY domain",
        )
        .bind(realm.to_string())
        .bind(organization_id.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        rows.iter().map(org_domain_from_row).collect()
    }

    async fn delete_org_domain(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
        domain: &str,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let n = sqlx::query(
            "DELETE FROM org_domain
             WHERE realm_id = $1 AND organization_id = $2 AND domain = $3",
        )
        .bind(realm.to_string())
        .bind(organization_id.to_string())
        .bind(domain)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn find_org_by_verified_domain(
        &self,
        realm: RealmId,
        domain: &str,
    ) -> Result<Option<Organization>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query(
            "SELECT o.* FROM organization o
             JOIN org_domain d ON d.organization_id = o.id
             WHERE d.realm_id = $1 AND d.domain = $2 AND d.verified = true
             LIMIT 1",
        )
        .bind(realm.to_string())
        .bind(domain)
        .fetch_optional(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        match row {
            Some(r) => Ok(Some(organization_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn upsert_org_membership(
        &self,
        membership: OrgMembership,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, membership.realm_id).await?;
        sqlx::query(
            "INSERT INTO org_membership
               (organization_id, realm_id, user_id, roles, invited_by, state, joined_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT (organization_id, user_id) DO UPDATE
               SET roles = EXCLUDED.roles,
                   invited_by = EXCLUDED.invited_by,
                   state = EXCLUDED.state",
        )
        .bind(membership.organization_id.to_string())
        .bind(membership.realm_id.to_string())
        .bind(membership.user_id.to_string())
        .bind(serde_json::to_value(&membership.roles).map_err(json_err)?)
        .bind(membership.invited_by.map(|u| u.to_string()))
        .bind(membership_state_to_str(membership.state))
        .bind(membership.joined_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_org_membership(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
        user_id: UserId,
    ) -> Result<OrgMembership, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query(
            "SELECT * FROM org_membership
             WHERE realm_id = $1 AND organization_id = $2 AND user_id = $3",
        )
        .bind(realm.to_string())
        .bind(organization_id.to_string())
        .bind(user_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .ok_or(StorageError::NotFound)?;
        let m = org_membership_from_row(&row)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(m)
    }

    async fn list_org_memberships(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
    ) -> Result<Vec<OrgMembership>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query(
            "SELECT * FROM org_membership
             WHERE realm_id = $1 AND organization_id = $2
             ORDER BY joined_at",
        )
        .bind(realm.to_string())
        .bind(organization_id.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        rows.iter().map(org_membership_from_row).collect()
    }

    async fn list_user_orgs(
        &self,
        realm: RealmId,
        user_id: UserId,
    ) -> Result<Vec<OrgMembership>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query(
            "SELECT * FROM org_membership
             WHERE realm_id = $1 AND user_id = $2
             ORDER BY joined_at",
        )
        .bind(realm.to_string())
        .bind(user_id.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        rows.iter().map(org_membership_from_row).collect()
    }

    async fn delete_org_membership(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
        user_id: UserId,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let n = sqlx::query(
            "DELETE FROM org_membership
             WHERE realm_id = $1 AND organization_id = $2 AND user_id = $3",
        )
        .bind(realm.to_string())
        .bind(organization_id.to_string())
        .bind(user_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn create_org_role(&self, role: OrgRole) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, role.realm_id).await?;
        sqlx::query(
            "INSERT INTO org_role
               (id, organization_id, realm_id, name, description, permissions, built_in)
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(role.id.to_string())
        .bind(role.organization_id.to_string())
        .bind(role.realm_id.to_string())
        .bind(&role.name)
        .bind(role.description.as_deref())
        .bind(serde_json::to_value(&role.permissions).map_err(json_err)?)
        .bind(role.built_in)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_org_role(
        &self,
        realm: RealmId,
        id: OrgRoleId,
    ) -> Result<OrgRole, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query("SELECT * FROM org_role WHERE id = $1 AND realm_id = $2")
            .bind(id.to_string())
            .bind(realm.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        let r = org_role_from_row(&row)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(r)
    }

    async fn list_org_roles(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
    ) -> Result<Vec<OrgRole>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query(
            "SELECT * FROM org_role
             WHERE realm_id = $1 AND organization_id = $2
             ORDER BY name",
        )
        .bind(realm.to_string())
        .bind(organization_id.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        rows.iter().map(org_role_from_row).collect()
    }

    async fn update_org_role(&self, role: OrgRole) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, role.realm_id).await?;
        let n = sqlx::query(
            "UPDATE org_role
               SET name = $3, description = $4, permissions = $5
             WHERE id = $1 AND realm_id = $2",
        )
        .bind(role.id.to_string())
        .bind(role.realm_id.to_string())
        .bind(&role.name)
        .bind(role.description.as_deref())
        .bind(serde_json::to_value(&role.permissions).map_err(json_err)?)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn delete_org_role(
        &self,
        realm: RealmId,
        id: OrgRoleId,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let n = sqlx::query("DELETE FROM org_role WHERE id = $1 AND realm_id = $2")
            .bind(id.to_string())
            .bind(realm.to_string())
            .execute(&mut *tx)
            .await
            .map_err(sqlx_err)?
            .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn create_org_invitation(
        &self,
        invitation: OrgInvitation,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, invitation.realm_id).await?;
        sqlx::query(
            "INSERT INTO org_invitation
               (id, organization_id, realm_id, email, roles, invited_by, token, expires_at, accepted_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(invitation.id.to_string())
        .bind(invitation.organization_id.to_string())
        .bind(invitation.realm_id.to_string())
        .bind(&invitation.email)
        .bind(serde_json::to_value(&invitation.roles).map_err(json_err)?)
        .bind(invitation.invited_by.to_string())
        .bind(invitation.token.expose())
        .bind(invitation.expires_at)
        .bind(invitation.accepted_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_org_invitation_by_token(
        &self,
        token: &str,
    ) -> Result<OrgInvitation, StorageError> {
        // Invitations are realm-scoped but the public accept-URL only
        // carries the token, so we route the lookup through the bypass
        // role (admin/migration role) — RLS is still enforced for every
        // realm-scoped read after this method returns.
        let row = sqlx::query("SELECT * FROM org_invitation WHERE token = $1")
            .bind(token)
            .fetch_optional(&self.pool)
            .await
            .map_err(sqlx_err)?
            .ok_or(StorageError::NotFound)?;
        org_invitation_from_row(&row)
    }

    async fn list_org_invitations(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
    ) -> Result<Vec<OrgInvitation>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query(
            "SELECT * FROM org_invitation
             WHERE realm_id = $1 AND organization_id = $2
             ORDER BY expires_at",
        )
        .bind(realm.to_string())
        .bind(organization_id.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        rows.iter().map(org_invitation_from_row).collect()
    }

    async fn mark_org_invitation_accepted(
        &self,
        id: OrgInvitationId,
    ) -> Result<(), StorageError> {
        let n = sqlx::query(
            "UPDATE org_invitation SET accepted_at = $2 WHERE id = $1",
        )
        .bind(id.to_string())
        .bind(Utc::now())
        .execute(&self.pool)
        .await
        .map_err(sqlx_err)?
        .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    async fn delete_org_invitation(
        &self,
        id: OrgInvitationId,
    ) -> Result<(), StorageError> {
        let n = sqlx::query("DELETE FROM org_invitation WHERE id = $1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(sqlx_err)?
            .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    async fn upsert_org_consent_policy(
        &self,
        policy: OrgConsentPolicy,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, policy.realm_id).await?;
        sqlx::query(
            "INSERT INTO org_consent_policy
               (id, organization_id, realm_id, client_id, mode,
                pre_approved_scopes, blocked_scopes, require_admin_approval,
                created_by, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
             ON CONFLICT (organization_id, client_id) DO UPDATE
               SET mode = EXCLUDED.mode,
                   pre_approved_scopes = EXCLUDED.pre_approved_scopes,
                   blocked_scopes = EXCLUDED.blocked_scopes,
                   require_admin_approval = EXCLUDED.require_admin_approval,
                   updated_at = EXCLUDED.updated_at",
        )
        .bind(policy.id.to_string())
        .bind(policy.organization_id.to_string())
        .bind(policy.realm_id.to_string())
        .bind(policy.client_id.to_string())
        .bind(org_consent_mode_to_str(policy.mode))
        .bind(serde_json::to_value(&policy.pre_approved_scopes).map_err(json_err)?)
        .bind(serde_json::to_value(&policy.blocked_scopes).map_err(json_err)?)
        .bind(policy.require_admin_approval)
        .bind(policy.created_by.to_string())
        .bind(policy.created_at)
        .bind(policy.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn get_org_consent_policy(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
        client_id: ClientId,
    ) -> Result<Option<OrgConsentPolicy>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let row = sqlx::query(
            "SELECT * FROM org_consent_policy
             WHERE realm_id = $1 AND organization_id = $2 AND client_id = $3",
        )
        .bind(realm.to_string())
        .bind(organization_id.to_string())
        .bind(client_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        match row {
            Some(r) => Ok(Some(org_consent_policy_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn list_org_consent_policies(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
    ) -> Result<Vec<OrgConsentPolicy>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query(
            "SELECT * FROM org_consent_policy
             WHERE realm_id = $1 AND organization_id = $2",
        )
        .bind(realm.to_string())
        .bind(organization_id.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        rows.iter().map(org_consent_policy_from_row).collect()
    }

    async fn delete_org_consent_policy(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
        client_id: ClientId,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let n = sqlx::query(
            "DELETE FROM org_consent_policy
             WHERE realm_id = $1 AND organization_id = $2 AND client_id = $3",
        )
        .bind(realm.to_string())
        .bind(organization_id.to_string())
        .bind(client_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn upsert_org_idp_binding(
        &self,
        binding: OrgIdpBinding,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, binding.realm_id).await?;
        sqlx::query(
            "INSERT INTO org_idp_binding
               (organization_id, realm_id, idp_alias, priority, enabled)
             VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT (organization_id, idp_alias) DO UPDATE
               SET priority = EXCLUDED.priority,
                   enabled = EXCLUDED.enabled",
        )
        .bind(binding.organization_id.to_string())
        .bind(binding.realm_id.to_string())
        .bind(&binding.idp_alias)
        .bind(binding.priority)
        .bind(binding.enabled)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn list_org_idp_bindings(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
    ) -> Result<Vec<OrgIdpBinding>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query(
            "SELECT * FROM org_idp_binding
             WHERE realm_id = $1 AND organization_id = $2
             ORDER BY priority DESC, idp_alias",
        )
        .bind(realm.to_string())
        .bind(organization_id.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        rows.iter().map(org_idp_binding_from_row).collect()
    }

    async fn delete_org_idp_binding(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
        idp_alias: &str,
    ) -> Result<(), StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let n = sqlx::query(
            "DELETE FROM org_idp_binding
             WHERE realm_id = $1 AND organization_id = $2 AND idp_alias = $3",
        )
        .bind(realm.to_string())
        .bind(organization_id.to_string())
        .bind(idp_alias)
        .execute(&mut *tx)
        .await
        .map_err(sqlx_err)?
        .rows_affected();
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit().await.map_err(sqlx_err)?;
        Ok(())
    }

    async fn list_sessions(
        &self,
        realm: RealmId,
        limit: usize,
    ) -> Result<Vec<Session>, StorageError> {
        let mut tx = begin_realm(&self.pool, realm).await?;
        let rows = sqlx::query(
            "SELECT * FROM session WHERE realm_id = $1
             ORDER BY last_seen_at DESC LIMIT $2",
        )
        .bind(realm.to_string())
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(sqlx_err)?;
        tx.commit().await.map_err(sqlx_err)?;
        rows.iter().map(session_from_row).collect()
    }

    async fn list_audit_events(
        &self,
        realm: RealmId,
        filter: &crate::traits::AuditEventFilter<'_>,
        limit: usize,
    ) -> Result<Vec<crate::traits::AuditEventRow>, StorageError> {
        // Bounded-arg query against the partitioned audit table.
        // Per docs/13, the table is indexed on `(realm_id,
        // occurred_at DESC)` and `(realm_id, action, occurred_at)`,
        // so the realm + ORDER BY + optional `action` predicate stay
        // index-served. `actor` is a JSONB column, so we cast to
        // text for the substring filter — the row count is already
        // bounded by realm + occurred_at, keeping the cast safe.
        let mut sql = String::from(
            "SELECT id, realm_id, occurred_at, actor, action, target, detail
             FROM audit_event WHERE realm_id = $1",
        );
        let mut idx = 2;
        if filter.action.is_some() {
            sql.push_str(&format!(" AND action = ${idx}"));
            idx += 1;
        }
        if filter.actor.is_some() {
            sql.push_str(&format!(" AND actor::text ILIKE ${idx}"));
            idx += 1;
        }
        if filter.from.is_some() {
            sql.push_str(&format!(" AND occurred_at >= ${idx}"));
            idx += 1;
        }
        if filter.until.is_some() {
            sql.push_str(&format!(" AND occurred_at < ${idx}"));
            idx += 1;
        }
        sql.push_str(&format!(" ORDER BY occurred_at DESC LIMIT ${idx}"));

        let mut q = sqlx::query_as::<_, AuditEventRowDb>(&sql).bind(realm.to_string());
        if let Some(a) = filter.action {
            q = q.bind(a.to_string());
        }
        if let Some(a) = filter.actor {
            q = q.bind(format!("%{a}%"));
        }
        if let Some(f) = filter.from {
            q = q.bind(f);
        }
        if let Some(u) = filter.until {
            q = q.bind(u);
        }
        let rows = q
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(sqlx_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
}

/// Internal row decoder for `audit_event`. Avoids leaking sqlx into
/// the public storage API.
#[derive(sqlx::FromRow)]
struct AuditEventRowDb {
    id: String,
    realm_id: String,
    occurred_at: chrono::DateTime<chrono::Utc>,
    actor: serde_json::Value,
    action: String,
    target: Option<serde_json::Value>,
    detail: serde_json::Value,
}

impl From<AuditEventRowDb> for crate::traits::AuditEventRow {
    fn from(r: AuditEventRowDb) -> Self {
        Self {
            id: r.id,
            realm_id: r.realm_id,
            occurred_at: r.occurred_at,
            actor: r.actor,
            action: r.action,
            target: r.target,
            detail: r.detail,
        }
    }
}

fn idp_from_row(row: &sqlx::postgres::PgRow) -> Result<IdentityProvider, StorageError> {
    use geonosis_broker::{IdpConfig, IdpKind};
    let id: String = row.try_get("id").map_err(sqlx_err)?;
    let realm_id: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let alias: String = row.try_get("alias").map_err(sqlx_err)?;
    let display_name: String = row.try_get("display_name").map_err(sqlx_err)?;
    let kind: String = row.try_get("kind").map_err(sqlx_err)?;
    let adapter_urn: Option<String> = row.try_get("adapter_urn").map_err(sqlx_err)?;
    let enabled: bool = row.try_get("enabled").map_err(sqlx_err)?;
    let link_only: bool = row.try_get("link_only").map_err(sqlx_err)?;
    let first_login_flow_alias: String = row.try_get("first_login_flow_alias").map_err(sqlx_err)?;
    let post_login_flow_alias: Option<String> = row.try_get("post_login_flow_alias").map_err(sqlx_err)?;
    let config_json: serde_json::Value = row.try_get("config").map_err(sqlx_err)?;
    let config: IdpConfig =
        serde_json::from_value(config_json).map_err(|e| StorageError::Backend(e.to_string()))?;
    Ok(IdentityProvider {
        id: id.parse().map_err(invalid_id)?,
        realm_id: realm_id.parse().map_err(invalid_id)?,
        alias,
        display_name,
        kind: match kind.as_str() {
            "oidc" => IdpKind::Oidc,
            "saml" => IdpKind::Saml,
            other => return Err(StorageError::Backend(format!("unknown idp kind: {other}"))),
        },
        config,
        first_login_flow_alias,
        post_login_flow_alias,
        link_only,
        adapter_urn,
        enabled,
    })
}

fn broker_state_from_row(row: &sqlx::postgres::PgRow) -> Result<BrokerAuthnState, StorageError> {
    use geonosis_core::secret::Secret;
    let id: String = row.try_get("id").map_err(sqlx_err)?;
    let realm_id: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let idp_alias: String = row.try_get("idp_alias").map_err(sqlx_err)?;
    let state: String = row.try_get("state").map_err(sqlx_err)?;
    let nonce: Option<String> = row.try_get("nonce").map_err(sqlx_err)?;
    let pkce: Option<String> = row.try_get("pkce_verifier").map_err(sqlx_err)?;
    let return_to: String = row.try_get("return_to_flow_state").map_err(sqlx_err)?;
    let created_at: DateTime<Utc> = row.try_get("created_at").map_err(sqlx_err)?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at").map_err(sqlx_err)?;
    Ok(BrokerAuthnState {
        id: id.parse().map_err(invalid_id)?,
        realm_id: realm_id.parse().map_err(invalid_id)?,
        idp_alias,
        state,
        nonce,
        pkce_verifier: pkce.map(Secret::new),
        return_to_flow_state: return_to.parse().map_err(invalid_id)?,
        created_at,
        expires_at,
    })
}

fn broker_link_from_row(row: &sqlx::postgres::PgRow) -> Result<BrokerLink, StorageError> {
    let id: String = row.try_get("id").map_err(sqlx_err)?;
    let realm_id: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let user_id: String = row.try_get("user_id").map_err(sqlx_err)?;
    let idp_alias: String = row.try_get("idp_alias").map_err(sqlx_err)?;
    let external_id: String = row.try_get("external_id").map_err(sqlx_err)?;
    let external_username: Option<String> = row.try_get("external_username").map_err(sqlx_err)?;
    let created_at: DateTime<Utc> = row.try_get("created_at").map_err(sqlx_err)?;
    let last_login_at: Option<DateTime<Utc>> = row.try_get("last_login_at").map_err(sqlx_err)?;
    Ok(BrokerLink {
        id: id.parse().map_err(invalid_id)?,
        realm_id: realm_id.parse().map_err(invalid_id)?,
        user_id: user_id.parse().map_err(invalid_id)?,
        idp_alias,
        external_id,
        external_username,
        created_at,
        last_login_at,
    })
}

fn wasm_module_from_row(row: &sqlx::postgres::PgRow) -> Result<WasmModule, StorageError> {
    let id: String = row.try_get("id").map_err(sqlx_err)?;
    let realm_id: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let alias: String = row.try_get("alias").map_err(sqlx_err)?;
    let interface: String = row.try_get("interface").map_err(sqlx_err)?;
    let sha: String = row.try_get("sha256_hex").map_err(sqlx_err)?;
    let size: i64 = row.try_get("size_bytes").map_err(sqlx_err)?;
    let bytecode: Vec<u8> = row.try_get("bytecode").map_err(sqlx_err)?;
    let uploaded_by: Option<String> = row.try_get("uploaded_by").map_err(sqlx_err)?;
    let created_at: DateTime<Utc> = row.try_get("created_at").map_err(sqlx_err)?;
    Ok(WasmModule {
        id: id.parse().map_err(invalid_id)?,
        realm_id: realm_id.parse().map_err(invalid_id)?,
        alias,
        interface,
        sha256_hex: sha,
        size_bytes: size,
        bytecode,
        uploaded_by: uploaded_by
            .map(|s| s.parse())
            .transpose()
            .map_err(invalid_id)?,
        created_at,
    })
}

fn wasm_module_header_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<WasmModuleHeader, StorageError> {
    let id: String = row.try_get("id").map_err(sqlx_err)?;
    let realm_id: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let alias: String = row.try_get("alias").map_err(sqlx_err)?;
    let interface: String = row.try_get("interface").map_err(sqlx_err)?;
    let sha: String = row.try_get("sha256_hex").map_err(sqlx_err)?;
    let size: i64 = row.try_get("size_bytes").map_err(sqlx_err)?;
    let created_at: DateTime<Utc> = row.try_get("created_at").map_err(sqlx_err)?;
    Ok(WasmModuleHeader {
        id: id.parse().map_err(invalid_id)?,
        realm_id: realm_id.parse().map_err(invalid_id)?,
        alias,
        interface,
        sha256_hex: sha,
        size_bytes: size,
        created_at,
    })
}

fn spi_binding_from_row(row: &sqlx::postgres::PgRow) -> Result<SpiBindingRow, StorageError> {
    let id: String = row.try_get("id").map_err(sqlx_err)?;
    let realm_id: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let interface: String = row.try_get("interface").map_err(sqlx_err)?;
    let provider_urn: String = row.try_get("provider_urn").map_err(sqlx_err)?;
    let priority: i32 = row.try_get("priority").map_err(sqlx_err)?;
    let enabled: bool = row.try_get("enabled").map_err(sqlx_err)?;
    let replaces: Option<String> = row.try_get("replaces").map_err(sqlx_err)?;
    let config: serde_json::Value = row.try_get("config").map_err(sqlx_err)?;
    let created_at: DateTime<Utc> = row.try_get("created_at").map_err(sqlx_err)?;
    let updated_at: DateTime<Utc> = row.try_get("updated_at").map_err(sqlx_err)?;
    Ok(SpiBindingRow {
        id: id.parse().map_err(invalid_id)?,
        realm_id: realm_id.parse().map_err(invalid_id)?,
        interface,
        provider_urn,
        priority,
        enabled,
        config,
        replaces,
        created_at,
        updated_at,
    })
}

fn authn_level_to_str(level: geonosis_core::AuthnLevel) -> &'static str {
    use geonosis_core::AuthnLevel::*;
    match level {
        Anonymous => "anonymous",
        Single => "single",
        Mfa => "mfa",
        HardwareBound => "hardware-bound",
    }
}

fn device_status_to_str(s: DeviceGrantStatus) -> &'static str {
    match s {
        DeviceGrantStatus::Pending => "pending",
        DeviceGrantStatus::Approved => "approved",
        DeviceGrantStatus::Denied => "denied",
        DeviceGrantStatus::Expired => "expired",
    }
}

fn session_from_row(row: &sqlx::postgres::PgRow) -> Result<Session, StorageError> {
    use geonosis_core::AuthnLevel;
    let id: String = row.try_get("id").map_err(sqlx_err)?;
    let realm_id: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let user_id: String = row.try_get("user_id").map_err(sqlx_err)?;
    let authn: String = row.try_get("authn_level").map_err(sqlx_err)?;
    let idp_alias: Option<String> = row.try_get("idp_alias").map_err(sqlx_err)?;
    let started_at: DateTime<Utc> = row.try_get("started_at").map_err(sqlx_err)?;
    let last_seen_at: DateTime<Utc> = row.try_get("last_seen_at").map_err(sqlx_err)?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at").map_err(sqlx_err)?;
    let clients: serde_json::Value = row.try_get("clients").map_err(sqlx_err)?;
    let level = match authn.as_str() {
        "anonymous" => AuthnLevel::Anonymous,
        "single" => AuthnLevel::Single,
        "mfa" => AuthnLevel::Mfa,
        "hardware-bound" => AuthnLevel::HardwareBound,
        _ => AuthnLevel::Single,
    };
    Ok(Session {
        id: SessionId(id),
        realm_id: realm_id.parse().map_err(invalid_id)?,
        user_id: user_id.parse().map_err(invalid_id)?,
        authn_level: level,
        idp_alias,
        started_at,
        last_seen_at,
        expires_at,
        clients: serde_json::from_value(clients).map_err(json_err)?,
    })
}

fn code_grant_from_row(row: &sqlx::postgres::PgRow) -> Result<CodeGrant, StorageError> {
    let code: String = row.try_get("code").map_err(sqlx_err)?;
    let realm_id: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let client_id: String = row.try_get("client_id").map_err(sqlx_err)?;
    let user_id: String = row.try_get("user_id").map_err(sqlx_err)?;
    let session_id: String = row.try_get("session_id").map_err(sqlx_err)?;
    let scope: serde_json::Value = row.try_get("scope").map_err(sqlx_err)?;
    let redirect_uri: String = row.try_get("redirect_uri").map_err(sqlx_err)?;
    let code_challenge: Option<serde_json::Value> =
        row.try_get("code_challenge").map_err(sqlx_err)?;
    let nonce: Option<String> = row.try_get("nonce").map_err(sqlx_err)?;
    let state: Option<String> = row.try_get("state").map_err(sqlx_err)?;
    let amr: serde_json::Value = row.try_get("amr").map_err(sqlx_err)?;
    let auth_time: DateTime<Utc> = row.try_get("auth_time").map_err(sqlx_err)?;
    let created_at: DateTime<Utc> = row.try_get("created_at").map_err(sqlx_err)?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at").map_err(sqlx_err)?;
    Ok(CodeGrant {
        code: CodeId(code),
        realm_id: realm_id.parse().map_err(invalid_id)?,
        client_id: client_id.parse().map_err(invalid_id)?,
        user_id: user_id.parse().map_err(invalid_id)?,
        session_id: SessionId(session_id),
        scope: serde_json::from_value(scope).map_err(json_err)?,
        redirect_uri: redirect_uri
            .parse()
            .map_err(|e: url::ParseError| StorageError::Backend(e.to_string()))?,
        code_challenge: code_challenge
            .map(serde_json::from_value)
            .transpose()
            .map_err(json_err)?,
        nonce,
        state,
        amr: serde_json::from_value(amr).map_err(json_err)?,
        auth_time,
        created_at,
        expires_at,
    })
}

fn refresh_from_row(row: &sqlx::postgres::PgRow) -> Result<RefreshToken, StorageError> {
    let id: String = row.try_get("id").map_err(sqlx_err)?;
    let family_id: String = row.try_get("family_id").map_err(sqlx_err)?;
    let realm_id: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let client_id: String = row.try_get("client_id").map_err(sqlx_err)?;
    let user_id: String = row.try_get("user_id").map_err(sqlx_err)?;
    let session_id: String = row.try_get("session_id").map_err(sqlx_err)?;
    let scope: serde_json::Value = row.try_get("scope").map_err(sqlx_err)?;
    let issued_at: DateTime<Utc> = row.try_get("issued_at").map_err(sqlx_err)?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at").map_err(sqlx_err)?;
    let used: bool = row.try_get("used").map_err(sqlx_err)?;
    Ok(RefreshToken {
        id: RefreshTokenId(id),
        family_id: family_id.parse().map_err(invalid_id)?,
        realm_id: realm_id.parse().map_err(invalid_id)?,
        client_id: client_id.parse().map_err(invalid_id)?,
        user_id: user_id.parse().map_err(invalid_id)?,
        session_id: SessionId(session_id),
        scope: serde_json::from_value(scope).map_err(json_err)?,
        issued_at,
        expires_at,
        used,
    })
}

fn par_from_row(row: &sqlx::postgres::PgRow) -> Result<ParRequest, StorageError> {
    let request_uri: String = row.try_get("request_uri").map_err(sqlx_err)?;
    let realm_id: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let client_id: String = row.try_get("client_id").map_err(sqlx_err)?;
    let params: serde_json::Value = row.try_get("params").map_err(sqlx_err)?;
    let created_at: DateTime<Utc> = row.try_get("created_at").map_err(sqlx_err)?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at").map_err(sqlx_err)?;
    Ok(ParRequest {
        request_uri,
        realm_id: realm_id.parse().map_err(invalid_id)?,
        client_id: client_id.parse().map_err(invalid_id)?,
        params: serde_json::from_value(params).map_err(json_err)?,
        created_at,
        expires_at,
    })
}

fn device_from_row(row: &sqlx::postgres::PgRow) -> Result<DeviceGrant, StorageError> {
    let device_code: String = row.try_get("device_code").map_err(sqlx_err)?;
    let user_code: String = row.try_get("user_code").map_err(sqlx_err)?;
    let realm_id: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let client_id: String = row.try_get("client_id").map_err(sqlx_err)?;
    let scope: serde_json::Value = row.try_get("scope").map_err(sqlx_err)?;
    let interval: i32 = row.try_get("interval_seconds").map_err(sqlx_err)?;
    let status: String = row.try_get("status").map_err(sqlx_err)?;
    let user_id: Option<String> = row.try_get("user_id").map_err(sqlx_err)?;
    let session_id: Option<String> = row.try_get("session_id").map_err(sqlx_err)?;
    let created_at: DateTime<Utc> = row.try_get("created_at").map_err(sqlx_err)?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at").map_err(sqlx_err)?;
    let last_polled_at: Option<DateTime<Utc>> = row.try_get("last_polled_at").map_err(sqlx_err)?;
    Ok(DeviceGrant {
        device_code,
        user_code,
        realm_id: realm_id.parse().map_err(invalid_id)?,
        client_id: client_id.parse().map_err(invalid_id)?,
        scope: serde_json::from_value(scope).map_err(json_err)?,
        interval_seconds: interval.max(0) as u32,
        status: match status.as_str() {
            "pending" => DeviceGrantStatus::Pending,
            "approved" => DeviceGrantStatus::Approved,
            "denied" => DeviceGrantStatus::Denied,
            _ => DeviceGrantStatus::Expired,
        },
        user_id: user_id.map(|s| s.parse()).transpose().map_err(invalid_id)?,
        session_id: session_id.map(SessionId),
        created_at,
        expires_at,
        last_polled_at,
    })
}

fn flow_state_from_row(row: &sqlx::postgres::PgRow) -> Result<FlowStateRow, StorageError> {
    use geonosis_flow::FlowState;
    let id: String = row.try_get("id").map_err(sqlx_err)?;
    let realm_id: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let flow_id: String = row.try_get("flow_id").map_err(sqlx_err)?;
    let flow_version: i32 = row.try_get("flow_version").map_err(sqlx_err)?;
    let current_node: String = row.try_get("current_node").map_err(sqlx_err)?;
    let history: serde_json::Value = row.try_get("history").map_err(sqlx_err)?;
    let context: serde_json::Value = row.try_get("context").map_err(sqlx_err)?;
    let authorize_params: serde_json::Value =
        row.try_get("authorize_params").map_err(sqlx_err)?;
    let started_at: DateTime<Utc> = row.try_get("started_at").map_err(sqlx_err)?;
    let last_activity_at: DateTime<Utc> = row.try_get("last_activity_at").map_err(sqlx_err)?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at").map_err(sqlx_err)?;
    let csrf_token: String = row.try_get("csrf_token").map_err(sqlx_err)?;
    Ok(FlowStateRow {
        state: FlowState {
            id: id.parse().map_err(invalid_id)?,
            realm_id: realm_id.parse().map_err(invalid_id)?,
            flow_id: flow_id.parse().map_err(invalid_id)?,
            flow_version,
            current_node: current_node.parse().map_err(invalid_id)?,
            history: serde_json::from_value(history).map_err(json_err)?,
            context: serde_json::from_value(context).map_err(json_err)?,
            started_at,
            last_activity_at,
            expires_at,
            csrf_token: geonosis_flow::CsrfToken(csrf_token),
        },
        authorize_params: serde_json::from_value(authorize_params).map_err(json_err)?,
    })
}

fn consent_from_row(row: &sqlx::postgres::PgRow) -> Result<ConsentGrant, StorageError> {
    let id: String = row.try_get("id").map_err(sqlx_err)?;
    let realm_id: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let user_id: String = row.try_get("user_id").map_err(sqlx_err)?;
    let client_id: String = row.try_get("client_id").map_err(sqlx_err)?;
    let scopes: serde_json::Value = row.try_get("scopes").map_err(sqlx_err)?;
    let granted_at: DateTime<Utc> = row.try_get("granted_at").map_err(sqlx_err)?;
    let updated_at: DateTime<Utc> = row.try_get("updated_at").map_err(sqlx_err)?;
    Ok(ConsentGrant {
        id: id.parse().map_err(invalid_id)?,
        realm_id: realm_id.parse().map_err(invalid_id)?,
        user_id: user_id.parse().map_err(invalid_id)?,
        client_id: client_id.parse().map_err(invalid_id)?,
        scopes: serde_json::from_value(scopes).map_err(json_err)?,
        granted_at,
        updated_at,
    })
}

/// Default connection pool settings for v0.1 per
/// `docs/01-architecture.md` cross-pod consistency model.
pub async fn build_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(32)
        .min_connections(4)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .idle_timeout(std::time::Duration::from_secs(300))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .test_before_acquire(true)
        .connect(database_url)
        .await
}

// ---- Phase-0 row parsers + enum-to-str helpers ----

fn role_from_row(row: &sqlx::postgres::PgRow) -> Result<Role, StorageError> {
    let id_s: String = row.try_get("id").map_err(sqlx_err)?;
    let realm_id_s: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let client_id_s: Option<String> = row.try_get("client_id").map_err(sqlx_err)?;
    let name: String = row.try_get("name").map_err(sqlx_err)?;
    let description: Option<String> = row.try_get("description").map_err(sqlx_err)?;
    let composites: serde_json::Value = row.try_get("composites").map_err(sqlx_err)?;
    let attributes: serde_json::Value = row.try_get("attributes").map_err(sqlx_err)?;
    let created_at: DateTime<Utc> = row.try_get("created_at").map_err(sqlx_err)?;
    let updated_at: DateTime<Utc> = row.try_get("updated_at").map_err(sqlx_err)?;
    Ok(Role {
        id: id_s.parse().map_err(invalid_id)?,
        realm_id: realm_id_s.parse().map_err(invalid_id)?,
        client_id: client_id_s
            .map(|s| s.parse())
            .transpose()
            .map_err(invalid_id)?,
        name,
        description,
        composites: serde_json::from_value(composites).map_err(json_err)?,
        attributes: serde_json::from_value(attributes).map_err(json_err)?,
        created_at,
        updated_at,
    })
}

fn group_from_row(row: &sqlx::postgres::PgRow) -> Result<Group, StorageError> {
    let id_s: String = row.try_get("id").map_err(sqlx_err)?;
    let realm_id_s: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let parent_id_s: Option<String> = row.try_get("parent_id").map_err(sqlx_err)?;
    let name: String = row.try_get("name").map_err(sqlx_err)?;
    let path: String = row.try_get("path").map_err(sqlx_err)?;
    let attributes: serde_json::Value = row.try_get("attributes").map_err(sqlx_err)?;
    let created_at: DateTime<Utc> = row.try_get("created_at").map_err(sqlx_err)?;
    let updated_at: DateTime<Utc> = row.try_get("updated_at").map_err(sqlx_err)?;
    Ok(Group {
        id: id_s.parse().map_err(invalid_id)?,
        realm_id: realm_id_s.parse().map_err(invalid_id)?,
        parent_id: parent_id_s
            .map(|s| s.parse())
            .transpose()
            .map_err(invalid_id)?,
        name,
        path,
        attributes: serde_json::from_value(attributes).map_err(json_err)?,
        // Role assignments live in the join tables (`user_role`,
        // `group_role`), not the group row itself. The legacy
        // realm_role_ids / client_role_ids fields on `Group` are kept
        // for in-memory composition; the postgres row returns them
        // empty and the storage caller composes via list_group_roles
        // when needed.
        realm_role_ids: vec![],
        client_role_ids: std::collections::BTreeMap::new(),
        created_at,
        updated_at,
    })
}

fn agent_from_row(row: &sqlx::postgres::PgRow) -> Result<Agent, StorageError> {
    let id_s: String = row.try_get("id").map_err(sqlx_err)?;
    let realm_id_s: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let alias: String = row.try_get("alias").map_err(sqlx_err)?;
    let display_name: String = row.try_get("display_name").map_err(sqlx_err)?;
    let kind: String = row.try_get("kind").map_err(sqlx_err)?;
    let model_hint: Option<String> = row.try_get("model_hint").map_err(sqlx_err)?;
    let vendor: Option<String> = row.try_get("vendor").map_err(sqlx_err)?;
    let version: Option<String> = row.try_get("version").map_err(sqlx_err)?;
    let parent_subject: serde_json::Value =
        row.try_get("parent_subject").map_err(sqlx_err)?;
    let capabilities: serde_json::Value = row.try_get("capabilities").map_err(sqlx_err)?;
    let allowed_scopes: serde_json::Value =
        row.try_get("allowed_scopes").map_err(sqlx_err)?;
    let allowed_audiences: serde_json::Value =
        row.try_get("allowed_audiences").map_err(sqlx_err)?;
    let rate_limit: serde_json::Value = row.try_get("rate_limit").map_err(sqlx_err)?;
    let auth_method: String = row.try_get("auth_method").map_err(sqlx_err)?;
    let public_jwk: Option<serde_json::Value> = row.try_get("public_jwk").map_err(sqlx_err)?;
    let created_at: DateTime<Utc> = row.try_get("created_at").map_err(sqlx_err)?;
    let expires_at: Option<DateTime<Utc>> = row.try_get("expires_at").map_err(sqlx_err)?;
    let revoked_at: Option<DateTime<Utc>> = row.try_get("revoked_at").map_err(sqlx_err)?;
    let enabled: bool = row.try_get("enabled").map_err(sqlx_err)?;
    Ok(Agent {
        id: id_s.parse().map_err(invalid_id)?,
        realm_id: realm_id_s.parse().map_err(invalid_id)?,
        alias,
        display_name,
        kind: agent_kind_from_str(&kind),
        model_hint,
        vendor,
        version,
        parent_subject: serde_json::from_value(parent_subject).map_err(json_err)?,
        capabilities: serde_json::from_value(capabilities).map_err(json_err)?,
        allowed_scopes: serde_json::from_value(allowed_scopes).map_err(json_err)?,
        allowed_audiences: serde_json::from_value(allowed_audiences).map_err(json_err)?,
        rate_limit: serde_json::from_value(rate_limit).map_err(json_err)?,
        auth_method: agent_auth_method_from_str(&auth_method)?,
        public_jwk,
        created_at,
        expires_at,
        revoked_at,
        enabled,
    })
}

fn agent_kind_to_str(k: &geonosis_core::AgentKind) -> String {
    serde_json::to_value(k)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "custom".into())
}

fn agent_kind_from_str(s: &str) -> geonosis_core::AgentKind {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .unwrap_or_else(|_| geonosis_core::AgentKind::Custom(s.to_string()))
}

fn agent_auth_method_to_str(m: geonosis_core::AgentAuthMethod) -> &'static str {
    use geonosis_core::AgentAuthMethod::*;
    match m {
        PrivateKeyJwt => "private-key-jwt",
        DpopBoundKey => "dpop-bound-key",
        TokenExchangeOnly => "token-exchange-only",
    }
}

fn agent_auth_method_from_str(s: &str) -> Result<geonosis_core::AgentAuthMethod, StorageError> {
    use geonosis_core::AgentAuthMethod::*;
    match s {
        "private-key-jwt" => Ok(PrivateKeyJwt),
        "dpop-bound-key" => Ok(DpopBoundKey),
        "token-exchange-only" => Ok(TokenExchangeOnly),
        other => Err(StorageError::Invalid(format!("agent auth_method: {other}"))),
    }
}

fn organization_from_row(row: &sqlx::postgres::PgRow) -> Result<Organization, StorageError> {
    let id_s: String = row.try_get("id").map_err(sqlx_err)?;
    let realm_id_s: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let alias: String = row.try_get("alias").map_err(sqlx_err)?;
    let display_name: String = row.try_get("display_name").map_err(sqlx_err)?;
    let description: Option<String> = row.try_get("description").map_err(sqlx_err)?;
    let branding: serde_json::Value = row.try_get("branding").map_err(sqlx_err)?;
    let attributes: serde_json::Value = row.try_get("attributes").map_err(sqlx_err)?;
    let default_idp_alias: Option<String> = row.try_get("default_idp_alias").map_err(sqlx_err)?;
    let redirect_url_s: Option<String> = row.try_get("redirect_url").map_err(sqlx_err)?;
    let enabled: bool = row.try_get("enabled").map_err(sqlx_err)?;
    let created_at: DateTime<Utc> = row.try_get("created_at").map_err(sqlx_err)?;
    let updated_at: DateTime<Utc> = row.try_get("updated_at").map_err(sqlx_err)?;
    Ok(Organization {
        id: id_s.parse().map_err(invalid_id)?,
        realm_id: realm_id_s.parse().map_err(invalid_id)?,
        alias,
        display_name,
        description,
        attributes: serde_json::from_value(attributes).map_err(json_err)?,
        branding: serde_json::from_value(branding).map_err(json_err)?,
        default_idp_alias,
        redirect_url: redirect_url_s
            .map(|s| s.parse::<url::Url>())
            .transpose()
            .map_err(|e| StorageError::Backend(e.to_string()))?,
        enabled,
        created_at,
        updated_at,
    })
}

fn org_domain_from_row(row: &sqlx::postgres::PgRow) -> Result<OrgDomain, StorageError> {
    let id_s: String = row.try_get("id").map_err(sqlx_err)?;
    let organization_id_s: String = row.try_get("organization_id").map_err(sqlx_err)?;
    let realm_id_s: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let domain: String = row.try_get("domain").map_err(sqlx_err)?;
    let verified: bool = row.try_get("verified").map_err(sqlx_err)?;
    let verification_token: Option<String> =
        row.try_get("verification_token").map_err(sqlx_err)?;
    let verified_at: Option<DateTime<Utc>> = row.try_get("verified_at").map_err(sqlx_err)?;
    Ok(OrgDomain {
        id: id_s.parse().map_err(invalid_id)?,
        organization_id: organization_id_s.parse().map_err(invalid_id)?,
        realm_id: realm_id_s.parse().map_err(invalid_id)?,
        domain,
        verified,
        verification_token,
        verified_at,
    })
}

fn org_membership_from_row(row: &sqlx::postgres::PgRow) -> Result<OrgMembership, StorageError> {
    let organization_id_s: String = row.try_get("organization_id").map_err(sqlx_err)?;
    let realm_id_s: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let user_id_s: String = row.try_get("user_id").map_err(sqlx_err)?;
    let roles: serde_json::Value = row.try_get("roles").map_err(sqlx_err)?;
    let invited_by_s: Option<String> = row.try_get("invited_by").map_err(sqlx_err)?;
    let state_s: String = row.try_get("state").map_err(sqlx_err)?;
    let joined_at: DateTime<Utc> = row.try_get("joined_at").map_err(sqlx_err)?;
    Ok(OrgMembership {
        organization_id: organization_id_s.parse().map_err(invalid_id)?,
        realm_id: realm_id_s.parse().map_err(invalid_id)?,
        user_id: user_id_s.parse().map_err(invalid_id)?,
        roles: serde_json::from_value(roles).map_err(json_err)?,
        invited_by: invited_by_s
            .map(|s| s.parse())
            .transpose()
            .map_err(invalid_id)?,
        state: membership_state_from_str(&state_s)?,
        joined_at,
    })
}

fn membership_state_to_str(s: geonosis_core::MembershipState) -> &'static str {
    use geonosis_core::MembershipState::*;
    match s {
        Active => "active",
        Invited => "invited",
        Suspended => "suspended",
    }
}

fn membership_state_from_str(s: &str) -> Result<geonosis_core::MembershipState, StorageError> {
    use geonosis_core::MembershipState::*;
    match s {
        "active" => Ok(Active),
        "invited" => Ok(Invited),
        "suspended" => Ok(Suspended),
        other => Err(StorageError::Invalid(format!(
            "membership state: {other}"
        ))),
    }
}

fn org_role_from_row(row: &sqlx::postgres::PgRow) -> Result<OrgRole, StorageError> {
    let id_s: String = row.try_get("id").map_err(sqlx_err)?;
    let organization_id_s: String = row.try_get("organization_id").map_err(sqlx_err)?;
    let realm_id_s: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let name: String = row.try_get("name").map_err(sqlx_err)?;
    let description: Option<String> = row.try_get("description").map_err(sqlx_err)?;
    let permissions: serde_json::Value = row.try_get("permissions").map_err(sqlx_err)?;
    let built_in: bool = row.try_get("built_in").map_err(sqlx_err)?;
    Ok(OrgRole {
        id: id_s.parse().map_err(invalid_id)?,
        organization_id: organization_id_s.parse().map_err(invalid_id)?,
        realm_id: realm_id_s.parse().map_err(invalid_id)?,
        name,
        description,
        permissions: serde_json::from_value(permissions).map_err(json_err)?,
        built_in,
    })
}

fn org_invitation_from_row(row: &sqlx::postgres::PgRow) -> Result<OrgInvitation, StorageError> {
    let id_s: String = row.try_get("id").map_err(sqlx_err)?;
    let organization_id_s: String = row.try_get("organization_id").map_err(sqlx_err)?;
    let realm_id_s: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let email: String = row.try_get("email").map_err(sqlx_err)?;
    let roles: serde_json::Value = row.try_get("roles").map_err(sqlx_err)?;
    let invited_by_s: String = row.try_get("invited_by").map_err(sqlx_err)?;
    let token: String = row.try_get("token").map_err(sqlx_err)?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at").map_err(sqlx_err)?;
    let accepted_at: Option<DateTime<Utc>> = row.try_get("accepted_at").map_err(sqlx_err)?;
    Ok(OrgInvitation {
        id: id_s.parse().map_err(invalid_id)?,
        organization_id: organization_id_s.parse().map_err(invalid_id)?,
        realm_id: realm_id_s.parse().map_err(invalid_id)?,
        email,
        roles: serde_json::from_value(roles).map_err(json_err)?,
        invited_by: invited_by_s.parse().map_err(invalid_id)?,
        token: geonosis_core::Secret::new(token),
        expires_at,
        accepted_at,
    })
}

fn org_consent_policy_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<OrgConsentPolicy, StorageError> {
    let id_s: String = row.try_get("id").map_err(sqlx_err)?;
    let organization_id_s: String = row.try_get("organization_id").map_err(sqlx_err)?;
    let realm_id_s: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let client_id_s: String = row.try_get("client_id").map_err(sqlx_err)?;
    let mode_s: String = row.try_get("mode").map_err(sqlx_err)?;
    let pre_approved_scopes: serde_json::Value =
        row.try_get("pre_approved_scopes").map_err(sqlx_err)?;
    let blocked_scopes: serde_json::Value =
        row.try_get("blocked_scopes").map_err(sqlx_err)?;
    let require_admin_approval: bool =
        row.try_get("require_admin_approval").map_err(sqlx_err)?;
    let created_by_s: String = row.try_get("created_by").map_err(sqlx_err)?;
    let created_at: DateTime<Utc> = row.try_get("created_at").map_err(sqlx_err)?;
    let updated_at: DateTime<Utc> = row.try_get("updated_at").map_err(sqlx_err)?;
    Ok(OrgConsentPolicy {
        id: id_s.parse().map_err(invalid_id)?,
        organization_id: organization_id_s.parse().map_err(invalid_id)?,
        realm_id: realm_id_s.parse().map_err(invalid_id)?,
        client_id: client_id_s.parse().map_err(invalid_id)?,
        mode: org_consent_mode_from_str(&mode_s)?,
        pre_approved_scopes: serde_json::from_value(pre_approved_scopes).map_err(json_err)?,
        blocked_scopes: serde_json::from_value(blocked_scopes).map_err(json_err)?,
        require_admin_approval,
        created_by: created_by_s.parse().map_err(invalid_id)?,
        created_at,
        updated_at,
    })
}

fn org_consent_mode_to_str(m: geonosis_core::OrgConsentMode) -> &'static str {
    use geonosis_core::OrgConsentMode::*;
    match m {
        UserDecides => "user-decides",
        OrgPreApproved => "org-pre-approved",
        OrgManaged => "org-managed",
    }
}

fn org_consent_mode_from_str(
    s: &str,
) -> Result<geonosis_core::OrgConsentMode, StorageError> {
    use geonosis_core::OrgConsentMode::*;
    match s {
        "user-decides" => Ok(UserDecides),
        "org-pre-approved" => Ok(OrgPreApproved),
        "org-managed" => Ok(OrgManaged),
        other => Err(StorageError::Invalid(format!(
            "org consent mode: {other}"
        ))),
    }
}

fn org_idp_binding_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<OrgIdpBinding, StorageError> {
    let organization_id_s: String = row.try_get("organization_id").map_err(sqlx_err)?;
    let realm_id_s: String = row.try_get("realm_id").map_err(sqlx_err)?;
    let idp_alias: String = row.try_get("idp_alias").map_err(sqlx_err)?;
    let priority: i32 = row.try_get("priority").map_err(sqlx_err)?;
    let enabled: bool = row.try_get("enabled").map_err(sqlx_err)?;
    Ok(OrgIdpBinding {
        organization_id: organization_id_s.parse().map_err(invalid_id)?,
        realm_id: realm_id_s.parse().map_err(invalid_id)?,
        idp_alias,
        priority,
        enabled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_kind_strings_match_migration_check() {
        for k in [
            geonosis_core::ClientKind::Confidential,
            geonosis_core::ClientKind::Public,
            geonosis_core::ClientKind::BearerOnly,
            geonosis_core::ClientKind::ServiceAccount,
            geonosis_core::ClientKind::SamlServiceProvider,
            geonosis_core::ClientKind::ScimClient,
        ] {
            let s = client_kind_as_str(k);
            assert!(matches!(
                s,
                "confidential"
                    | "public"
                    | "bearer-only"
                    | "service-account"
                    | "saml-service-provider"
                    | "scim-client"
            ));
        }
    }

    #[test]
    fn authn_level_strings_match_doc_kebab_case() {
        use geonosis_core::AuthnLevel::*;
        assert_eq!(authn_level_to_str(Anonymous), "anonymous");
        assert_eq!(authn_level_to_str(Single), "single");
        assert_eq!(authn_level_to_str(Mfa), "mfa");
        assert_eq!(authn_level_to_str(HardwareBound), "hardware-bound");
    }

    #[test]
    fn device_status_strings_match_migration_check() {
        assert_eq!(device_status_to_str(DeviceGrantStatus::Pending), "pending");
        assert_eq!(device_status_to_str(DeviceGrantStatus::Approved), "approved");
        assert_eq!(device_status_to_str(DeviceGrantStatus::Denied), "denied");
        assert_eq!(device_status_to_str(DeviceGrantStatus::Expired), "expired");
    }

    #[test]
    fn invalid_id_wraps_into_storage_invalid() {
        let err = "not-a-ulid".parse::<RealmId>().unwrap_err();
        let se = invalid_id(err);
        assert!(matches!(se, StorageError::Invalid(_)));
    }

    #[test]
    fn membership_state_roundtrips() {
        use geonosis_core::MembershipState::*;
        for s in [Active, Invited, Suspended] {
            let txt = membership_state_to_str(s);
            assert_eq!(membership_state_from_str(txt).unwrap(), s);
        }
        assert!(membership_state_from_str("bogus").is_err());
    }

    #[test]
    fn org_consent_mode_roundtrips() {
        use geonosis_core::OrgConsentMode::*;
        for m in [UserDecides, OrgPreApproved, OrgManaged] {
            let txt = org_consent_mode_to_str(m);
            assert_eq!(org_consent_mode_from_str(txt).unwrap(), m);
        }
        assert!(org_consent_mode_from_str("bogus").is_err());
    }

    #[test]
    fn agent_auth_method_roundtrips() {
        use geonosis_core::AgentAuthMethod::*;
        for m in [PrivateKeyJwt, DpopBoundKey, TokenExchangeOnly] {
            let txt = agent_auth_method_to_str(m);
            assert_eq!(agent_auth_method_from_str(txt).unwrap(), m);
        }
        assert!(agent_auth_method_from_str("bogus").is_err());
    }

    #[test]
    fn agent_kind_roundtrips_kebab_and_custom() {
        use geonosis_core::AgentKind::*;
        // Built-in kebab variants.
        for k in [Assistant, Scraper, Webhook, Batch] {
            let txt = agent_kind_to_str(&k);
            assert_eq!(agent_kind_from_str(&txt), k);
        }
        // Custom variant flows through as an opaque tag.
        let custom = Custom("inventory-bot".into());
        let txt = agent_kind_to_str(&custom);
        assert_eq!(agent_kind_from_str(&txt), custom);
    }
}
