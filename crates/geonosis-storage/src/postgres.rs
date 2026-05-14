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
    Client, ClientId, CodeGrant, CodeId, Realm, RealmId, RefreshToken, RefreshTokenId, Session,
    SessionId, TokenFamilyId, User, UserId,
};
use geonosis_federation_ldap::LdapFederationConfig;

use crate::error::StorageError;
use crate::traits::{
    ConsentGrant, DeviceGrant, DeviceGrantStatus, FlowStateRow, ParRequest, SpiBindingRow,
    Storage, WasmModule, WasmModuleHeader,
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
}
