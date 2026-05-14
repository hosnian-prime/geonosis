//! `GEONOSIS_BOOTSTRAP_QUICKSTART=1` — one-shot demo realm provisioning.
//!
//! Per `docs/21-dx-package.md` §"The 5-minute quickstart" the
//! quickstart compose stack expects this gate to exist: setting the
//! env var on a fresh database leaves the operator with realm
//! `acme`, end-user `ada@acme.test` (pw `ada-pw`), admin user
//! `admin@acme.test` (pw `admin-pw`), and OIDC client `acme-web`
//! with redirect URI `http://127.0.0.1:8888/callback`.
//!
//! Safety properties this module enforces:
//!
//! - **Idempotent**: if realm `acme` already exists, the run is a
//!   no-op so restart loops do not duplicate state.
//! - **Production-safe by construction**: the only entry point is
//!   guarded by an env-var check at the call site
//!   (`main` checks `bootstrap_quickstart` from `Args`). The
//!   production Helm chart in `deploy/helm/geonosis/` does not set
//!   the env var, so a misconfigured image cannot leak this state
//!   into a real cluster.
//! - **Dev-credential disclaimer**: every successful run logs the
//!   credentials at WARN level so an operator never thinks they're
//!   accidentally running this in production with the demo password.

use std::sync::Arc;

use chrono::Utc;
use geonosis_core::{
    AccessTokenType, Client, ClientAuthMethod, ClientId, ClientKind, ConsentPolicy, CredentialId,
    CredentialKind, CredentialRef, FlowBinding, GrantPolicy, PasswordRule, Realm, RealmId,
    RedirectUri, SenderConstraint, SslRequirement, User, UserId,
};
use geonosis_storage::Storage;

const REALM_SLUG: &str = "acme";
const REALM_DISPLAY: &str = "Acme (quickstart)";
const ADMIN_USER: &str = "admin@acme.test";
const ADMIN_PW: &str = "admin-pw";
const END_USER: &str = "ada@acme.test";
const END_USER_PW: &str = "ada-pw";
const CLIENT_ID: &str = "acme-web";
const REDIRECT_URI: &str = "http://127.0.0.1:8888/callback";

#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("storage: {0}")]
    Storage(#[from] geonosis_storage::StorageError),
    #[error("password hashing: {0}")]
    Hash(String),
}

/// Run the quickstart bootstrap. Idempotent: short-circuits if realm
/// `acme` already exists with no further checks (per the v0.1 demo
/// contract — re-running the compose stack must not error).
pub async fn run(storage: Arc<dyn Storage>) -> Result<(), BootstrapError> {
    if storage.get_realm_by_slug(REALM_SLUG).await.is_ok() {
        tracing::info!(
            realm = REALM_SLUG,
            "GEONOSIS_BOOTSTRAP_QUICKSTART: realm already provisioned; skipping"
        );
        return Ok(());
    }

    tracing::warn!(
        admin_user = ADMIN_USER,
        admin_pw = ADMIN_PW,
        end_user = END_USER,
        end_user_pw = END_USER_PW,
        client_id = CLIENT_ID,
        redirect_uri = REDIRECT_URI,
        "GEONOSIS_BOOTSTRAP_QUICKSTART: provisioning demo realm — credentials are public; do NOT use in production"
    );

    let now = Utc::now();
    let realm_id = RealmId::new();
    let realm = Realm {
        id: realm_id,
        slug: REALM_SLUG.into(),
        display_name: REALM_DISPLAY.into(),
        frontend_url: None,
        admin_frontend_url: None,
        enabled: true,
        ssl_required: SslRequirement::None,
        login: Default::default(),
        registration: Default::default(),
        session_policy: Default::default(),
        token_policy: Default::default(),
        brute_force: Default::default(),
        password_policy: relaxed_password_policy(),
        otp_policy: Default::default(),
        webauthn_policy: Default::default(),
        acr_policy: Default::default(),
        sender_constraint_default: SenderConstraint::None,
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
    storage.create_realm(realm).await?;
    geonosis_storage::seed_default_flows(storage.as_ref(), realm_id).await?;

    provision_user(&storage, realm_id, END_USER, END_USER_PW, false, now).await?;
    provision_user(&storage, realm_id, ADMIN_USER, ADMIN_PW, true, now).await?;
    provision_client(&storage, realm_id, now).await?;

    tracing::info!(
        realm = REALM_SLUG,
        client_id = CLIENT_ID,
        "GEONOSIS_BOOTSTRAP_QUICKSTART: provisioning complete"
    );
    Ok(())
}

async fn provision_user(
    storage: &Arc<dyn Storage>,
    realm_id: RealmId,
    username: &str,
    password: &str,
    is_admin: bool,
    now: chrono::DateTime<Utc>,
) -> Result<(), BootstrapError> {
    let user_id = UserId::new();
    let credential_id = CredentialId::new();
    let mut attributes = std::collections::BTreeMap::new();
    if is_admin {
        attributes.insert(
            "admin".to_string(),
            geonosis_core::attribute::AttributeValue::Bool(true),
        );
    }
    let user = User {
        id: user_id,
        realm_id,
        username: username.to_string(),
        email: Some(username.to_string()),
        email_verified: true,
        name: None,
        credentials: vec![CredentialRef {
            id: credential_id,
            kind: CredentialKind::Password,
            label: Some("quickstart".into()),
            created_at: now,
            last_used_at: None,
        }],
        federation: None,
        attributes,
        required_actions: vec![],
        required_flow: None,
        organizations: vec![],
        enabled: true,
        failed_attempts: 0,
        locked_until: None,
        last_failed_at: None,
        created_at: now,
        updated_at: now,
    };
    storage.create_user(user).await?;

    let hash = geonosis_crypto::hash_password(password)
        .map_err(|e| BootstrapError::Hash(e.to_string()))?;
    storage.store_password_hash(realm_id, user_id, hash).await?;
    Ok(())
}

async fn provision_client(
    storage: &Arc<dyn Storage>,
    realm_id: RealmId,
    now: chrono::DateTime<Utc>,
) -> Result<(), BootstrapError> {
    let client = Client {
        id: ClientId::new(),
        realm_id,
        client_id: CLIENT_ID.into(),
        display_name: Some("Acme Web (quickstart)".into()),
        kind: ClientKind::Public,
        grants: GrantPolicy::public_app(),
        auth_method: ClientAuthMethod::None,
        flow_binding: FlowBinding::default(),
        default_scopes: vec![],
        optional_scopes: vec![],
        redirect_uris: vec![RedirectUri {
            uri: REDIRECT_URI.into(),
            wildcard_path: false,
        }],
        post_logout_redirect_uris: vec![],
        web_origins: vec![],
        access_token_type: AccessTokenType::Jwt,
        consent: ConsentPolicy::default(),
        access_token_lifespan: None,
        refresh_token_lifespan: None,
        access_token_signing_alg: None,
        front_channel_logout_enabled: false,
        backchannel_logout_url: None,
        client_authentication_keys: vec![],
        pairwise_sub_algorithm: None,
        saml_sp_config: None,
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    storage.create_client(client).await?;
    Ok(())
}

/// Quickstart credentials are intentionally short (`ada-pw`) so the
/// recipe's curl commands stay copy-pasteable. The default
/// PasswordPolicy enforces a minimum length that would reject them.
fn relaxed_password_policy() -> geonosis_core::PasswordPolicy {
    geonosis_core::PasswordPolicy {
        rules: vec![PasswordRule::Length { min: 4 }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn quickstart_bootstrap_seeds_built_in_flows() {
        // Without the flow seed an /authorize against the bootstrapped
        // realm 500s with "realm has no browser flow" — assert all 7
        // canonical aliases land so the recipe is reproducible.
        let storage: Arc<dyn Storage> = Arc::new(geonosis_storage::MemoryStorage::new());
        run(storage.clone()).await.unwrap();
        let realm = storage.get_realm_by_slug(REALM_SLUG).await.unwrap();
        let mut aliases: Vec<String> = storage
            .list_auth_flows(realm.id)
            .await
            .unwrap()
            .into_iter()
            .map(|f| f.alias)
            .collect();
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
    async fn quickstart_bootstrap_creates_realm_and_users() {
        let storage: Arc<dyn Storage> = Arc::new(geonosis_storage::MemoryStorage::new());
        run(storage.clone()).await.unwrap();
        let realm = storage.get_realm_by_slug(REALM_SLUG).await.unwrap();
        assert_eq!(realm.slug, REALM_SLUG);
        assert!(storage
            .get_user_by_username(realm.id, END_USER)
            .await
            .is_ok());
        assert!(storage
            .get_user_by_username(realm.id, ADMIN_USER)
            .await
            .is_ok());
        assert!(storage
            .get_client_by_client_id(realm.id, CLIENT_ID)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn quickstart_bootstrap_is_idempotent() {
        let storage: Arc<dyn Storage> = Arc::new(geonosis_storage::MemoryStorage::new());
        run(storage.clone()).await.unwrap();
        // Second run on an already-bootstrapped store must succeed
        // without duplicating users or returning an error.
        run(storage.clone()).await.unwrap();
        let realm = storage.get_realm_by_slug(REALM_SLUG).await.unwrap();
        let users = storage.list_users(realm.id, 100).await.unwrap();
        assert_eq!(users.len(), 2);
    }
}
