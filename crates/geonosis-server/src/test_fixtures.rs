//! Shared test fixtures for integration and unit tests.
//!
//! Extracted from `app.rs` inline tests so that crate-level integration
//! tests (`tests/`) can reuse the same `AppState` construction,
//! client/user seeding, and session helpers.

use std::sync::Arc;

use chrono::Utc;

use geonosis_audit::Publisher;
use geonosis_cache::LocalCache;
use geonosis_core::realm::DefaultRoles;
use geonosis_core::{
    AcrPolicy, BruteForcePolicy, EventConfig, LocalizationPolicy, LoginSettings, OtpPolicy,
    PasswordPolicy, Realm, RealmId, RegistrationPolicy, SenderConstraint, SessionPolicy,
    SslRequirement, ThemeBinding, TokenPolicy, WebauthnPolicy,
};
use geonosis_crypto::{MasterKey, SoftwareKms};
use geonosis_spi_host::ProviderRegistry;
use geonosis_storage::{MemoryStorage, Storage};

use crate::state::AppState;

/// Build a fully-wired `AppState` backed by `MemoryStorage` with one
/// seeded realm (slug = `"acme"`). Each call generates a fresh
/// `MasterKey` so tests are isolated.
pub async fn fixture_state() -> AppState {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    // Tests use EdDSA so we don't pay the RSA key-gen cost per fixture.
    let token_policy = TokenPolicy {
        default_signing_alg: geonosis_core::JwsAlgorithm::EdDSA,
        ..TokenPolicy::default()
    };
    let realm = Realm {
        id: RealmId::new(),
        slug: "acme".into(),
        display_name: "Acme".into(),
        frontend_url: None,
        admin_frontend_url: None,
        enabled: true,
        ssl_required: SslRequirement::ExternalRequests,
        login: LoginSettings::default(),
        registration: RegistrationPolicy::default(),
        session_policy: SessionPolicy::default(),
        token_policy,
        brute_force: BruteForcePolicy::default(),
        password_policy: PasswordPolicy::default(),
        otp_policy: OtpPolicy::default(),
        webauthn_policy: WebauthnPolicy::default(),
        acr_policy: AcrPolicy::default(),
        sender_constraint_default: SenderConstraint::None,
        theme_binding: ThemeBinding::default(),
        localization: LocalizationPolicy::default(),
        events: EventConfig::default(),
        default_groups: vec![],
        default_roles: DefaultRoles::default(),
        organizations_enabled: true,
        organization_policy: Default::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    storage.create_realm(realm).await.unwrap();
    AppState {
        storage,
        cache: Arc::new(LocalCache::default_small()),
        kms: Arc::new(SoftwareKms::new(MasterKey::generate())),
        providers: Arc::new(ProviderRegistry::new()),
        audit: Arc::new(Publisher::new(vec![])),
        public_base_url: url::Url::parse("https://g.example").unwrap(),
        refresh_hash_key: [42u8; 32],
        client_secret_hash_key: [99u8; 32],
        authenticators: Arc::new(crate::authenticators::BuiltinAuthenticators::default()),
        broker_adapters: Arc::new(geonosis_broker::BuiltinAdapters::default()),
        broker: Arc::new(crate::broker::BrokerRuntime::new()),
        ldap: Arc::new(crate::ldap::LdapRuntime::new()),
        metrics: Arc::new(crate::metrics::MetricsState::new()),
        rate_limiter: Arc::new(crate::rate_limit::CompositeRateLimiter::local_only()),
        wasm_engine: geonosis_spi_host::runtime::WasmEngine::new(
            geonosis_spi_host::runtime::SandboxConfig::default(),
        )
        .expect("wasm engine bootstrap"),
        draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    }
}

/// Create an admin session and return the cookie header value for
/// test requests that hit auth-protected admin routes.
pub async fn admin_session_cookie(state: &AppState) -> String {
    use geonosis_core::attribute::AttributeValue;
    use geonosis_core::common::AuthnLevel;

    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    let user_id = geonosis_core::id::UserId::new();
    let now = Utc::now();
    let user = geonosis_core::User {
        id: user_id,
        realm_id: realm.id,
        username: "test-admin@acme.test".into(),
        email: Some("test-admin@acme.test".into()),
        email_verified: true,
        name: None,
        credentials: vec![],
        federation: None,
        attributes: [("admin".into(), AttributeValue::Bool(true))]
            .into_iter()
            .collect(),
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
    state.storage.create_user(user).await.unwrap();
    let session = geonosis_core::Session {
        id: geonosis_core::id::SessionId::new_random(),
        realm_id: realm.id,
        user_id,
        authn_level: AuthnLevel::Single,
        idp_alias: None,
        started_at: now,
        last_seen_at: now,
        expires_at: now + chrono::Duration::hours(1),
        clients: vec![],
    };
    let sid = session.id.to_string();
    state.storage.create_session(session).await.unwrap();
    format!("geonosis_admin_sid={sid}")
}

/// Seed an EdDSA signing key into the KMS for the given realm.
/// Required before any token can be minted.
pub async fn seed_eddsa_key(state: &AppState, realm_id: RealmId) {
    use ed25519_dalek::SigningKey;
    use geonosis_crypto::{
        jwk::Jwk,
        kms::{KeyMaterial, KeyState, KeyUsage, PrivateKeyRef},
        wrap::WrappedSecret,
    };
    use pkcs8::EncodePrivateKey;
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let sk = SigningKey::from_bytes(&bytes);
    let pem = sk.to_pkcs8_pem(pkcs8::LineEnding::LF).unwrap();
    let kid = geonosis_core::KeyId::new();
    let material = KeyMaterial {
        id: kid,
        realm_id,
        usage: KeyUsage::Sig,
        alg: geonosis_core::JwsAlgorithm::EdDSA,
        state: KeyState::Active,
        public_jwk: Jwk {
            kid: kid.to_string(),
            kty: "OKP".into(),
            r#use: "sig".into(),
            alg: "EdDSA".into(),
            params: serde_json::Map::new(),
        },
        private_ref: PrivateKeyRef::Local(WrappedSecret {
            nonce: vec![],
            ciphertext: vec![],
        }),
        created_at: Utc::now(),
        rotated_at: None,
    };
    state.kms.register(material, pem.as_bytes()).unwrap();
}

/// Seed a public client (e.g. SPA) with `authorization_code` grant.
pub async fn seed_public_client(state: &AppState, client_id: &str) {
    seed_public_client_with_grants(state, client_id, false).await;
}

/// Seed a public client with optional `device_code` grant.
pub async fn seed_public_client_with_grants(state: &AppState, client_id: &str, device_code: bool) {
    use geonosis_core::{
        AccessTokenType, ClientAuthMethod, ClientId, ClientKind, ConsentPolicy, FlowBinding,
        GrantPolicy, RedirectUri,
    };
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    let mut grants = GrantPolicy::public_app();
    grants.device_code = device_code;
    let client = geonosis_core::Client {
        id: ClientId::new(),
        realm_id: realm.id,
        client_id: client_id.into(),
        display_name: None,
        kind: ClientKind::Public,
        grants,
        auth_method: ClientAuthMethod::None,
        flow_binding: FlowBinding::default(),
        default_scopes: vec![],
        optional_scopes: vec![],
        redirect_uris: vec![RedirectUri {
            uri: "https://example.com/cb".into(),
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
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    state.storage.create_client(client).await.unwrap();
}

/// Seed a confidential client with `client_credentials` grant + a known
/// secret. Returns the plaintext secret for tests to use.
pub async fn seed_service_account(state: &AppState, client_id: &str) -> String {
    use geonosis_core::{
        AccessTokenType, ClientAuthMethod, ClientId, ClientKind, ConsentPolicy, FlowBinding,
        GrantPolicy,
    };
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    let secret = "super-secret-1234567890".to_string();
    // Stage a signing key so token mint succeeds.
    seed_eddsa_key(state, realm.id).await;
    let client = geonosis_core::Client {
        id: ClientId::new(),
        realm_id: realm.id,
        client_id: client_id.into(),
        display_name: None,
        kind: ClientKind::Confidential,
        grants: GrantPolicy::service_account(),
        auth_method: ClientAuthMethod::ClientSecretBasic,
        flow_binding: FlowBinding::default(),
        default_scopes: vec![],
        optional_scopes: vec![],
        redirect_uris: vec![],
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
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let cid = client.id;
    state.storage.create_client(client).await.unwrap();
    let realm_key = geonosis_crypto::derive_realm_key(
        &state.client_secret_hash_key,
        &realm.id.to_string(),
        b"client-secret",
    );
    let h = hex::encode(geonosis_crypto::hash::token_hash(
        &realm_key,
        secret.as_bytes(),
    ));
    state
        .storage
        .store_client_secret_hash(realm.id, cid, h)
        .await
        .unwrap();
    secret
}

/// Seed a broker identity provider (OIDC).
pub async fn seed_broker_idp(state: &AppState, realm_id: RealmId, alias: &str) {
    use geonosis_broker::{IdentityProvider, IdpConfig, IdpKind, OidcIdpConfig};
    use geonosis_core::id::IdpId;
    let idp = IdentityProvider {
        id: IdpId::new(),
        realm_id,
        alias: alias.into(),
        display_name: alias.into(),
        kind: IdpKind::Oidc,
        config: IdpConfig::Oidc(OidcIdpConfig {
            issuer: "https://accounts.google.com".into(),
            discovery_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None,
            client_id: "client-abc".into(),
            client_secret: None,
            scopes: vec!["openid".into(), "email".into()],
            pkce: true,
            accept_unsigned_userinfo: false,
            client_auth: geonosis_broker::ClientAuthMethod::None,
            client_assertion_key: None,
            prompt: None,
            response_mode: None,
        }),
        first_login_flow_alias: "review-profile".into(),
        post_login_flow_alias: None,
        link_only: false,
        adapter_urn: Some(geonosis_broker::adapter::urn::GOOGLE.into()),
        enabled: true,
    };
    state.storage.create_idp(idp).await.unwrap();
}

/// Seed a confidential client with `password` (ROPC) grant enabled +
/// a known secret. Returns the plaintext secret.
pub async fn seed_password_grant_client(state: &AppState, client_id: &str) -> String {
    use geonosis_core::{
        AccessTokenType, ClientAuthMethod, ClientId, ClientKind, ConsentPolicy, FlowBinding,
        GrantPolicy,
    };
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    let secret = "password-grant-secret-xyz".to_string();
    seed_eddsa_key(state, realm.id).await;
    let mut grants = GrantPolicy::web_app();
    grants.password = true;
    let client = geonosis_core::Client {
        id: ClientId::new(),
        realm_id: realm.id,
        client_id: client_id.into(),
        display_name: None,
        kind: ClientKind::Confidential,
        grants,
        auth_method: ClientAuthMethod::ClientSecretBasic,
        flow_binding: FlowBinding::default(),
        default_scopes: vec![],
        optional_scopes: vec![],
        redirect_uris: vec![],
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
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let cid = client.id;
    state.storage.create_client(client).await.unwrap();
    let realm_key = geonosis_crypto::derive_realm_key(
        &state.client_secret_hash_key,
        &realm.id.to_string(),
        b"client-secret",
    );
    let h = hex::encode(geonosis_crypto::hash::token_hash(
        &realm_key,
        secret.as_bytes(),
    ));
    state
        .storage
        .store_client_secret_hash(realm.id, cid, h)
        .await
        .unwrap();
    secret
}

// ---------------------------------------------------------------------------
// Config update helpers
// ---------------------------------------------------------------------------

/// Update the realm's token policy via a closure.
pub async fn update_realm_token_policy(state: &AppState, f: impl FnOnce(&mut TokenPolicy)) {
    let mut realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    f(&mut realm.token_policy);
    realm.updated_at = Utc::now();
    state.storage.update_realm(realm).await.unwrap();
}

/// Replace the realm's password policy rules.
pub async fn update_realm_password_policy(
    state: &AppState,
    rules: Vec<geonosis_core::PasswordRule>,
) {
    let mut realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    realm.password_policy.rules = rules;
    realm.updated_at = Utc::now();
    state.storage.update_realm(realm).await.unwrap();
}

/// Update the realm's brute force policy via a closure.
pub async fn update_realm_brute_force(
    state: &AppState,
    f: impl FnOnce(&mut geonosis_core::BruteForcePolicy),
) {
    let mut realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    f(&mut realm.brute_force);
    realm.updated_at = Utc::now();
    state.storage.update_realm(realm).await.unwrap();
}

/// Update the realm's session policy via a closure.
pub async fn update_realm_session_policy(state: &AppState, f: impl FnOnce(&mut SessionPolicy)) {
    let mut realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    f(&mut realm.session_policy);
    realm.updated_at = Utc::now();
    state.storage.update_realm(realm).await.unwrap();
}

/// Update the realm's login settings via a closure.
pub async fn update_realm_login_settings(
    state: &AppState,
    f: impl FnOnce(&mut geonosis_core::LoginSettings),
) {
    let mut realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    f(&mut realm.login);
    realm.updated_at = Utc::now();
    state.storage.update_realm(realm).await.unwrap();
}

/// Update a client's grant policy by client_id string.
pub async fn update_client_grants(
    state: &AppState,
    client_id: &str,
    f: impl FnOnce(&mut geonosis_core::GrantPolicy),
) {
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    let mut client = state
        .storage
        .get_client_by_client_id(realm.id, client_id)
        .await
        .unwrap();
    f(&mut client.grants);
    client.updated_at = Utc::now();
    state.storage.update_client(client).await.unwrap();
}

/// Disable/enable a client by client_id string.
pub async fn set_client_enabled(state: &AppState, client_id: &str, enabled: bool) {
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    let mut client = state
        .storage
        .get_client_by_client_id(realm.id, client_id)
        .await
        .unwrap();
    client.enabled = enabled;
    client.updated_at = Utc::now();
    state.storage.update_client(client).await.unwrap();
}

// ---------------------------------------------------------------------------
// Seed helpers
// ---------------------------------------------------------------------------

/// Seed a user with a password. Returns the user.
pub async fn seed_user_with_password(
    state: &AppState,
    realm_id: RealmId,
    username: &str,
    password: &str,
) -> geonosis_core::User {
    let now = Utc::now();
    let user = geonosis_core::User {
        id: geonosis_core::id::UserId::new(),
        realm_id,
        username: username.into(),
        email: Some(format!("{username}@example.com")),
        email_verified: false,
        name: None,
        credentials: vec![],
        federation: None,
        attributes: Default::default(),
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
    state.storage.create_user(user.clone()).await.unwrap();
    let phc = geonosis_crypto::hash_password(password).unwrap();
    state
        .storage
        .store_password_hash(realm_id, user.id, phc)
        .await
        .unwrap();
    user
}
