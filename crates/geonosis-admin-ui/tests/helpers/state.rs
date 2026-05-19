#![allow(dead_code)]
use std::sync::Arc;

use chrono::Utc;

use geonosis_core::id::{AgentId, RealmId, UserId};
use geonosis_core::{
    AcrPolicy, Agent, AgentAuthMethod, AgentKind, AgentRateLimit, BruteForcePolicy, EventConfig,
    LocalizationPolicy, LoginSettings, OtpPolicy, ParentSubject, PasswordPolicy, Realm,
    RegistrationPolicy, SenderConstraint, SessionPolicy, SslRequirement, ThemeBinding, TokenPolicy,
    User, WebauthnPolicy,
};
use geonosis_storage::{seed_default_flows, MemoryStorage, Storage};

use geonosis_admin_ui::state::AdminState;

/// Create a test `AdminState` with one seeded realm (slug = "acme").
/// Returns the shared state and the realm ID.
pub async fn fixture_state() -> (Arc<AdminState>, RealmId) {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let realm = Realm {
        id: RealmId::new(),
        slug: "acme".into(),
        display_name: "Acme".into(),
        frontend_url: None,
        admin_frontend_url: None,
        enabled: true,
        ssl_required: SslRequirement::None,
        login: LoginSettings::default(),
        registration: RegistrationPolicy::default(),
        session_policy: SessionPolicy::default(),
        token_policy: TokenPolicy::default(),
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
        default_roles: Default::default(),
        organizations_enabled: true,
        organization_policy: Default::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let realm_id = realm.id;
    storage.create_realm(realm).await.unwrap();
    seed_default_flows(storage.as_ref(), realm_id)
        .await
        .unwrap();
    let admin = AdminState::new(storage).unwrap();
    (Arc::new(admin), realm_id)
}

/// Build the v1 admin router without auth middleware.
pub fn test_router(state: Arc<AdminState>) -> axum::Router {
    geonosis_admin_ui::handlers_v1::router(state)
}

/// Seed a user into the given realm via the storage layer directly.
pub async fn seed_user(state: &AdminState, realm_id: RealmId, username: &str) -> User {
    let now = Utc::now();
    let user = User {
        id: UserId::new(),
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
    user
}

/// Seed an agent into the given realm via the storage layer directly.
pub async fn seed_agent(state: &AdminState, realm_id: RealmId, alias: &str) -> Agent {
    let now = Utc::now();
    let agent = Agent {
        id: AgentId::new(),
        realm_id,
        alias: alias.into(),
        display_name: format!("Agent {alias}"),
        kind: AgentKind::Assistant,
        model_hint: None,
        vendor: None,
        version: None,
        parent_subject: ParentSubject::User {
            user_id: UserId::new(),
        },
        capabilities: vec![],
        allowed_scopes: vec![],
        allowed_audiences: vec![],
        rate_limit: AgentRateLimit::default(),
        auth_method: AgentAuthMethod::TokenExchangeOnly,
        public_jwk: None,
        created_at: now,
        expires_at: None,
        revoked_at: None,
        enabled: true,
    };
    state.storage.create_agent(agent.clone()).await.unwrap();
    agent
}
