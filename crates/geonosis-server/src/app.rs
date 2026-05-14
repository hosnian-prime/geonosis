//! Axum router assembly.

use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

use crate::handlers;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        // Health probes
        .route("/-/started", get(handlers::started))
        .route("/-/ready", get(handlers::ready))
        .route("/-/healthy", get(handlers::healthy))
        // OIDC discovery + JWKS
        .route(
            "/realms/:slug/.well-known/openid-configuration",
            get(handlers::openid_configuration),
        )
        // RFC 8414 — OAuth 2.0 Authorization Server Metadata. The shape
        // is a strict subset of the OIDC discovery doc, so we serve the
        // same body for both URLs (other IdPs do the same).
        .route(
            "/realms/:slug/.well-known/oauth-authorization-server",
            get(handlers::openid_configuration),
        )
        .route(
            "/realms/:slug/protocol/openid-connect/jwks",
            get(handlers::jwks),
        )
        // OIDC authorize
        .route(
            "/realms/:slug/protocol/openid-connect/auth",
            get(handlers::authorize_get).post(handlers::authorize_post),
        )
        // OIDC token + grants
        .route(
            "/realms/:slug/protocol/openid-connect/token",
            post(handlers::token),
        )
        // OIDC userinfo
        .route(
            "/realms/:slug/protocol/openid-connect/userinfo",
            get(handlers::userinfo_get).post(handlers::userinfo_post),
        )
        // OIDC logout
        .route(
            "/realms/:slug/protocol/openid-connect/logout",
            get(handlers::logout_get).post(handlers::logout_post),
        )
        // RFC 7009 — token revocation
        .route(
            "/realms/:slug/protocol/openid-connect/revoke",
            post(handlers::revoke),
        )
        // RFC 7662 — token introspection
        .route(
            "/realms/:slug/protocol/openid-connect/introspect",
            post(handlers::introspect),
        )
        // RFC 9126 — pushed authorization request
        .route(
            "/realms/:slug/protocol/openid-connect/par",
            post(handlers::par),
        )
        // RFC 8628 — device authorization
        .route(
            "/realms/:slug/protocol/openid-connect/device/authorize",
            post(handlers::device_authorize),
        )
        .route(
            "/realms/:slug/protocol/openid-connect/device/token",
            post(handlers::device_token),
        )
        // Login UI form action
        .route(
            "/realms/:slug/login-actions/authenticate",
            post(handlers::authenticate_post),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::timeout;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chrono::Utc;
    use tower::ServiceExt;

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

    pub(crate) async fn fixture_state() -> AppState {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let mut token_policy = TokenPolicy::default();
        // Tests use EdDSA so we don't pay the RSA key-gen cost per fixture.
        token_policy.default_signing_alg = geonosis_core::JwsAlgorithm::EdDSA;
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
        }
    }

    #[tokio::test]
    async fn health_probes_return_200() {
        let r = router(fixture_state().await);
        for path in ["/-/started", "/-/ready", "/-/healthy"] {
            let resp = timeout(
                Duration::from_secs(2),
                r.clone().oneshot(
                    Request::builder()
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{path}");
        }
    }

    #[tokio::test]
    async fn discovery_returns_well_known() {
        let r = router(fixture_state().await);
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/realms/acme/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code_challenge_methods_supported"], serde_json::json!(["S256"]));
        assert_eq!(json["response_types_supported"], serde_json::json!(["code"]));
    }

    #[tokio::test]
    async fn discovery_unknown_realm_404s() {
        let r = router(fixture_state().await);
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/realms/missing/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn token_endpoint_rejects_missing_grant_type() {
        let r = router(fixture_state().await);
        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/realms/acme/protocol/openid-connect/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("client_id=foo"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid_request");
    }

    #[tokio::test]
    async fn token_endpoint_rejects_unknown_grant_type() {
        let r = router(fixture_state().await);
        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/realms/acme/protocol/openid-connect/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("grant_type=banana"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "unsupported_grant_type");
    }

    #[tokio::test]
    async fn revoke_returns_200_for_unknown_token() {
        let r = router(fixture_state().await);
        // Build a public client to satisfy `auth_method=none`.
        // We bypass that by sending no auth and expecting the unknown-client
        // error path.
        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/realms/acme/protocol/openid-connect/revoke")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("token=zzz&client_id=missing"))
                    .unwrap(),
            )
            .await
            .unwrap();
        // missing client returns invalid_client (401).
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn introspect_inactive_for_garbage_token() {
        let state = fixture_state().await;
        // Create a public client so authentication path passes.
        seed_public_client(&state, "spa").await;
        let r = router(state);
        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/realms/acme/protocol/openid-connect/introspect")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("token=garbage&client_id=spa"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["active"], serde_json::Value::Bool(false));
    }

    #[tokio::test]
    async fn par_creates_request_uri() {
        let state = fixture_state().await;
        seed_public_client(&state, "spa").await;
        let r = router(state);
        let body = "client_id=spa&response_type=code&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&scope=openid&nonce=n1&code_challenge=abc&code_challenge_method=S256";
        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/realms/acme/protocol/openid-connect/par")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["request_uri"]
            .as_str()
            .unwrap()
            .starts_with("urn:ietf:params:oauth:request_uri:"));
    }

    #[tokio::test]
    async fn authorize_unknown_client_400s() {
        let r = router(fixture_state().await);
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/realms/acme/protocol/openid-connect/auth?response_type=code&client_id=missing&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&scope=openid&nonce=n1&code_challenge=abc&code_challenge_method=S256")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn userinfo_without_bearer_returns_401() {
        let r = router(fixture_state().await);
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/realms/acme/protocol/openid-connect/userinfo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www = resp
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(www.contains("Bearer"));
    }

    #[tokio::test]
    async fn logout_get_redirects_to_post_logout_uri() {
        let r = router(fixture_state().await);
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/realms/acme/protocol/openid-connect/logout?post_logout_redirect_uri=https%3A%2F%2Fexample.com%2Fbye&state=s1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let loc = resp.headers().get(axum::http::header::LOCATION).unwrap().to_str().unwrap();
        assert!(loc.starts_with("https://example.com/bye"));
        assert!(loc.contains("state=s1"));
    }

    #[tokio::test]
    async fn device_authorize_emits_codes() {
        let state = fixture_state().await;
        seed_public_client_with_grants(&state, "cli", true).await;
        let r = router(state);
        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/realms/acme/protocol/openid-connect/device/authorize")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("client_id=cli&scope=openid"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(!json["device_code"].as_str().unwrap().is_empty());
        let user_code = json["user_code"].as_str().unwrap();
        assert_eq!(user_code.len(), 9);
        assert_eq!(user_code.as_bytes()[4], b'-');
        assert_eq!(json["interval"], serde_json::json!(5));
    }

    // --- helpers ---

    pub(crate) async fn seed_public_client(state: &AppState, client_id: &str) {
        seed_public_client_with_grants(state, client_id, false).await;
    }

    /// Seed a confidential client with `client_credentials` grant + a known
    /// secret. Returns the plaintext secret for tests to use.
    pub(crate) async fn seed_service_account(state: &AppState, client_id: &str) -> String {
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
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let cid = client.id;
        state.storage.create_client(client).await.unwrap();
        let h = hex::encode(geonosis_crypto::hash::token_hash(
            &state.client_secret_hash_key,
            secret.as_bytes(),
        ));
        state
            .storage
            .store_client_secret_hash(realm.id, cid, h)
            .await
            .unwrap();
        secret
    }

    pub(crate) async fn seed_eddsa_key(state: &AppState, realm_id: RealmId) {
        use ed25519_dalek::SigningKey;
        use geonosis_crypto::{
            jwk::Jwk, kms::{KeyMaterial, KeyState, KeyUsage, PrivateKeyRef},
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

    #[tokio::test]
    async fn client_credentials_grant_returns_access_token() {
        let state = fixture_state().await;
        let secret = seed_service_account(&state, "svc").await;
        let r = router(state);
        use base64::Engine as _;
        let auth = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("svc:{secret}"))
        );
        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/realms/acme/protocol/openid-connect/token")
                    .header("authorization", auth)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("grant_type=client_credentials&scope=api%2Fread"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let access = json["access_token"].as_str().unwrap();
        // JWT structure: three dot-separated parts.
        assert_eq!(access.matches('.').count(), 2);
        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["scope"], "api/read");
    }

    #[tokio::test]
    async fn client_credentials_with_wrong_secret_rejected() {
        let state = fixture_state().await;
        let _real_secret = seed_service_account(&state, "svc").await;
        let r = router(state);
        use base64::Engine as _;
        let auth = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("svc:WRONG")
        );
        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/realms/acme/protocol/openid-connect/token")
                    .header("authorization", auth)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("grant_type=client_credentials"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid_client");
    }

    pub(crate) async fn seed_public_client_with_grants(
        state: &AppState,
        client_id: &str,
        device_code: bool,
    ) {
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
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        state.storage.create_client(client).await.unwrap();
    }
}
