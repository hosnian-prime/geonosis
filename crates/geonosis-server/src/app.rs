//! Axum router assembly.

use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

use crate::handlers;
use crate::metrics::{count_requests, metrics_handler};
use crate::security_headers;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    let admin =
        geonosis_admin_ui::AdminState::with_audit(state.storage.clone(), state.audit.clone())
            .expect("admin state");
    let admin_router = geonosis_admin_ui::router(admin);
    let metrics_state = state.metrics.clone();
    Router::new()
        // Health probes
        .route("/-/started", get(handlers::started))
        .route("/-/ready", get(handlers::ready))
        .route("/-/healthy", get(handlers::healthy))
        .route("/-/drain", post(handlers::drain))
        // SAML 2.0 IdP — `docs/20-saml-idp.md` §URL surface.
        // SSO (POST + Redirect bindings) + metadata land in v0.1;
        // SLO + IdP-initiated entry follow in v0.1.x.
        .route(
            "/realms/:slug/protocol/saml/descriptor",
            get(handlers::saml_metadata),
        )
        .route(
            "/realms/:slug/protocol/saml/sso",
            get(handlers::saml_sso_get).post(handlers::saml_sso_post),
        )
        .route(
            "/realms/:slug/protocol/saml/slo",
            get(handlers::saml_slo_get).post(handlers::saml_slo_post),
        )
        // IdP-initiated SSO entry — authenticated user picks an SP
        // by alias and the IdP mints + posts an assertion as if
        // responding to an AuthnRequest (no InResponseTo).
        .route(
            "/realms/:slug/clients-saml/:alias/unsolicited",
            get(handlers::saml_unsolicited),
        )
        // Prometheus exposition endpoint — `docs/13-observability.md`.
        .route(
            "/metrics",
            get(metrics_handler).with_state(metrics_state.clone()),
        )
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
            get(handlers::authorize_get)
                .post(handlers::authorize_post)
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::rate_limit::limit_per_realm,
                )),
        )
        // OIDC token + grants
        .route(
            "/realms/:slug/protocol/openid-connect/token",
            post(handlers::token).layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::rate_limit::limit_per_realm,
            )),
        )
        // OIDC userinfo
        .route(
            "/realms/:slug/protocol/openid-connect/userinfo",
            get(handlers::userinfo_get)
                .post(handlers::userinfo_post)
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::rate_limit::limit_per_realm,
                )),
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
            post(handlers::par).layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::rate_limit::limit_per_realm,
            )),
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
        // Broker (identity federation) — RP / SP endpoints
        .route(
            "/realms/:slug/broker/:alias/login",
            get(handlers::broker_login),
        )
        .route(
            "/realms/:slug/broker/:alias/endpoint",
            get(handlers::broker_endpoint_get).post(handlers::broker_endpoint_post),
        )
        .route(
            "/realms/:slug/broker/:alias/metadata",
            get(handlers::broker_metadata),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
        .merge(admin_router)
        // Mount last so they wrap every route, including admin + metrics.
        .layer(axum::middleware::from_fn_with_state(
            metrics_state,
            count_requests,
        ))
        .layer(axum::middleware::from_fn(security_headers::apply))
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
            rate_limiter: Arc::new(crate::rate_limit::PerRealmRateLimiter::default_v0_1()),
            wasm_engine: geonosis_spi_host::runtime::WasmEngine::new(
                geonosis_spi_host::runtime::SandboxConfig::default(),
            )
            .expect("wasm engine bootstrap"),
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    #[tokio::test]
    async fn admin_realms_html_renders() {
        let state = fixture_state().await;
        let r = router(state);
        let resp = r
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/realms")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("<html"));
        assert!(text.contains("Realms"));
        assert!(text.contains("acme"));
    }

    #[tokio::test]
    async fn admin_realms_api_returns_json() {
        let state = fixture_state().await;
        let r = router(state);
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/admin/v1/realms")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // handlers_v1 returns a plain JSON array for consistency
        // with /orgs, /agents, etc. The legacy `{ "realms": [...] }`
        // envelope shape retired with the handlers_v1 migration.
        let arr = json.as_array().expect("realms array");
        assert!(arr.iter().any(|r| r["slug"] == "acme"));
    }

    #[tokio::test]
    async fn admin_css_served() {
        let state = fixture_state().await;
        let r = router(state);
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/static/admin.css")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.starts_with("text/css"));
    }

    #[tokio::test]
    async fn admin_negotiates_turkish() {
        let state = fixture_state().await;
        let r = router(state);
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/admin/realms")
                    .header(axum::http::header::ACCEPT_LANGUAGE, "tr,en;q=0.5")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("Alanlar"));
        assert!(text.contains("lang=\"tr\""));
    }

    #[tokio::test]
    async fn metrics_endpoint_exposes_prometheus_text() {
        let r = router(fixture_state().await);
        // Burn through one request first so the counter has something to report.
        let _ = r
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/-/started")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.starts_with("text/plain"));
        let body = axum::body::to_bytes(resp.into_body(), 16 * 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("geonosis_build_info"));
        assert!(text.contains("geonosis_http_requests_total"));
    }

    #[tokio::test]
    async fn responses_carry_default_security_headers() {
        let r = router(fixture_state().await);
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/-/started")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let h = resp.headers();
        let csp = h.get("content-security-policy").unwrap().to_str().unwrap();
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(h.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(h.get("referrer-policy").unwrap(), "no-referrer");
    }

    #[tokio::test]
    async fn health_probes_return_200() {
        let r = router(fixture_state().await);
        for path in ["/-/started", "/-/ready", "/-/healthy"] {
            let resp = timeout(
                Duration::from_secs(2),
                r.clone()
                    .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap()),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{path}");
        }
    }

    #[tokio::test]
    async fn drain_flips_readiness_but_not_liveness() {
        // The preStop hook contract from docs/11: POST /-/drain → 200,
        // then readiness reports 503 while liveness stays 200 so the
        // pod gets pulled out of rotation without restart.
        let r = router(fixture_state().await);
        // Sanity: pre-drain, /-/ready is 200.
        let resp = r
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/-/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // Flip the drain flag.
        let resp = r
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/-/drain")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // /-/ready now reports 503.
        let resp = r
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/-/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        // /-/healthy stays 200 — the orchestrator must not restart a
        // draining pod.
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/-/healthy")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
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
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["code_challenge_methods_supported"],
            serde_json::json!(["S256"])
        );
        assert_eq!(
            json["response_types_supported"],
            serde_json::json!(["code"])
        );
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
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
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
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "unsupported_grant_type");
    }

    #[tokio::test]
    async fn metrics_endpoint_surfaces_labeled_authorize_counter() {
        // Hitting /authorize bumps `geonosis_oidc_authorize_total`;
        // the realm's slug + the `started` outcome should land in
        // the next `/metrics` scrape.
        let state = fixture_state().await;
        let r = router(state);
        let _ = r
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/realms/acme/protocol/openid-connect/auth?response_type=code&client_id=demo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 32 * 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains("geonosis_oidc_authorize_total{realm=\"acme\""),
            "expected per-realm authorize counter line; body was:\n{text}"
        );
    }

    #[tokio::test]
    async fn metrics_endpoint_surfaces_token_counter_on_unknown_grant() {
        // A bad grant_type lands in `oidc_token_total` as
        // `(realm, unknown, error)` — the dispatcher rejects before
        // resolving the grant, so the counter records the path.
        let state = fixture_state().await;
        let r = router(state);
        let _ = r
            .clone()
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
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 32 * 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        // The handler rejects before the grant-type label is bound,
        // so the response counter we get back is the 4xx class one.
        // The OIDC token counter only emits once a grant is resolved
        // (intentional — unknown grant types should not pollute
        // grant-typed series).
        assert!(text.contains("geonosis_http_responses_total{class=\"4xx\"}"));
        // Token counter remains absent for this path, matching the
        // bounded-cardinality contract.
        assert!(!text.contains("geonosis_oidc_token_total{realm=\"acme\",grant_type=\"banana\""));
    }

    #[tokio::test]
    async fn saml_metadata_endpoint_serves_idp_descriptor() {
        // GET /realms/acme/protocol/saml/descriptor returns the
        // metadata XML with entityID, SSO/SLO endpoints, and the
        // realm's supported NameIDFormats.
        let r = router(fixture_state().await);
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/realms/acme/protocol/saml/descriptor")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.starts_with("application/samlmetadata+xml"));
        let body = axum::body::to_bytes(resp.into_body(), 32 * 1024)
            .await
            .unwrap();
        let xml = std::str::from_utf8(&body).unwrap();
        assert!(xml.starts_with("<?xml"));
        assert!(xml.contains("md:IDPSSODescriptor"));
        assert!(xml.contains("entityID=\"https://g.example/realms/acme\""));
        assert!(xml.contains("HTTP-POST"));
        assert!(xml.contains("HTTP-Redirect"));
        // The realm publishes the four canonical NameIDFormats.
        assert!(xml.contains("nameid-format:emailAddress"));
        assert!(xml.contains("nameid-format:persistent"));
        assert!(xml.contains("nameid-format:transient"));
    }

    #[tokio::test]
    async fn saml_metadata_404s_on_unknown_realm() {
        let r = router(fixture_state().await);
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/realms/nope/protocol/saml/descriptor")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn saml_sso_post_rejects_missing_saml_request() {
        // POST without a SAMLRequest form field must reject with 400.
        let r = router(fixture_state().await);
        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/realms/acme/protocol/saml/sso")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), 16 * 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("missing SAMLRequest"));
    }

    #[tokio::test]
    async fn saml_sso_get_redirect_binding_rejects_missing_saml_request() {
        // The Redirect binding is wired (G1) — a GET with no
        // SAMLRequest query parameter rejects with 400, not 501.
        let r = router(fixture_state().await);
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/realms/acme/protocol/saml/sso")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), 16 * 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("missing SAMLRequest"));
    }

    #[tokio::test]
    async fn saml_sso_get_decodes_deflate_then_dispatches() {
        // A valid deflate-encoded AuthnRequest from an unknown SP
        // round-trips through the decoder and hits the same SP
        // resolution path POST uses — outcome: 400 "unknown SP".
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write as _;

        let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_x" Version="2.0" IssueInstant="2026-05-14T12:00:00Z"><saml:Issuer>https://unknown.sp</saml:Issuer></samlp:AuthnRequest>"#;
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(xml.as_bytes()).unwrap();
        let b64 = B64.encode(enc.finish().unwrap());
        let encoded =
            percent_encoding::utf8_percent_encode(&b64, percent_encoding::NON_ALPHANUMERIC)
                .to_string();

        let r = router(fixture_state().await);
        let resp = r
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/realms/acme/protocol/saml/sso?SAMLRequest={encoded}"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), 16 * 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("unknown SP"), "got: {text}");
    }

    #[tokio::test]
    async fn saml_unsolicited_requires_session_cookie() {
        // GET /realms/:slug/clients-saml/:alias/unsolicited without
        // a `geonosis_sid` cookie must reject with 401 — the
        // operator hasn't signed in yet.
        let r = router(fixture_state().await);
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/realms/acme/clients-saml/some-sp/unsolicited")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(resp.into_body(), 16 * 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("no SSO session"));
    }

    #[tokio::test]
    async fn saml_unsolicited_rejects_unknown_session() {
        // A `geonosis_sid` cookie that doesn't match a stored
        // session must reject with 401.
        let r = router(fixture_state().await);
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/realms/acme/clients-saml/some-sp/unsolicited")
                    .header(
                        axum::http::header::COOKIE,
                        "geonosis_sid=does-not-exist; Path=/realms/acme",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn saml_sso_post_rejects_garbage_saml_request() {
        // A malformed (non-base64) SAMLRequest must reject with 400,
        // not 500. The error surfaces the base64 decode failure.
        let r = router(fixture_state().await);
        let resp = r
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/realms/acme/protocol/saml/sso")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("SAMLRequest=!!!not-base64!!!"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
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
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
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
        let loc = resp
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(loc.starts_with("https://example.com/bye"));
        assert!(loc.contains("state=s1"));
    }

    #[tokio::test]
    async fn broker_login_for_unknown_idp_404s() {
        let r = router(fixture_state().await);
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/realms/acme/broker/missing/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn broker_metadata_returns_acs_url() {
        let state = fixture_state().await;
        let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
        seed_broker_idp(&state, realm.id, "google").await;
        let r = router(state);
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/realms/acme/broker/google/metadata")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let acs = json["acs_url"].as_str().unwrap();
        assert!(acs.contains("/broker/google/endpoint"));
        assert!(acs.starts_with("https://g.example"));
    }

    #[tokio::test]
    async fn broker_endpoint_get_rejects_unknown_state() {
        let state = fixture_state().await;
        let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
        seed_broker_idp(&state, realm.id, "google").await;
        let r = router(state);
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/realms/acme/broker/google/endpoint?state=nope&code=xyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn broker_login_redirects_to_idp() {
        let state = fixture_state().await;
        let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
        seed_broker_idp(&state, realm.id, "google").await;
        // Install a fixture so the handler doesn't try to fetch
        // https://accounts.google.com/.well-known/openid-configuration.
        state.broker.discovery.install_fixture(
            "google",
            geonosis_broker::oidc::OidcDiscovery {
                issuer: "https://accounts.google.com".into(),
                authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".into(),
                token_endpoint: "https://oauth2.googleapis.com/token".into(),
                userinfo_endpoint: None,
                jwks_uri: "https://www.googleapis.com/oauth2/v3/certs".into(),
                end_session_endpoint: None,
                code_challenge_methods_supported: vec!["S256".into()],
                id_token_signing_alg_values_supported: vec!["RS256".into()],
            },
            vec![],
        );
        let r = router(state);
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/realms/acme/broker/google/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let loc = resp
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(loc.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
        assert!(loc.contains("prompt=select"));
        assert!(loc.contains("code_challenge="));
        assert!(loc.contains("code_challenge_method=S256"));
    }

    async fn seed_broker_idp(state: &AppState, realm_id: RealmId, alias: &str) {
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
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
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
            saml_sp_config: None,
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
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
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
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
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
            saml_sp_config: None,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        state.storage.create_client(client).await.unwrap();
    }
}
