//! Axum router assembly.

use axum::routing::get;
use axum::Router;
use tower_http::trace::TraceLayer;

use crate::handlers;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/-/started", get(handlers::started))
        .route("/-/ready", get(handlers::ready))
        .route("/-/healthy", get(handlers::healthy))
        .route(
            "/realms/:slug/.well-known/openid-configuration",
            get(handlers::openid_configuration),
        )
        .route(
            "/realms/:slug/protocol/openid-connect/jwks",
            get(handlers::jwks),
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

    async fn fixture_state() -> AppState {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
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
}
