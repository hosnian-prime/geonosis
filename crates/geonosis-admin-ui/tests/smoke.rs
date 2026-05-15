mod helpers;

use axum::http::StatusCode;
use tower::ServiceExt;

use helpers::request::get;
use helpers::state::{fixture_state, seed_agent, seed_user, test_router};

/// Smoke test: hit every GET endpoint once and assert 200 OK.
/// If any endpoint breaks (handler panic, missing route, storage
/// error), this test catches it immediately.
#[tokio::test]
async fn smoke_all_get_endpoints_respond_200() {
    let (state, realm_id) = fixture_state().await;

    // Seed minimal entities so get-by-id endpoints have data.
    seed_user(&state, realm_id, "alice").await;
    seed_agent(&state, realm_id, "bot-1").await;

    let router = test_router(state);

    let endpoints = vec![
        "/admin/v1/realms",
        "/admin/v1/realms/acme",
        "/admin/v1/realms/acme/users",
        "/admin/v1/realms/acme/users/alice",
        "/admin/v1/realms/acme/clients",
        "/admin/v1/realms/acme/roles",
        "/admin/v1/realms/acme/groups",
        "/admin/v1/realms/acme/orgs",
        "/admin/v1/realms/acme/agents",
        "/admin/v1/realms/acme/agents/bot-1",
        "/admin/v1/realms/acme/idps",
        "/admin/v1/realms/acme/sessions",
        "/admin/v1/realms/acme/keys",
        "/admin/v1/realms/acme/events",
        "/admin/v1/realms/acme/user-profile",
    ];

    for uri in endpoints {
        let resp = router.clone().oneshot(get(uri)).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "SMOKE FAILED: GET {uri} returned {}",
            resp.status()
        );
    }
}
