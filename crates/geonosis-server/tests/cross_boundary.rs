//! Cross-boundary integration tests.
//!
//! These tests verify that admin API changes actually affect
//! OIDC/OAuth protocol behaviour. For example: create a client via
//! admin API → get a token via the token endpoint; disable a user →
//! password grant fails.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use tower::ServiceExt;

use geonosis_server::test_fixtures::*;
use geonosis_server::{router, AppState};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn token_url() -> &'static str {
    "/realms/acme/protocol/openid-connect/token"
}

/// POST to the token endpoint with client_credentials grant + Basic auth.
async fn token_client_credentials(
    router: axum::Router,
    client_id: &str,
    secret: &str,
    scope: &str,
) -> axum::response::Response {
    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    );
    let body = format!("grant_type=client_credentials&scope={}", urlencoded(scope));
    router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(token_url())
                .header("authorization", auth)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// POST to the token endpoint with password (ROPC) grant.
async fn token_password(
    router: axum::Router,
    client_id: &str,
    client_secret: &str,
    username: &str,
    password: &str,
    scope: &str,
) -> axum::response::Response {
    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{client_secret}"))
    );
    let body = format!(
        "grant_type=password&username={}&password={}&scope={}",
        urlencoded(username),
        urlencoded(password),
        urlencoded(scope),
    );
    router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(token_url())
                .header("authorization", auth)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

fn urlencoded(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

/// Decode the JWT payload (middle segment) without verifying the signature.
fn decode_jwt_payload(jwt: &str) -> serde_json::Value {
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .unwrap();
    serde_json::from_slice(&payload).unwrap()
}

async fn read_json(resp: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// Send an admin API POST (with auth cookie) through the full server router.
async fn admin_post(
    router: axum::Router,
    cookie: &str,
    uri: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header(axum::http::header::COOKIE, cookie)
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Send an admin API PUT (with auth cookie) through the full server router.
async fn admin_put(
    router: axum::Router,
    cookie: &str,
    uri: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(uri)
                .header("content-type", "application/json")
                .header(axum::http::header::COOKIE, cookie)
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Send an admin API DELETE (with auth cookie) through the full server router.
async fn admin_delete(router: axum::Router, cookie: &str, uri: &str) -> axum::response::Response {
    router
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(uri)
                .header(axum::http::header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Common setup: AppState + admin cookie + signing key + full router.
async fn setup() -> (AppState, String) {
    let state = fixture_state().await;
    let cookie = admin_session_cookie(&state).await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    seed_eddsa_key(&state, realm.id).await;
    (state, cookie)
}

// ===========================================================================
// P0 — Core Token Flows
// ===========================================================================

#[tokio::test]
async fn client_credentials_grant_via_seeded_client() {
    let state = fixture_state().await;
    let secret = seed_service_account(&state, "svc").await;
    let r = router(state);

    let resp = token_client_credentials(r, "svc", &secret, "api/read").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["token_type"], "Bearer");
    let access = json["access_token"].as_str().unwrap();
    assert_eq!(access.matches('.').count(), 2, "must be a 3-part JWT");
}

#[tokio::test]
async fn password_grant_via_seeded_user() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    let secret = seed_password_grant_client(&state, "web").await;
    seed_user_with_password(&state, realm.id, "alice", "Str0ng!Pass9").await;
    let r = router(state);

    let resp = token_password(r, "web", &secret, "alice", "Str0ng!Pass9", "openid").await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "password grant should succeed"
    );
    let json = read_json(resp).await;
    assert!(json["access_token"].is_string());
    assert!(json["refresh_token"].is_string());
}

#[tokio::test]
async fn token_claims_have_correct_issuer_and_audience() {
    let state = fixture_state().await;
    let secret = seed_service_account(&state, "svc").await;
    let r = router(state);

    let resp = token_client_credentials(r, "svc", &secret, "api/read").await;
    let json = read_json(resp).await;
    let claims = decode_jwt_payload(json["access_token"].as_str().unwrap());

    assert_eq!(claims["iss"], "https://g.example/realms/acme");
    assert!(claims["aud"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("svc")));
    assert_eq!(claims["azp"], "svc");
    assert!(claims["exp"].as_i64().unwrap() > chrono::Utc::now().timestamp());
}

#[tokio::test]
async fn client_credentials_returns_no_refresh_token() {
    let state = fixture_state().await;
    let secret = seed_service_account(&state, "svc").await;
    let r = router(state);

    let resp = token_client_credentials(r, "svc", &secret, "api/read").await;
    let json = read_json(resp).await;
    assert!(
        json.get("refresh_token").is_none() || json["refresh_token"].is_null(),
        "client_credentials must not return a refresh_token"
    );
}

#[tokio::test]
async fn password_grant_wrong_password_fails() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    let secret = seed_password_grant_client(&state, "web").await;
    seed_user_with_password(&state, realm.id, "alice", "Str0ng!Pass9").await;
    let r = router(state);

    let resp = token_password(r, "web", &secret, "alice", "WRONG", "openid").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = read_json(resp).await;
    assert_eq!(json["error"], "invalid_grant");
}

// ===========================================================================
// P1 — Admin Changes Affect Protocol Behaviour
// ===========================================================================

#[tokio::test]
async fn disable_user_then_password_grant_fails() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    let secret = seed_password_grant_client(&state, "web").await;
    seed_user_with_password(&state, realm.id, "alice", "Str0ng!Pass9").await;

    // Verify login works first
    let r = router(state.clone());
    let resp = token_password(r, "web", &secret, "alice", "Str0ng!Pass9", "openid").await;
    assert_eq!(resp.status(), StatusCode::OK, "should work before disable");

    // Disable user via storage (direct — admin API would need the full user JSON)
    let mut user = state
        .storage
        .get_user_by_username(realm.id, "alice")
        .await
        .unwrap();
    user.enabled = false;
    state.storage.update_user(user).await.unwrap();

    // Token request should now fail
    let r2 = router(state);
    let resp = token_password(r2, "web", &secret, "alice", "Str0ng!Pass9", "openid").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = read_json(resp).await;
    assert_eq!(json["error"], "invalid_grant");
}

#[tokio::test]
async fn delete_user_then_password_grant_fails() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    let secret = seed_password_grant_client(&state, "web").await;
    let user = seed_user_with_password(&state, realm.id, "alice", "Str0ng!Pass9").await;

    // Verify login works
    let r = router(state.clone());
    let resp = token_password(r, "web", &secret, "alice", "Str0ng!Pass9", "openid").await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Delete user
    state.storage.delete_user(realm.id, user.id).await.unwrap();

    // Token request should fail
    let r2 = router(state);
    let resp = token_password(r2, "web", &secret, "alice", "Str0ng!Pass9", "openid").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn change_password_then_old_fails_new_works() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    let secret = seed_password_grant_client(&state, "web").await;
    seed_user_with_password(&state, realm.id, "alice", "OldPass!123").await;

    // Change password via storage
    let user = state
        .storage
        .get_user_by_username(realm.id, "alice")
        .await
        .unwrap();
    let new_phc = geonosis_crypto::hash_password("NewPass!456").unwrap();
    state
        .storage
        .store_password_hash(realm.id, user.id, new_phc)
        .await
        .unwrap();

    // Old password should fail
    let r = router(state.clone());
    let resp = token_password(r, "web", &secret, "alice", "OldPass!123", "openid").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // New password should work
    let r2 = router(state);
    let resp = token_password(r2, "web", &secret, "alice", "NewPass!456", "openid").await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn create_realm_then_discovery_works() {
    let (state, cookie) = setup().await;
    let r = router(state.clone());

    // Create a new realm via admin API
    let resp = admin_post(
        r.clone(),
        &cookie,
        "/admin/v1/realms",
        serde_json::json!({
            "slug": "new-realm",
            "display_name": "New Realm"
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Discovery should work for the new realm
    let resp = r
        .clone()
        .oneshot(
            Request::builder()
                .uri("/realms/new-realm/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["issuer"], "https://g.example/realms/new-realm");
}

#[tokio::test]
async fn delete_realm_then_discovery_404s() {
    let (state, cookie) = setup().await;
    let r = router(state);

    // Delete the acme realm via admin API
    let resp = admin_delete(r.clone(), &cookie, "/admin/v1/realms/acme").await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Discovery should now 404
    let resp = r
        .oneshot(
            Request::builder()
                .uri("/realms/acme/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn client_credentials_wrong_secret_rejected() {
    let state = fixture_state().await;
    let _secret = seed_service_account(&state, "svc").await;
    let r = router(state);

    let resp = token_client_credentials(r, "svc", "WRONG-SECRET", "api/read").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json = read_json(resp).await;
    assert_eq!(json["error"], "invalid_client");
}

// ===========================================================================
// P2 — Role/Group Token Propagation (TODO v0.1.x: role mappers)
// ===========================================================================

#[tokio::test]
#[ignore = "v0.1.x: mint_access_token sets realm_access=None — role mapper not implemented yet"]
async fn assign_role_to_user_then_token_contains_role() {
    // TODO(v0.1.x): once role mappers exist:
    // 1. Create user + password
    // 2. Create role "viewer"
    // 3. Assign role to user
    // 4. Get token via ROPC
    // 5. Decode JWT → assert realm_access.roles contains "viewer"
}

#[tokio::test]
#[ignore = "v0.1.x: group membership not yet populated in token claims"]
async fn group_role_propagates_to_user_token() {
    // TODO(v0.1.x):
    // 1. Create user, group, role
    // 2. Assign role to group, user to group
    // 3. Get token → groups claim contains group path, realm_access contains role
}

#[tokio::test]
#[ignore = "v0.1.x: org claim not yet populated in token"]
async fn org_membership_produces_org_claim() {
    // TODO(v0.1.x):
    // 1. Create user, org, add user as member
    // 2. Get token → org claim present with alias + id
}

#[tokio::test]
#[ignore = "v0.1.x: role unassignment + token refresh not yet wired"]
async fn unassign_role_removes_from_token() {
    // TODO(v0.1.x):
    // 1. Assign role → token has it
    // 2. Unassign role → new token does not have it
}

// ===========================================================================
// P3 — Realm Settings Behavioral
// ===========================================================================

#[tokio::test]
async fn password_policy_change_enforced_on_next_set_password() {
    let (state, cookie) = setup().await;
    let r = router(state.clone());

    // Create a user via admin API
    let resp = admin_post(
        r.clone(),
        &cookie,
        "/admin/v1/realms/acme/users",
        serde_json::json!({"username": "bob"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Default password policy has Length { min: 8 }
    // Try setting a short password — should fail
    let resp = admin_put(
        r.clone(),
        &cookie,
        "/admin/v1/realms/acme/users/bob/password",
        serde_json::json!({"password": "short"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = read_json(resp).await;
    assert_eq!(json["error"], "password_policy_violation");

    // Set a valid password — should work
    let resp = admin_put(
        r.clone(),
        &cookie,
        "/admin/v1/realms/acme/users/bob/password",
        serde_json::json!({"password": "ValidPass!123"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn token_endpoint_404s_on_unknown_realm() {
    let state = fixture_state().await;
    let r = router(state);

    let resp = r
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/realms/nonexistent/protocol/openid-connect/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("grant_type=client_credentials&client_id=x"))
                .unwrap(),
        )
        .await
        .unwrap();
    // Should be 404 or 400 — not 500
    assert!(
        resp.status() == StatusCode::NOT_FOUND || resp.status() == StatusCode::BAD_REQUEST,
        "expected 404 or 400, got {}",
        resp.status()
    );
}
