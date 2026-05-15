//! Config behavioral specification tests.
//!
//! These tests verify that configuration changes actually affect system
//! behaviour — written from a Keycloak-like specification perspective,
//! not from the current implementation. Tests for configs that are not
//! yet enforced are marked `#[ignore]` to expose implementation gaps.
//!
//! Run enforced-only:  cargo test --package geonosis-server --test config_behavior
//! Run including gaps:  cargo test --package geonosis-server --test config_behavior -- --include-ignored

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use tower::ServiceExt;

use geonosis_server::test_fixtures::*;
use geonosis_server::router;

// ---------------------------------------------------------------------------
// Helpers (reused from cross_boundary.rs pattern)
// ---------------------------------------------------------------------------

fn token_url() -> &'static str {
    "/realms/acme/protocol/openid-connect/token"
}

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
    let body = format!(
        "grant_type=client_credentials&scope={}",
        urlenc(scope)
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
        urlenc(username),
        urlenc(password),
        urlenc(scope),
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

fn urlenc(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

fn decode_jwt_payload(jwt: &str) -> serde_json::Value {
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .unwrap();
    serde_json::from_slice(&payload).unwrap()
}

fn decode_jwt_header(jwt: &str) -> serde_json::Value {
    let parts: Vec<&str> = jwt.split('.').collect();
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .unwrap();
    serde_json::from_slice(&header).unwrap()
}

async fn read_json(resp: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

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

// ===========================================================================
// A. REALM TOKEN POLICY
// ===========================================================================

#[tokio::test]
async fn access_token_lifespan_reflected_in_jwt_exp() {
    let state = fixture_state().await;
    let secret = seed_service_account(&state, "svc").await;

    // Set access token lifespan to 10 minutes
    update_realm_token_policy(&state, |p| {
        p.access_token_lifespan = Duration::from_secs(600);
    })
    .await;

    let r = router(state);
    let resp = token_client_credentials(r, "svc", &secret, "api").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    let claims = decode_jwt_payload(json["access_token"].as_str().unwrap());

    let iat = claims["iat"].as_i64().unwrap();
    let exp = claims["exp"].as_i64().unwrap();
    assert_eq!(exp - iat, 600, "token should expire in 10 minutes");
}

#[tokio::test]
async fn access_token_lifespan_change_affects_next_token() {
    let state = fixture_state().await;
    let secret = seed_service_account(&state, "svc").await;

    // First token with default lifespan
    let r = router(state.clone());
    let resp = token_client_credentials(r, "svc", &secret, "api").await;
    let json = read_json(resp).await;
    let claims1 = decode_jwt_payload(json["access_token"].as_str().unwrap());
    let ttl1 = claims1["exp"].as_i64().unwrap() - claims1["iat"].as_i64().unwrap();

    // Change to 120 seconds
    update_realm_token_policy(&state, |p| {
        p.access_token_lifespan = Duration::from_secs(120);
    })
    .await;

    let r2 = router(state);
    let resp = token_client_credentials(r2, "svc", &secret, "api").await;
    let json = read_json(resp).await;
    let claims2 = decode_jwt_payload(json["access_token"].as_str().unwrap());
    let ttl2 = claims2["exp"].as_i64().unwrap() - claims2["iat"].as_i64().unwrap();

    assert_ne!(ttl1, ttl2, "lifespan should change between tokens");
    assert_eq!(ttl2, 120, "second token should have 120s lifespan");
}

#[tokio::test]
async fn default_signing_alg_reflected_in_jwt_header() {
    let state = fixture_state().await;
    let secret = seed_service_account(&state, "svc").await;

    // Default is EdDSA (set by fixture_state)
    let r = router(state);
    let resp = token_client_credentials(r, "svc", &secret, "api").await;
    let json = read_json(resp).await;
    let header = decode_jwt_header(json["access_token"].as_str().unwrap());

    assert_eq!(header["alg"], "EdDSA");
}

#[tokio::test]
#[ignore = "GAP: client-level access_token_lifespan override not enforced in v0.1"]
async fn client_access_token_lifespan_overrides_realm() {
    // In Keycloak: client.access_token_lifespan overrides realm default
    let state = fixture_state().await;
    let secret = seed_service_account(&state, "svc").await;

    // Realm default = 5 min
    update_realm_token_policy(&state, |p| {
        p.access_token_lifespan = Duration::from_secs(300);
    })
    .await;

    // Client override = 60 seconds
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    let mut client = state
        .storage
        .get_client_by_client_id(realm.id, "svc")
        .await
        .unwrap();
    client.access_token_lifespan = Some(Duration::from_secs(60));
    state.storage.update_client(client).await.unwrap();

    let r = router(state);
    let resp = token_client_credentials(r, "svc", &secret, "api").await;
    let json = read_json(resp).await;
    let claims = decode_jwt_payload(json["access_token"].as_str().unwrap());
    let ttl = claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap();
    assert_eq!(ttl, 60, "client override should take precedence");
}

#[tokio::test]
#[ignore = "GAP: revoke_refresh_token_on_use not enforced in v0.1"]
async fn revoke_refresh_on_use_invalidates_old() {
    // In Keycloak: when revoke_refresh_token_on_use=true, using a
    // refresh token invalidates the old one (rotation).
}

// ===========================================================================
// B. REALM SESSION POLICY
// ===========================================================================

#[tokio::test]
async fn sso_session_max_reflected_in_session_expiry() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    let secret = seed_password_grant_client(&state, "web").await;
    seed_user_with_password(&state, realm.id, "alice", "Str0ng!Pass9").await;

    // Set session max to 2 hours
    update_realm_session_policy(&state, |p| {
        p.sso_session_max = Duration::from_secs(7200);
    })
    .await;

    let r = router(state.clone());
    let resp = token_password(r, "web", &secret, "alice", "Str0ng!Pass9", "openid").await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify session was created with correct expiry
    let sessions = state
        .storage
        .list_sessions(realm.id, 10)
        .await
        .unwrap();
    // Find the non-admin session (admin session from fixture has different user)
    let user_session = sessions
        .iter()
        .find(|s| {
            let diff = (s.expires_at - s.started_at).num_seconds();
            // Should be approximately 7200 seconds
            (7100..=7300).contains(&diff)
        });
    assert!(
        user_session.is_some(),
        "session should have ~2h expiry matching sso_session_max"
    );
}

#[tokio::test]
#[ignore = "GAP: sso_session_idle not enforced in v0.1"]
async fn sso_session_idle_enforced() {
    // In Keycloak: session becomes invalid after idle timeout
}

#[tokio::test]
#[ignore = "GAP: remember_me session extension not enforced in v0.1"]
async fn remember_me_extends_session() {
    // In Keycloak: remember_me_max > sso_session_max when remember_me is used
}

// ===========================================================================
// C. PASSWORD POLICY
// ===========================================================================

#[tokio::test]
async fn min_length_enforced() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    seed_user_with_password(&state, realm.id, "alice", "InitialPass1!").await;

    // Set min length to 12
    update_realm_password_policy(
        &state,
        vec![geonosis_core::PasswordRule::Length { min: 12 }],
    )
    .await;

    let cookie = admin_session_cookie(&state).await;
    let r = router(state);

    // Short password should be rejected
    let resp = admin_put(
        r.clone(),
        &cookie,
        "/admin/v1/realms/acme/users/alice/password",
        serde_json::json!({"password": "Short1!"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = read_json(resp).await;
    assert_eq!(json["error"], "password_policy_violation");

    // Long enough password should be accepted
    let resp = admin_put(
        r,
        &cookie,
        "/admin/v1/realms/acme/users/alice/password",
        serde_json::json!({"password": "ThisIsLongEnough1!"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn special_chars_enforced() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    seed_user_with_password(&state, realm.id, "alice", "InitialPass1!").await;

    update_realm_password_policy(
        &state,
        vec![geonosis_core::PasswordRule::SpecialChars { min: 2 }],
    )
    .await;

    let cookie = admin_session_cookie(&state).await;
    let r = router(state);

    // Only 1 special char → rejected
    let resp = admin_put(
        r.clone(),
        &cookie,
        "/admin/v1/realms/acme/users/alice/password",
        serde_json::json!({"password": "OnlyOneSpecial1!"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 2 special chars → accepted
    let resp = admin_put(
        r,
        &cookie,
        "/admin/v1/realms/acme/users/alice/password",
        serde_json::json!({"password": "TwoSpecials@#"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn uppercase_enforced() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    seed_user_with_password(&state, realm.id, "alice", "InitialPass1!").await;

    update_realm_password_policy(
        &state,
        vec![geonosis_core::PasswordRule::UpperCase { min: 1 }],
    )
    .await;

    let cookie = admin_session_cookie(&state).await;
    let r = router(state);

    let resp = admin_put(
        r.clone(),
        &cookie,
        "/admin/v1/realms/acme/users/alice/password",
        serde_json::json!({"password": "alllowercase1!"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let resp = admin_put(
        r,
        &cookie,
        "/admin/v1/realms/acme/users/alice/password",
        serde_json::json!({"password": "hasUppercase1!"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn digits_enforced() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    seed_user_with_password(&state, realm.id, "alice", "InitialPass1!").await;

    update_realm_password_policy(
        &state,
        vec![geonosis_core::PasswordRule::Digits { min: 1 }],
    )
    .await;

    let cookie = admin_session_cookie(&state).await;
    let r = router(state);

    let resp = admin_put(
        r.clone(),
        &cookie,
        "/admin/v1/realms/acme/users/alice/password",
        serde_json::json!({"password": "NoDigitsHere!"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let resp = admin_put(
        r,
        &cookie,
        "/admin/v1/realms/acme/users/alice/password",
        serde_json::json!({"password": "HasDigit1Here!"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn not_username_enforced() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    seed_user_with_password(&state, realm.id, "alice", "InitialPass1!").await;

    update_realm_password_policy(
        &state,
        vec![geonosis_core::PasswordRule::NotUsername],
    )
    .await;

    let cookie = admin_session_cookie(&state).await;
    let r = router(state);

    // Password = username → rejected
    let resp = admin_put(
        r.clone(),
        &cookie,
        "/admin/v1/realms/acme/users/alice/password",
        serde_json::json!({"password": "alice"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Different password → accepted
    let resp = admin_put(
        r,
        &cookie,
        "/admin/v1/realms/acme/users/alice/password",
        serde_json::json!({"password": "NotTheUsername1!"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn not_email_enforced() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    seed_user_with_password(&state, realm.id, "alice", "InitialPass1!").await;

    update_realm_password_policy(
        &state,
        vec![geonosis_core::PasswordRule::NotEmail],
    )
    .await;

    let cookie = admin_session_cookie(&state).await;
    let r = router(state);

    // Password contains email → rejected
    let resp = admin_put(
        r.clone(),
        &cookie,
        "/admin/v1/realms/acme/users/alice/password",
        serde_json::json!({"password": "alice@example.com"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn multiple_password_rules_all_checked() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    seed_user_with_password(&state, realm.id, "alice", "InitialPass1!").await;

    update_realm_password_policy(
        &state,
        vec![
            geonosis_core::PasswordRule::Length { min: 8 },
            geonosis_core::PasswordRule::SpecialChars { min: 1 },
            geonosis_core::PasswordRule::Digits { min: 1 },
        ],
    )
    .await;

    let cookie = admin_session_cookie(&state).await;
    let r = router(state);

    // Violates all three
    let resp = admin_put(
        r.clone(),
        &cookie,
        "/admin/v1/realms/acme/users/alice/password",
        serde_json::json!({"password": "short"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = read_json(resp).await;
    let violations = json["violations"].as_array().unwrap();
    assert!(violations.len() >= 2, "multiple violations should be returned");

    // Passes all
    let resp = admin_put(
        r,
        &cookie,
        "/admin/v1/realms/acme/users/alice/password",
        serde_json::json!({"password": "GoodPass1!x"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn password_policy_change_applies_immediately() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    seed_user_with_password(&state, realm.id, "alice", "InitialPass1!").await;

    let cookie = admin_session_cookie(&state).await;

    // No special char rule → "NoSpecial1" should be accepted
    update_realm_password_policy(
        &state,
        vec![geonosis_core::PasswordRule::Length { min: 8 }],
    )
    .await;

    let r = router(state.clone());
    let resp = admin_put(
        r,
        &cookie,
        "/admin/v1/realms/acme/users/alice/password",
        serde_json::json!({"password": "NoSpecial1Long"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Now add special char requirement
    update_realm_password_policy(
        &state,
        vec![
            geonosis_core::PasswordRule::Length { min: 8 },
            geonosis_core::PasswordRule::SpecialChars { min: 1 },
        ],
    )
    .await;

    // Same password pattern should now fail
    let r2 = router(state);
    let resp = admin_put(
        r2,
        &cookie,
        "/admin/v1/realms/acme/users/alice/password",
        serde_json::json!({"password": "NoSpecial2Long"}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ===========================================================================
// D. BRUTE FORCE POLICY
// ===========================================================================

#[tokio::test]
#[ignore = "GAP: brute force not enforced on ROPC/token endpoint path in v0.1 (only flow-based login)"]
async fn lockout_after_max_failures() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    let secret = seed_password_grant_client(&state, "web").await;
    seed_user_with_password(&state, realm.id, "alice", "Str0ng!Pass9").await;

    // Set max failures to 3
    update_realm_brute_force(&state, |bf| {
        bf.enabled = true;
        bf.max_login_failures = 3;
        bf.permanent_lockout = false;
        bf.wait_increment = Duration::from_secs(60);
    })
    .await;

    // 3 wrong attempts
    for _ in 0..3 {
        let r = router(state.clone());
        let resp = token_password(r, "web", &secret, "alice", "WRONG", "openid").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // Correct password should now fail due to lockout
    let r = router(state);
    let resp = token_password(r, "web", &secret, "alice", "Str0ng!Pass9", "openid").await;
    // Should be rejected (either 400 "user disabled" or "account locked")
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "account should be locked after max failures"
    );
}

#[tokio::test]
async fn brute_force_disabled_no_lockout() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    let secret = seed_password_grant_client(&state, "web").await;
    seed_user_with_password(&state, realm.id, "alice", "Str0ng!Pass9").await;

    // Disable brute force
    update_realm_brute_force(&state, |bf| {
        bf.enabled = false;
    })
    .await;

    // Many wrong attempts
    for _ in 0..10 {
        let r = router(state.clone());
        let _ = token_password(r, "web", &secret, "alice", "WRONG", "openid").await;
    }

    // Correct password should still work
    let r = router(state);
    let resp = token_password(r, "web", &secret, "alice", "Str0ng!Pass9", "openid").await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "brute force disabled — login should succeed"
    );
}

// ===========================================================================
// E. CLIENT GRANT POLICY
// ===========================================================================

#[tokio::test]
async fn client_credentials_disabled_rejected() {
    let state = fixture_state().await;
    let secret = seed_service_account(&state, "svc").await;

    // Verify it works first
    let r = router(state.clone());
    let resp = token_client_credentials(r, "svc", &secret, "api").await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Disable client_credentials grant
    update_client_grants(&state, "svc", |g| {
        g.client_credentials = false;
    })
    .await;

    let r2 = router(state);
    let resp = token_client_credentials(r2, "svc", &secret, "api").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = read_json(resp).await;
    assert_eq!(json["error"], "unauthorized_client");
}

#[tokio::test]
async fn password_grant_disabled_rejected() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    let secret = seed_password_grant_client(&state, "web").await;
    seed_user_with_password(&state, realm.id, "alice", "Str0ng!Pass9").await;

    // Verify it works
    let r = router(state.clone());
    let resp = token_password(r, "web", &secret, "alice", "Str0ng!Pass9", "openid").await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Disable password grant
    update_client_grants(&state, "web", |g| {
        g.password = false;
    })
    .await;

    let r2 = router(state);
    let resp = token_password(r2, "web", &secret, "alice", "Str0ng!Pass9", "openid").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = read_json(resp).await;
    assert_eq!(json["error"], "unauthorized_client");
}

// ===========================================================================
// F. CLIENT AUTH METHOD
// ===========================================================================

#[tokio::test]
async fn client_secret_basic_no_secret_rejected() {
    let state = fixture_state().await;
    let _secret = seed_service_account(&state, "svc").await;
    let r = router(state);

    // Send without Authorization header
    let resp = r
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(token_url())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("grant_type=client_credentials&client_id=svc"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn client_secret_basic_wrong_secret_rejected() {
    let state = fixture_state().await;
    let _secret = seed_service_account(&state, "svc").await;
    let r = router(state);

    let resp = token_client_credentials(r, "svc", "WRONG", "api").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json = read_json(resp).await;
    assert_eq!(json["error"], "invalid_client");
}

#[tokio::test]
async fn public_client_no_secret_needed() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    seed_eddsa_key(&state, realm.id).await;
    seed_public_client(&state, "spa").await;

    // Public client with introspect (no secret needed, just client_id)
    let r = router(state);
    let resp = r
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/realms/acme/protocol/openid-connect/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("token=fake&client_id=spa"))
                .unwrap(),
        )
        .await
        .unwrap();
    // Should be 200 with active=false (not 401 for missing secret)
    assert_eq!(resp.status(), StatusCode::OK);
}

// ===========================================================================
// G. REDIRECT URI
// ===========================================================================

#[tokio::test]
async fn registered_uri_not_rejected() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    seed_eddsa_key(&state, realm.id).await;
    seed_public_client(&state, "spa").await;
    // spa has redirect_uri = "https://example.com/cb"

    let r = router(state);
    let resp = r
        .oneshot(
            Request::builder()
                .uri("/realms/acme/protocol/openid-connect/auth?response_type=code&client_id=spa&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&scope=openid&nonce=n1&code_challenge=abc&code_challenge_method=S256")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // Should NOT be a 400 redirect mismatch — it'll be a login page or redirect
    assert_ne!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "registered redirect_uri should be accepted"
    );
}

#[tokio::test]
async fn unregistered_uri_rejected() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    seed_eddsa_key(&state, realm.id).await;
    seed_public_client(&state, "spa").await;

    let r = router(state);
    let resp = r
        .oneshot(
            Request::builder()
                .uri("/realms/acme/protocol/openid-connect/auth?response_type=code&client_id=spa&redirect_uri=https%3A%2F%2Fevil.com%2Fcb&scope=openid&nonce=n1&code_challenge=abc&code_challenge_method=S256")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "unregistered redirect_uri should be rejected"
    );
}

#[tokio::test]
#[ignore = "GAP: PKCE validation happens at code exchange, not at /authorize in v0.1"]
async fn public_client_pkce_required() {
    let state = fixture_state().await;
    let realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    seed_eddsa_key(&state, realm.id).await;
    seed_public_client(&state, "spa").await;

    let r = router(state);
    // No code_challenge parameter
    let resp = r
        .oneshot(
            Request::builder()
                .uri("/realms/acme/protocol/openid-connect/auth?response_type=code&client_id=spa&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&scope=openid&nonce=n1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "public client without PKCE should be rejected"
    );
}

// ===========================================================================
// H. CLIENT ENABLE/DISABLE
// ===========================================================================

#[tokio::test]
async fn disabled_client_rejected_at_token() {
    let state = fixture_state().await;
    let secret = seed_service_account(&state, "svc").await;

    // Verify works
    let r = router(state.clone());
    let resp = token_client_credentials(r, "svc", &secret, "api").await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Disable
    set_client_enabled(&state, "svc", false).await;

    let r2 = router(state);
    let resp = token_client_credentials(r2, "svc", &secret, "api").await;
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "disabled client should be rejected"
    );
}

// ===========================================================================
// I. REALM ENABLE/DISABLE
// ===========================================================================

#[tokio::test]
#[ignore = "GAP: realm.enabled not checked in protocol handlers in v0.1"]
async fn disabled_realm_rejects_all_protocol_requests() {
    // In Keycloak: disabled realm → all protocol endpoints return 403
    let state = fixture_state().await;
    let secret = seed_service_account(&state, "svc").await;

    let mut realm = state.storage.get_realm_by_slug("acme").await.unwrap();
    realm.enabled = false;
    state.storage.update_realm(realm).await.unwrap();

    let r = router(state);
    let resp = token_client_credentials(r, "svc", &secret, "api").await;
    assert_ne!(resp.status(), StatusCode::OK, "disabled realm should reject");
}

// ===========================================================================
// J. LOGIN SETTINGS
// ===========================================================================

#[tokio::test]
#[ignore = "GAP: login_with_email_allowed not enforced in v0.1"]
async fn login_with_email_allowed() {
    // In Keycloak: login_with_email_allowed=true → email as username works
}

#[tokio::test]
#[ignore = "GAP: verify_email_required not enforced in v0.1"]
async fn verify_email_required_blocks_login() {
    // In Keycloak: verify_email_required=true → unverified user blocked at login
}

#[tokio::test]
#[ignore = "GAP: registration_allowed not enforced in v0.1"]
async fn registration_allowed_controls_endpoint() {
    // In Keycloak: registration_allowed=true → /auth?registration=true works
}
