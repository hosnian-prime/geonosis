mod helpers;

use tower::ServiceExt;

use helpers::assert::*;
use helpers::request::*;
use helpers::state::{fixture_state, seed_user, test_router};

#[tokio::test]
async fn list_users_empty() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/users"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn list_users_after_create() {
    let (state, realm_id) = fixture_state().await;
    seed_user(&state, realm_id, "alice").await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/users"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["username"], "alice");
}

#[tokio::test]
async fn list_users_respects_limit() {
    let (state, realm_id) = fixture_state().await;
    seed_user(&state, realm_id, "alice").await;
    seed_user(&state, realm_id, "bob").await;
    seed_user(&state, realm_id, "carol").await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/users?limit=1"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert!(json.as_array().unwrap().len() <= 1);
}

#[tokio::test]
async fn create_user() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms/acme/users",
            serde_json::json!({
                "username": "alice",
                "email": "alice@example.com"
            }),
        ))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["username"], "alice");
    assert_eq!(json["email"], "alice@example.com");
    assert_eq!(json["enabled"], true);
    assert!(json["id"].is_string());
}

#[tokio::test]
async fn create_user_defaults_enabled() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms/acme/users",
            serde_json::json!({"username": "bob"}),
        ))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["enabled"], true);
}

#[tokio::test]
async fn get_user_by_username() {
    let (state, realm_id) = fixture_state().await;
    seed_user(&state, realm_id, "alice").await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/users/alice"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["username"], "alice");
}

#[tokio::test]
async fn get_unknown_user_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/users/nobody"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}

#[tokio::test]
async fn update_user_preserves_identity() {
    let (state, realm_id) = fixture_state().await;
    let user = seed_user(&state, realm_id, "alice").await;

    // Get the user to build an update payload
    let router = test_router(state.clone());
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/users/alice"))
        .await
        .unwrap();
    let mut original = assert_ok_json(resp).await;
    let original_id = original["id"].as_str().unwrap().to_string();
    let original_created = original["created_at"].as_str().unwrap().to_string();

    // Update email
    original["email"] = serde_json::json!("newalice@example.com");
    let router2 = test_router(state);
    let resp = router2
        .oneshot(put_json("/admin/v1/realms/acme/users/alice", original))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["id"], original_id, "id must not change");
    assert_eq!(json["username"], "alice", "username must not change");
    assert_eq!(
        json["created_at"], original_created,
        "created_at must not change"
    );
    assert_eq!(json["email"], "newalice@example.com");
    let _ = user;
}

#[tokio::test]
async fn delete_user() {
    let (state, realm_id) = fixture_state().await;
    seed_user(&state, realm_id, "alice").await;

    let router = test_router(state.clone());
    let resp = router
        .oneshot(delete_req("/admin/v1/realms/acme/users/alice"))
        .await
        .unwrap();
    assert_no_content(resp).await;

    // Verify gone
    let router2 = test_router(state);
    let resp = router2
        .oneshot(get("/admin/v1/realms/acme/users/alice"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}

#[tokio::test]
async fn verify_email_sets_flag() {
    let (state, realm_id) = fixture_state().await;
    seed_user(&state, realm_id, "alice").await;

    let router = test_router(state);
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms/acme/users/alice/verify-email",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["email_verified"], true);
}

#[tokio::test]
async fn set_password_succeeds() {
    let (state, realm_id) = fixture_state().await;
    seed_user(&state, realm_id, "alice").await;

    let router = test_router(state);
    let resp = router
        .oneshot(put_json(
            "/admin/v1/realms/acme/users/alice/password",
            serde_json::json!({"password": "Strong-P@ss-123"}),
        ))
        .await
        .unwrap();
    assert_no_content(resp).await;
}

#[tokio::test]
async fn set_password_rejects_weak() {
    // Default PasswordPolicy has Length { min: 8 }
    let (state, realm_id) = fixture_state().await;
    seed_user(&state, realm_id, "alice").await;

    let router = test_router(state);
    let resp = router
        .oneshot(put_json(
            "/admin/v1/realms/acme/users/alice/password",
            serde_json::json!({"password": "short"}),
        ))
        .await
        .unwrap();
    let json = assert_bad_request(resp).await;
    assert_eq!(json["error"], "password_policy_violation");
    let violations = json["violations"].as_array().unwrap();
    assert!(violations.iter().any(|v| v == "length"));
}

#[tokio::test]
async fn set_password_unknown_user_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(put_json(
            "/admin/v1/realms/acme/users/nobody/password",
            serde_json::json!({"password": "whatever-123"}),
        ))
        .await
        .unwrap();
    assert_not_found(resp).await;
}

#[tokio::test]
async fn user_on_unknown_realm_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/nope/users"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}
