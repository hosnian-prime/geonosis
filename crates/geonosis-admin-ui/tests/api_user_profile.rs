mod helpers;

use tower::ServiceExt;

use helpers::assert::*;
use helpers::request::*;
use helpers::state::{fixture_state, test_router};

#[tokio::test]
async fn get_schema_returns_default() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/user-profile"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert!(json["realm_id"].is_string());
}

#[tokio::test]
async fn put_schema_updates_and_returns() {
    let (state, _) = fixture_state().await;

    // Get current schema
    let router = test_router(state.clone());
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/user-profile"))
        .await
        .unwrap();
    let mut schema = assert_ok_json(resp).await;

    // Update unmanaged_policy
    schema["unmanaged_policy"] = serde_json::json!("allow");
    let router2 = test_router(state);
    let resp = router2
        .oneshot(put_json("/admin/v1/realms/acme/user-profile", schema))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["unmanaged_policy"], "allow");
}

#[tokio::test]
async fn put_schema_forces_realm_id() {
    let (state, _) = fixture_state().await;

    let router = test_router(state.clone());
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/user-profile"))
        .await
        .unwrap();
    let mut schema = assert_ok_json(resp).await;
    let original_realm_id = schema["realm_id"].as_str().unwrap().to_string();

    // Try to change realm_id — should be overwritten
    schema["realm_id"] = serde_json::json!("01JAAAAAAAAAAAAAAAAAAAAAA0");
    let router2 = test_router(state);
    let resp = router2
        .oneshot(put_json("/admin/v1/realms/acme/user-profile", schema))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(
        json["realm_id"], original_realm_id,
        "realm_id should be forced to the path realm"
    );
}

#[tokio::test]
async fn user_profile_on_unknown_realm_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/nope/user-profile"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}
