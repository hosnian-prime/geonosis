mod helpers;

use tower::ServiceExt;

use helpers::assert::*;
use helpers::request::*;
use helpers::state::{fixture_state, test_router};

fn public_client_body() -> serde_json::Value {
    serde_json::json!({
        "client_id": "my-app",
        "display_name": "My App",
        "kind": "public",
        "redirect_uris": ["https://app.example/cb"]
    })
}

#[tokio::test]
async fn list_clients_empty() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/clients"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn create_client() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms/acme/clients",
            public_client_body(),
        ))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["client_id"], "my-app");
    assert_eq!(json["kind"], "public");
    assert_eq!(json["enabled"], true);
    assert!(json["id"].is_string());
}

#[tokio::test]
async fn get_client() {
    let (state, _) = fixture_state().await;
    // Create first
    let router = test_router(state.clone());
    router
        .oneshot(post_json(
            "/admin/v1/realms/acme/clients",
            public_client_body(),
        ))
        .await
        .unwrap();

    // Get
    let router2 = test_router(state);
    let resp = router2
        .oneshot(get("/admin/v1/realms/acme/clients/my-app"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["client_id"], "my-app");
}

#[tokio::test]
async fn get_unknown_client_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/clients/nope"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}

#[tokio::test]
async fn update_client_preserves_identity() {
    let (state, _) = fixture_state().await;
    // Create
    let router = test_router(state.clone());
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms/acme/clients",
            public_client_body(),
        ))
        .await
        .unwrap();
    let original = assert_ok_json(resp).await;
    let original_id = original["id"].as_str().unwrap().to_string();
    let original_created = original["created_at"].as_str().unwrap().to_string();

    // Update
    let mut updated = original.clone();
    updated["display_name"] = serde_json::json!("My Updated App");
    let router2 = test_router(state);
    let resp = router2
        .oneshot(put_json("/admin/v1/realms/acme/clients/my-app", updated))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["id"], original_id, "id must not change");
    assert_eq!(json["client_id"], "my-app", "client_id must not change");
    assert_eq!(
        json["created_at"], original_created,
        "created_at must not change"
    );
    assert_eq!(json["display_name"], "My Updated App");
}

#[tokio::test]
async fn delete_client() {
    let (state, _) = fixture_state().await;
    // Create
    let router = test_router(state.clone());
    router
        .oneshot(post_json(
            "/admin/v1/realms/acme/clients",
            public_client_body(),
        ))
        .await
        .unwrap();

    // Delete
    let router2 = test_router(state.clone());
    let resp = router2
        .oneshot(delete_req("/admin/v1/realms/acme/clients/my-app"))
        .await
        .unwrap();
    assert_no_content(resp).await;

    // Verify gone
    let router3 = test_router(state);
    let resp = router3
        .oneshot(get("/admin/v1/realms/acme/clients/my-app"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}

#[tokio::test]
async fn delete_unknown_client_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(delete_req("/admin/v1/realms/acme/clients/nope"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}

#[tokio::test]
async fn client_on_unknown_realm_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/nope/clients"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}
