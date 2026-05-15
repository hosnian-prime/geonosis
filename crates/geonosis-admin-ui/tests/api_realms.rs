mod helpers;

use tower::ServiceExt;

use helpers::assert::*;
use helpers::request::*;
use helpers::state::{fixture_state, test_router};

#[tokio::test]
async fn list_realms_returns_seeded() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router.oneshot(get("/admin/v1/realms")).await.unwrap();
    let json = assert_ok_json(resp).await;
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["slug"], "acme");
}

#[tokio::test]
async fn create_realm() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms",
            serde_json::json!({
                "slug": "new-realm",
                "display_name": "New Realm"
            }),
        ))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["slug"], "new-realm");
    assert_eq!(json["display_name"], "New Realm");
    assert_eq!(json["enabled"], true);
    assert!(json["id"].is_string());
}

#[tokio::test]
async fn create_realm_seeds_default_flows() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());

    // Create a new realm
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms",
            serde_json::json!({
                "slug": "flow-test",
                "display_name": "Flow Test"
            }),
        ))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    let realm_id = json["id"].as_str().unwrap();

    // Dry-run the browser flow to confirm it was seeded
    let router2 = test_router(state);
    let resp = router2
        .oneshot(post_json(
            "/admin/v1/realms/flow-test/flows/browser/dry-run",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let _ = realm_id; // used for assertion above
}

#[tokio::test]
async fn get_realm_by_slug() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/acme"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["slug"], "acme");
    assert_eq!(json["display_name"], "Acme");
}

#[tokio::test]
async fn get_unknown_realm_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/nope"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}

#[tokio::test]
async fn update_realm_preserves_slug_and_id() {
    let (state, _) = fixture_state().await;

    // Get the original realm to capture its ID
    let router = test_router(state.clone());
    let resp = router
        .oneshot(get("/admin/v1/realms/acme"))
        .await
        .unwrap();
    let original = assert_ok_json(resp).await;
    let original_id = original["id"].as_str().unwrap().to_string();

    // Update with a different display_name
    let router2 = test_router(state);
    let mut updated = original.clone();
    updated["display_name"] = serde_json::json!("Acme Corp");
    let resp = router2
        .oneshot(put_json("/admin/v1/realms/acme", updated))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["id"], original_id, "id must not change");
    assert_eq!(json["slug"], "acme", "slug must not change");
    assert_eq!(json["display_name"], "Acme Corp");
}

#[tokio::test]
async fn update_unknown_realm_404() {
    let (state, _) = fixture_state().await;

    // Get a valid realm body from the existing realm
    let router = test_router(state.clone());
    let resp = router
        .oneshot(get("/admin/v1/realms/acme"))
        .await
        .unwrap();
    let body = assert_ok_json(resp).await;

    // PUT it against a non-existing slug
    let router2 = test_router(state);
    let resp = router2
        .oneshot(put_json("/admin/v1/realms/nope", body))
        .await
        .unwrap();
    assert_not_found(resp).await;
}

#[tokio::test]
async fn delete_realm() {
    let (state, _) = fixture_state().await;

    // Delete
    let router = test_router(state.clone());
    let resp = router
        .oneshot(delete_req("/admin/v1/realms/acme"))
        .await
        .unwrap();
    assert_no_content(resp).await;

    // Verify it's gone
    let router2 = test_router(state);
    let resp = router2
        .oneshot(get("/admin/v1/realms/acme"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}

#[tokio::test]
async fn delete_unknown_realm_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(delete_req("/admin/v1/realms/nope"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}
