mod helpers;

use tower::ServiceExt;

use helpers::assert::*;
use helpers::request::*;
use helpers::state::{fixture_state, seed_user, test_router};

#[tokio::test]
async fn list_roles_empty() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/roles"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn create_role() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms/acme/roles",
            serde_json::json!({
                "name": "admin",
                "description": "Administrator role"
            }),
        ))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["name"], "admin");
    assert_eq!(json["description"], "Administrator role");
}

#[tokio::test]
async fn get_role() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());
    router
        .oneshot(post_json(
            "/admin/v1/realms/acme/roles",
            serde_json::json!({"name": "admin"}),
        ))
        .await
        .unwrap();

    let router2 = test_router(state);
    let resp = router2
        .oneshot(get("/admin/v1/realms/acme/roles/admin"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["name"], "admin");
}

#[tokio::test]
async fn get_unknown_role_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/roles/nope"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}

#[tokio::test]
async fn update_role_preserves_identity() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms/acme/roles",
            serde_json::json!({"name": "admin"}),
        ))
        .await
        .unwrap();
    let original = assert_ok_json(resp).await;
    let original_id = original["id"].as_str().unwrap().to_string();

    let mut updated = original.clone();
    updated["description"] = serde_json::json!("Updated description");
    let router2 = test_router(state);
    let resp = router2
        .oneshot(put_json("/admin/v1/realms/acme/roles/admin", updated))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["id"], original_id, "id must not change");
    assert_eq!(json["description"], "Updated description");
}

#[tokio::test]
async fn delete_role() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());
    router
        .oneshot(post_json(
            "/admin/v1/realms/acme/roles",
            serde_json::json!({"name": "admin"}),
        ))
        .await
        .unwrap();

    let router2 = test_router(state.clone());
    let resp = router2
        .oneshot(delete_req("/admin/v1/realms/acme/roles/admin"))
        .await
        .unwrap();
    assert_no_content(resp).await;

    let router3 = test_router(state);
    let resp = router3
        .oneshot(get("/admin/v1/realms/acme/roles/admin"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}

#[tokio::test]
async fn delete_unknown_role_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(delete_req("/admin/v1/realms/acme/roles/nope"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}

#[tokio::test]
async fn assign_role_to_user() {
    let (state, realm_id) = fixture_state().await;
    let user = seed_user(&state, realm_id, "alice").await;

    // Create role
    let router = test_router(state.clone());
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms/acme/roles",
            serde_json::json!({"name": "editor"}),
        ))
        .await
        .unwrap();
    let role = assert_ok_json(resp).await;
    let role_id = role["id"].as_str().unwrap();

    // Assign
    let router2 = test_router(state.clone());
    let resp = router2
        .oneshot(post_json(
            &format!("/admin/v1/realms/acme/users/{}/roles", user.id),
            serde_json::json!({"role_id": role_id}),
        ))
        .await
        .unwrap();
    assert_no_content(resp).await;
}

#[tokio::test]
async fn list_user_roles_after_assign() {
    let (state, realm_id) = fixture_state().await;
    let user = seed_user(&state, realm_id, "alice").await;

    let router = test_router(state.clone());
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms/acme/roles",
            serde_json::json!({"name": "editor"}),
        ))
        .await
        .unwrap();
    let role = assert_ok_json(resp).await;
    let role_id = role["id"].as_str().unwrap();

    let router2 = test_router(state.clone());
    router2
        .oneshot(post_json(
            &format!("/admin/v1/realms/acme/users/{}/roles", user.id),
            serde_json::json!({"role_id": role_id}),
        ))
        .await
        .unwrap();

    let router3 = test_router(state);
    let resp = router3
        .oneshot(get(&format!(
            "/admin/v1/realms/acme/users/{}/roles",
            user.id
        )))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "editor");
}

#[tokio::test]
async fn unassign_role_from_user() {
    let (state, realm_id) = fixture_state().await;
    let user = seed_user(&state, realm_id, "alice").await;

    let router = test_router(state.clone());
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms/acme/roles",
            serde_json::json!({"name": "editor"}),
        ))
        .await
        .unwrap();
    let role = assert_ok_json(resp).await;
    let role_id = role["id"].as_str().unwrap();

    // Assign
    let router2 = test_router(state.clone());
    router2
        .oneshot(post_json(
            &format!("/admin/v1/realms/acme/users/{}/roles", user.id),
            serde_json::json!({"role_id": role_id}),
        ))
        .await
        .unwrap();

    // Unassign
    let router3 = test_router(state.clone());
    let resp = router3
        .oneshot(delete_req(&format!(
            "/admin/v1/realms/acme/users/{}/roles/{}",
            user.id, role_id
        )))
        .await
        .unwrap();
    assert_no_content(resp).await;

    // Verify empty
    let router4 = test_router(state);
    let resp = router4
        .oneshot(get(&format!(
            "/admin/v1/realms/acme/users/{}/roles",
            user.id
        )))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn list_user_roles_empty() {
    let (state, realm_id) = fixture_state().await;
    let user = seed_user(&state, realm_id, "alice").await;
    let router = test_router(state);
    let resp = router
        .oneshot(get(&format!(
            "/admin/v1/realms/acme/users/{}/roles",
            user.id
        )))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn role_on_unknown_realm_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/nope/roles"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}
