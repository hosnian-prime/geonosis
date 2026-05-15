mod helpers;

use tower::ServiceExt;

use helpers::assert::*;
use helpers::request::*;
use helpers::state::{fixture_state, seed_user, test_router};

#[tokio::test]
async fn list_groups_empty() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/groups"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn create_group_root() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms/acme/groups",
            serde_json::json!({"name": "engineering"}),
        ))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["name"], "engineering");
    assert_eq!(json["path"], "/engineering");
}

#[tokio::test]
async fn create_group_nested() {
    let (state, _) = fixture_state().await;
    // Create parent
    let router = test_router(state.clone());
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms/acme/groups",
            serde_json::json!({"name": "engineering"}),
        ))
        .await
        .unwrap();
    let parent = assert_ok_json(resp).await;
    let parent_id = parent["id"].as_str().unwrap();

    // Create child
    let router2 = test_router(state);
    let resp = router2
        .oneshot(post_json(
            "/admin/v1/realms/acme/groups",
            serde_json::json!({
                "name": "backend",
                "parent_id": parent_id
            }),
        ))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["name"], "backend");
    assert_eq!(json["path"], "/engineering/backend");
}

#[tokio::test]
async fn get_group() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms/acme/groups",
            serde_json::json!({"name": "devs"}),
        ))
        .await
        .unwrap();
    let group = assert_ok_json(resp).await;
    let group_id = group["id"].as_str().unwrap();

    let router2 = test_router(state);
    let resp = router2
        .oneshot(get(&format!("/admin/v1/realms/acme/groups/{group_id}")))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["name"], "devs");
}

#[tokio::test]
async fn get_unknown_group_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get(
            "/admin/v1/realms/acme/groups/01JAAAAAAAAAAAAAAAAAAAAAA0",
        ))
        .await
        .unwrap();
    assert_not_found(resp).await;
}

#[tokio::test]
async fn update_group_preserves_path() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms/acme/groups",
            serde_json::json!({"name": "devs"}),
        ))
        .await
        .unwrap();
    let original = assert_ok_json(resp).await;
    let group_id = original["id"].as_str().unwrap();

    let mut updated = original.clone();
    updated["name"] = serde_json::json!("renamed");
    let router2 = test_router(state);
    let resp = router2
        .oneshot(put_json(
            &format!("/admin/v1/realms/acme/groups/{group_id}"),
            updated,
        ))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["path"], "/devs", "path must not change via update");
}

#[tokio::test]
async fn delete_group() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms/acme/groups",
            serde_json::json!({"name": "devs"}),
        ))
        .await
        .unwrap();
    let group = assert_ok_json(resp).await;
    let group_id = group["id"].as_str().unwrap();

    let router2 = test_router(state.clone());
    let resp = router2
        .oneshot(delete_req(&format!(
            "/admin/v1/realms/acme/groups/{group_id}"
        )))
        .await
        .unwrap();
    assert_no_content(resp).await;

    let router3 = test_router(state);
    let resp = router3
        .oneshot(get(&format!("/admin/v1/realms/acme/groups/{group_id}")))
        .await
        .unwrap();
    assert_not_found(resp).await;
}

#[tokio::test]
async fn assign_user_to_group() {
    let (state, realm_id) = fixture_state().await;
    let user = seed_user(&state, realm_id, "alice").await;

    let router = test_router(state.clone());
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms/acme/groups",
            serde_json::json!({"name": "devs"}),
        ))
        .await
        .unwrap();
    let group = assert_ok_json(resp).await;
    let group_id = group["id"].as_str().unwrap();

    let router2 = test_router(state.clone());
    let resp = router2
        .oneshot(post_json(
            &format!("/admin/v1/realms/acme/users/{}/groups", user.id),
            serde_json::json!({"group_id": group_id}),
        ))
        .await
        .unwrap();
    assert_no_content(resp).await;
}

#[tokio::test]
async fn list_user_groups() {
    let (state, realm_id) = fixture_state().await;
    let user = seed_user(&state, realm_id, "alice").await;

    let router = test_router(state.clone());
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms/acme/groups",
            serde_json::json!({"name": "devs"}),
        ))
        .await
        .unwrap();
    let group = assert_ok_json(resp).await;
    let group_id = group["id"].as_str().unwrap();

    let router2 = test_router(state.clone());
    router2
        .oneshot(post_json(
            &format!("/admin/v1/realms/acme/users/{}/groups", user.id),
            serde_json::json!({"group_id": group_id}),
        ))
        .await
        .unwrap();

    let router3 = test_router(state);
    let resp = router3
        .oneshot(get(&format!(
            "/admin/v1/realms/acme/users/{}/groups",
            user.id
        )))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn unassign_user_from_group() {
    let (state, realm_id) = fixture_state().await;
    let user = seed_user(&state, realm_id, "alice").await;

    let router = test_router(state.clone());
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms/acme/groups",
            serde_json::json!({"name": "devs"}),
        ))
        .await
        .unwrap();
    let group = assert_ok_json(resp).await;
    let group_id = group["id"].as_str().unwrap();

    // Assign
    let router2 = test_router(state.clone());
    router2
        .oneshot(post_json(
            &format!("/admin/v1/realms/acme/users/{}/groups", user.id),
            serde_json::json!({"group_id": group_id}),
        ))
        .await
        .unwrap();

    // Unassign
    let router3 = test_router(state.clone());
    let resp = router3
        .oneshot(delete_req(&format!(
            "/admin/v1/realms/acme/users/{}/groups/{}",
            user.id, group_id
        )))
        .await
        .unwrap();
    assert_no_content(resp).await;

    // Verify empty
    let router4 = test_router(state);
    let resp = router4
        .oneshot(get(&format!(
            "/admin/v1/realms/acme/users/{}/groups",
            user.id
        )))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn assign_role_to_group() {
    let (state, _) = fixture_state().await;

    // Create group
    let router = test_router(state.clone());
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms/acme/groups",
            serde_json::json!({"name": "devs"}),
        ))
        .await
        .unwrap();
    let group = assert_ok_json(resp).await;
    let group_id = group["id"].as_str().unwrap();

    // Create role
    let router2 = test_router(state.clone());
    let resp = router2
        .oneshot(post_json(
            "/admin/v1/realms/acme/roles",
            serde_json::json!({"name": "editor"}),
        ))
        .await
        .unwrap();
    let role = assert_ok_json(resp).await;
    let role_id = role["id"].as_str().unwrap();

    // Assign role to group
    let router3 = test_router(state.clone());
    let resp = router3
        .oneshot(post_json(
            &format!("/admin/v1/realms/acme/groups/{group_id}/roles"),
            serde_json::json!({"role_id": role_id}),
        ))
        .await
        .unwrap();
    assert_no_content(resp).await;
}

#[tokio::test]
async fn list_group_roles() {
    let (state, _) = fixture_state().await;

    let router = test_router(state.clone());
    let resp = router
        .oneshot(post_json(
            "/admin/v1/realms/acme/groups",
            serde_json::json!({"name": "devs"}),
        ))
        .await
        .unwrap();
    let group = assert_ok_json(resp).await;
    let group_id = group["id"].as_str().unwrap();

    let router2 = test_router(state.clone());
    let resp = router2
        .oneshot(post_json(
            "/admin/v1/realms/acme/roles",
            serde_json::json!({"name": "editor"}),
        ))
        .await
        .unwrap();
    let role = assert_ok_json(resp).await;
    let role_id = role["id"].as_str().unwrap();

    let router3 = test_router(state.clone());
    router3
        .oneshot(post_json(
            &format!("/admin/v1/realms/acme/groups/{group_id}/roles"),
            serde_json::json!({"role_id": role_id}),
        ))
        .await
        .unwrap();

    let router4 = test_router(state);
    let resp = router4
        .oneshot(get(&format!(
            "/admin/v1/realms/acme/groups/{group_id}/roles"
        )))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 1);
    assert_eq!(json.as_array().unwrap()[0]["name"], "editor");
}

#[tokio::test]
async fn group_on_unknown_realm_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/nope/groups"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}
