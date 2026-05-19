mod helpers;

use tower::ServiceExt;

use helpers::assert::*;
use helpers::request::*;
use helpers::state::{fixture_state, seed_agent, test_router};

fn agent_body() -> serde_json::Value {
    serde_json::json!({
        "alias": "bot-1",
        "display_name": "Test Bot",
        "kind": "assistant",
        "parent_subject": {"kind": "user", "user_id": "01JAAAAAAAAAAAAAAAAAAAAAA0"},
        "auth_method": "token-exchange-only"
    })
}

#[tokio::test]
async fn list_agents_empty() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/agents"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn create_agent() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(post_json("/admin/v1/realms/acme/agents", agent_body()))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["alias"], "bot-1");
    assert_eq!(json["display_name"], "Test Bot");
    assert_eq!(json["kind"], "assistant");
    assert!(json["revoked_at"].is_null());
    assert_eq!(json["enabled"], true);
}

#[tokio::test]
async fn get_agent() {
    let (state, realm_id) = fixture_state().await;
    seed_agent(&state, realm_id, "bot-1").await;

    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/agents/bot-1"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["alias"], "bot-1");
}

#[tokio::test]
async fn get_unknown_agent_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/agents/nope"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}

#[tokio::test]
async fn update_agent_preserves_parent_subject() {
    let (state, realm_id) = fixture_state().await;
    let agent = seed_agent(&state, realm_id, "bot-1").await;

    let router = test_router(state.clone());
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/agents/bot-1"))
        .await
        .unwrap();
    let mut original = assert_ok_json(resp).await;
    let original_parent = original["parent_subject"].clone();

    // Try to change parent_subject — should be preserved
    original["display_name"] = serde_json::json!("Updated Bot");
    original["parent_subject"] =
        serde_json::json!({"kind": "user", "user_id": "01JAAAAAAAAAAAAAAAAAAAAAA9"});

    let router2 = test_router(state);
    let resp = router2
        .oneshot(put_json("/admin/v1/realms/acme/agents/bot-1", original))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(
        json["parent_subject"], original_parent,
        "parent_subject must not change"
    );
    assert_eq!(json["display_name"], "Updated Bot");
    let _ = agent;
}

#[tokio::test]
async fn revoke_agent() {
    let (state, realm_id) = fixture_state().await;
    seed_agent(&state, realm_id, "bot-1").await;

    let router = test_router(state);
    let resp = router
        .oneshot(delete_req("/admin/v1/realms/acme/agents/bot-1"))
        .await
        .unwrap();
    assert_no_content(resp).await;
}

#[tokio::test]
async fn revoke_unknown_agent_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(delete_req("/admin/v1/realms/acme/agents/nope"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}

#[tokio::test]
async fn agent_on_unknown_realm_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/nope/agents"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}
