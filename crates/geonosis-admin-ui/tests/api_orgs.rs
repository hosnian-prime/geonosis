mod helpers;

use tower::ServiceExt;

use helpers::assert::*;
use helpers::request::*;
use helpers::state::{fixture_state, seed_user, test_router};

fn org_body() -> serde_json::Value {
    serde_json::json!({
        "alias": "acme-org",
        "display_name": "Acme Organization"
    })
}

// ---- Organization CRUD ----

#[tokio::test]
async fn list_orgs_empty() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/orgs"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn create_org() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(post_json("/admin/v1/realms/acme/orgs", org_body()))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["alias"], "acme-org");
    assert_eq!(json["display_name"], "Acme Organization");
    assert_eq!(json["enabled"], true);
}

#[tokio::test]
async fn get_org() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());
    router
        .oneshot(post_json("/admin/v1/realms/acme/orgs", org_body()))
        .await
        .unwrap();

    let router2 = test_router(state);
    let resp = router2
        .oneshot(get("/admin/v1/realms/acme/orgs/acme-org"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["alias"], "acme-org");
}

#[tokio::test]
async fn get_unknown_org_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/orgs/nope"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}

#[tokio::test]
async fn update_org() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());
    let resp = router
        .oneshot(post_json("/admin/v1/realms/acme/orgs", org_body()))
        .await
        .unwrap();
    let original = assert_ok_json(resp).await;
    let original_id = original["id"].as_str().unwrap().to_string();

    let mut updated = original.clone();
    updated["display_name"] = serde_json::json!("Updated Org");
    let router2 = test_router(state);
    let resp = router2
        .oneshot(put_json("/admin/v1/realms/acme/orgs/acme-org", updated))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["id"], original_id);
    assert_eq!(json["display_name"], "Updated Org");
}

#[tokio::test]
async fn delete_org() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());
    router
        .oneshot(post_json("/admin/v1/realms/acme/orgs", org_body()))
        .await
        .unwrap();

    let router2 = test_router(state.clone());
    let resp = router2
        .oneshot(delete_req("/admin/v1/realms/acme/orgs/acme-org"))
        .await
        .unwrap();
    assert_no_content(resp).await;

    let router3 = test_router(state);
    let resp = router3
        .oneshot(get("/admin/v1/realms/acme/orgs/acme-org"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}

// ---- Domains ----

#[tokio::test]
async fn list_domains_empty() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());
    router
        .oneshot(post_json("/admin/v1/realms/acme/orgs", org_body()))
        .await
        .unwrap();

    let router2 = test_router(state);
    let resp = router2
        .oneshot(get("/admin/v1/realms/acme/orgs/acme-org/domains"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn add_domain_lowercases_and_returns_token() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());
    router
        .oneshot(post_json("/admin/v1/realms/acme/orgs", org_body()))
        .await
        .unwrap();

    let router2 = test_router(state);
    let resp = router2
        .oneshot(post_json(
            "/admin/v1/realms/acme/orgs/acme-org/domains",
            serde_json::json!({"domain": "ACME.COM"}),
        ))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["domain"], "acme.com", "domain should be lowercased");
    assert_eq!(json["verified"], false);
    assert!(json["verification_token"].is_string());
}

#[tokio::test]
async fn mark_domain_verified() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());
    router
        .oneshot(post_json("/admin/v1/realms/acme/orgs", org_body()))
        .await
        .unwrap();

    let router2 = test_router(state.clone());
    router2
        .oneshot(post_json(
            "/admin/v1/realms/acme/orgs/acme-org/domains",
            serde_json::json!({"domain": "acme.com"}),
        ))
        .await
        .unwrap();

    let router3 = test_router(state);
    let resp = router3
        .oneshot(post_json(
            "/admin/v1/realms/acme/orgs/acme-org/domains/acme.com/verify",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["verified"], true);
    assert!(json["verification_token"].is_null());
}

#[tokio::test]
async fn remove_domain() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());
    router
        .oneshot(post_json("/admin/v1/realms/acme/orgs", org_body()))
        .await
        .unwrap();

    let router2 = test_router(state.clone());
    router2
        .oneshot(post_json(
            "/admin/v1/realms/acme/orgs/acme-org/domains",
            serde_json::json!({"domain": "acme.com"}),
        ))
        .await
        .unwrap();

    let router3 = test_router(state.clone());
    let resp = router3
        .oneshot(delete_req(
            "/admin/v1/realms/acme/orgs/acme-org/domains/acme.com",
        ))
        .await
        .unwrap();
    assert_no_content(resp).await;

    // Verify the list is now empty
    let router4 = test_router(state);
    let resp = router4
        .oneshot(get("/admin/v1/realms/acme/orgs/acme-org/domains"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 0);
}

// ---- Memberships ----

#[tokio::test]
async fn list_memberships_empty() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());
    router
        .oneshot(post_json("/admin/v1/realms/acme/orgs", org_body()))
        .await
        .unwrap();

    let router2 = test_router(state);
    let resp = router2
        .oneshot(get("/admin/v1/realms/acme/orgs/acme-org/memberships"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn add_and_list_member() {
    let (state, realm_id) = fixture_state().await;
    let user = seed_user(&state, realm_id, "alice").await;

    let router = test_router(state.clone());
    router
        .oneshot(post_json("/admin/v1/realms/acme/orgs", org_body()))
        .await
        .unwrap();

    let router2 = test_router(state.clone());
    let resp = router2
        .oneshot(post_json(
            "/admin/v1/realms/acme/orgs/acme-org/memberships",
            serde_json::json!({"user_id": user.id.to_string()}),
        ))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["user_id"], user.id.to_string());

    let router3 = test_router(state);
    let resp = router3
        .oneshot(get("/admin/v1/realms/acme/orgs/acme-org/memberships"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn remove_member() {
    let (state, realm_id) = fixture_state().await;
    let user = seed_user(&state, realm_id, "alice").await;

    let router = test_router(state.clone());
    router
        .oneshot(post_json("/admin/v1/realms/acme/orgs", org_body()))
        .await
        .unwrap();

    let router2 = test_router(state.clone());
    router2
        .oneshot(post_json(
            "/admin/v1/realms/acme/orgs/acme-org/memberships",
            serde_json::json!({"user_id": user.id.to_string()}),
        ))
        .await
        .unwrap();

    let router3 = test_router(state.clone());
    let resp = router3
        .oneshot(delete_req(&format!(
            "/admin/v1/realms/acme/orgs/acme-org/memberships/{}",
            user.id
        )))
        .await
        .unwrap();
    assert_no_content(resp).await;
}

// ---- Invitations ----

#[tokio::test]
async fn create_and_list_invitation() {
    let (state, realm_id) = fixture_state().await;
    let inviter = seed_user(&state, realm_id, "admin").await;

    let router = test_router(state.clone());
    router
        .oneshot(post_json("/admin/v1/realms/acme/orgs", org_body()))
        .await
        .unwrap();

    let router2 = test_router(state.clone());
    let resp = router2
        .oneshot(post_json(
            "/admin/v1/realms/acme/orgs/acme-org/invitations",
            serde_json::json!({
                "email": "new@example.com",
                "invited_by": inviter.id.to_string()
            }),
        ))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["email"], "new@example.com");
    assert!(json["token"].is_string());

    let router3 = test_router(state);
    let resp = router3
        .oneshot(get("/admin/v1/realms/acme/orgs/acme-org/invitations"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn accept_invitation() {
    let (state, realm_id) = fixture_state().await;
    let inviter = seed_user(&state, realm_id, "admin").await;

    let router = test_router(state.clone());
    router
        .oneshot(post_json("/admin/v1/realms/acme/orgs", org_body()))
        .await
        .unwrap();

    let router2 = test_router(state.clone());
    let resp = router2
        .oneshot(post_json(
            "/admin/v1/realms/acme/orgs/acme-org/invitations",
            serde_json::json!({
                "email": "new@example.com",
                "invited_by": inviter.id.to_string()
            }),
        ))
        .await
        .unwrap();
    let inv = assert_ok_json(resp).await;
    let token = inv["token"].as_str().unwrap();

    let router3 = test_router(state);
    let resp = router3
        .oneshot(post_json(
            &format!("/admin/v1/realms/acme/orgs/acme-org/invitations/accept/{token}"),
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
}

// ---- Org roles ----

#[tokio::test]
async fn create_org_role() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());
    router
        .oneshot(post_json("/admin/v1/realms/acme/orgs", org_body()))
        .await
        .unwrap();

    let router2 = test_router(state);
    let resp = router2
        .oneshot(post_json(
            "/admin/v1/realms/acme/orgs/acme-org/roles",
            serde_json::json!({
                "name": "org-admin",
                "description": "Organization admin"
            }),
        ))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["name"], "org-admin");
    assert_eq!(json["built_in"], false);
}

// ---- Consent policies ----

#[tokio::test]
async fn upsert_and_list_consent_policy() {
    let (state, realm_id) = fixture_state().await;
    let user = seed_user(&state, realm_id, "admin").await;

    let router = test_router(state.clone());
    router
        .oneshot(post_json("/admin/v1/realms/acme/orgs", org_body()))
        .await
        .unwrap();

    // Create a client to reference
    let router2 = test_router(state.clone());
    let resp = router2
        .oneshot(post_json(
            "/admin/v1/realms/acme/clients",
            serde_json::json!({
                "client_id": "my-app",
                "kind": "public",
                "redirect_uris": ["https://app.example/cb"]
            }),
        ))
        .await
        .unwrap();
    let client = assert_ok_json(resp).await;
    let client_internal_id = client["id"].as_str().unwrap();

    let router3 = test_router(state.clone());
    let resp = router3
        .oneshot(post_json(
            "/admin/v1/realms/acme/orgs/acme-org/consent-policies",
            serde_json::json!({
                "client_id": client_internal_id,
                "mode": "org-pre-approved",
                "created_by": user.id.to_string()
            }),
        ))
        .await
        .unwrap();
    assert_ok_json(resp).await;

    let router4 = test_router(state);
    let resp = router4
        .oneshot(get("/admin/v1/realms/acme/orgs/acme-org/consent-policies"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 1);
}

// ---- IdP bindings ----

#[tokio::test]
async fn upsert_and_list_idp_binding() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());
    router
        .oneshot(post_json("/admin/v1/realms/acme/orgs", org_body()))
        .await
        .unwrap();

    let router2 = test_router(state.clone());
    let resp = router2
        .oneshot(post_json(
            "/admin/v1/realms/acme/orgs/acme-org/idps",
            serde_json::json!({
                "idp_alias": "google",
                "priority": 1
            }),
        ))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["idp_alias"], "google");

    let router3 = test_router(state);
    let resp = router3
        .oneshot(get("/admin/v1/realms/acme/orgs/acme-org/idps"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn remove_idp_binding() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());
    router
        .oneshot(post_json("/admin/v1/realms/acme/orgs", org_body()))
        .await
        .unwrap();

    let router2 = test_router(state.clone());
    router2
        .oneshot(post_json(
            "/admin/v1/realms/acme/orgs/acme-org/idps",
            serde_json::json!({"idp_alias": "google", "priority": 1}),
        ))
        .await
        .unwrap();

    let router3 = test_router(state.clone());
    let resp = router3
        .oneshot(delete_req(
            "/admin/v1/realms/acme/orgs/acme-org/idps/google",
        ))
        .await
        .unwrap();
    assert_no_content(resp).await;

    let router4 = test_router(state);
    let resp = router4
        .oneshot(get("/admin/v1/realms/acme/orgs/acme-org/idps"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn org_on_unknown_realm_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/nope/orgs"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}
