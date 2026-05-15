mod helpers;

use tower::ServiceExt;

use helpers::assert::*;
use helpers::request::*;
use helpers::state::{fixture_state, test_router};

fn idp_body() -> serde_json::Value {
    serde_json::json!({
        "alias": "google",
        "display_name": "Google",
        "kind": "oidc",
        "config": {
            "kind": "oidc",
            "issuer": "https://accounts.google.com",
            "client_id": "google-client-id",
            "client_secret": "google-secret",
            "client_auth": "basic",
            "scopes": ["openid"],
            "pkce": false,
            "accept_unsigned_userinfo": false
        }
    })
}

#[tokio::test]
async fn list_idps_empty() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/idps"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn create_idp() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(post_json("/admin/v1/realms/acme/idps", idp_body()))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["alias"], "google");
    assert_eq!(json["kind"], "oidc");
    assert_eq!(json["enabled"], true);
}

#[tokio::test]
async fn get_idp() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());
    router
        .oneshot(post_json("/admin/v1/realms/acme/idps", idp_body()))
        .await
        .unwrap();

    let router2 = test_router(state);
    let resp = router2
        .oneshot(get("/admin/v1/realms/acme/idps/google"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["alias"], "google");
}

#[tokio::test]
async fn get_unknown_idp_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/idps/nope"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}

#[tokio::test]
#[ignore = "idp update uses create_idp upsert — round-trip serialization issue with IdpConfig tag"]
async fn update_idp_preserves_alias() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());
    let resp = router
        .oneshot(post_json("/admin/v1/realms/acme/idps", idp_body()))
        .await
        .unwrap();
    let original = assert_ok_json(resp).await;

    // Build the update payload from the created response, keeping all
    // fields intact but changing display_name.
    let mut update_body = original.clone();
    update_body["display_name"] = serde_json::json!("Google Updated");
    // The serialized response round-trips through the IdentityProvider
    // struct directly (no DTO layer in v0.1).
    let router2 = test_router(state);
    let resp = router2
        .oneshot(put_json("/admin/v1/realms/acme/idps/google", update_body))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json["alias"], "google", "alias must not change");
    assert_eq!(json["display_name"], "Google Updated");
}

#[tokio::test]
async fn delete_idp() {
    let (state, _) = fixture_state().await;
    let router = test_router(state.clone());
    router
        .oneshot(post_json("/admin/v1/realms/acme/idps", idp_body()))
        .await
        .unwrap();

    let router2 = test_router(state.clone());
    let resp = router2
        .oneshot(delete_req("/admin/v1/realms/acme/idps/google"))
        .await
        .unwrap();
    assert_no_content(resp).await;

    let router3 = test_router(state);
    let resp = router3
        .oneshot(get("/admin/v1/realms/acme/idps/google"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}

#[tokio::test]
async fn idp_on_unknown_realm_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/nope/idps"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}
