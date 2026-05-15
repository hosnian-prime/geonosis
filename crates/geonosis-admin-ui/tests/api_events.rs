mod helpers;

use tower::ServiceExt;

use helpers::assert::*;
use helpers::request::*;
use helpers::state::{fixture_state, test_router};

#[tokio::test]
async fn list_events_empty() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/acme/events"))
        .await
        .unwrap();
    let json = assert_ok_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn events_on_unknown_realm_404() {
    let (state, _) = fixture_state().await;
    let router = test_router(state);
    let resp = router
        .oneshot(get("/admin/v1/realms/nope/events"))
        .await
        .unwrap();
    assert_not_found(resp).await;
}
