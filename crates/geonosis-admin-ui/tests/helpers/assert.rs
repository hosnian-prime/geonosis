use axum::http::StatusCode;
use axum::response::Response;

/// Read the response body as JSON.
pub async fn read_json(resp: Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// Assert the response has the expected status code.
pub async fn assert_status(resp: Response, expected: StatusCode) {
    assert_eq!(
        resp.status(),
        expected,
        "expected {expected} but got {}",
        resp.status()
    );
}

/// Assert the response is 200 OK and return the parsed JSON body.
pub async fn assert_ok_json(resp: Response) -> serde_json::Value {
    assert_eq!(resp.status(), StatusCode::OK, "expected 200 OK");
    read_json(resp).await
}

/// Assert the response is 404 Not Found.
pub async fn assert_not_found(resp: Response) {
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "expected 404");
}

/// Assert the response is 204 No Content.
pub async fn assert_no_content(resp: Response) {
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "expected 204");
}

/// Assert the response is 400 Bad Request and return the parsed JSON body.
pub async fn assert_bad_request(resp: Response) -> serde_json::Value {
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "expected 400");
    read_json(resp).await
}
