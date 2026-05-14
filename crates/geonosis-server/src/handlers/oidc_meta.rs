//! OIDC metadata endpoints: discovery + JWKS.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use url::Url;

use geonosis_protocol_oidc::{discovery_document, DiscoveryDocument};

use crate::state::AppState;

pub async fn openid_configuration(
    Path(slug): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<DiscoveryDocument>, (StatusCode, String)> {
    let realm = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "realm not found".into()))?;
    let issuer = realm_issuer_url(&state.public_base_url, &realm.slug);
    Ok(Json(discovery_document(issuer)))
}

pub async fn jwks(
    Path(slug): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<geonosis_crypto::JwkSet>, (StatusCode, String)> {
    let realm = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "realm not found".into()))?;
    let set = geonosis_crypto::KeyManagementService::jwks(&*state.kms, realm.id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(set))
}

pub fn realm_issuer_url(base: &Url, slug: &str) -> Url {
    let mut u = base.clone();
    u.set_path(&format!("/realms/{slug}"));
    u
}
