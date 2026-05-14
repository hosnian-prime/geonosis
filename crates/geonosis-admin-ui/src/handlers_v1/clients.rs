//! `/admin/v1/realms/:slug/clients` — OIDC / SAML client CRUD.
//!
//! Replaces the legacy list-only `handlers::api_clients_list`. The CLI
//! and admin UI both consume this single surface; audit emission +
//! bearer auth go through one place.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;

use geonosis_core::id::ClientId;
use geonosis_core::{
    AccessTokenType, Client, ClientAuthMethod, ClientKind, ConsentPolicy, FlowBinding, GrantPolicy,
    RedirectUri,
};

use crate::handlers_v1::extractors::realm_by_slug;
use crate::state::{AdminError, AdminState};

#[derive(Debug, Deserialize)]
pub struct CreateClientRequest {
    pub client_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub kind: ClientKind,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub auth_method: Option<ClientAuthMethod>,
    #[serde(default)]
    pub grants: Option<GrantPolicy>,
    #[serde(default)]
    pub default_scopes: Vec<geonosis_core::ScopeName>,
    #[serde(default)]
    pub optional_scopes: Vec<geonosis_core::ScopeName>,
}

pub async fn list(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Json<Vec<Client>>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    state
        .storage
        .list_clients(realm.id)
        .await
        .map(Json)
        .map_err(AdminError::from)
}

pub async fn create(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Json(req): Json<CreateClientRequest>,
) -> Result<Json<Client>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let now = chrono::Utc::now();
    let kind = req.kind;
    let client = Client {
        id: ClientId::new(),
        realm_id: realm.id,
        client_id: req.client_id,
        display_name: req.display_name,
        kind,
        // GrantPolicy defaults track the kind: public app gets
        // authorization_code only, confidential adds client_credentials,
        // service-account drops authorization_code. Callers may
        // override via the request.
        grants: req.grants.unwrap_or_else(|| match kind {
            ClientKind::Public | ClientKind::SamlServiceProvider => GrantPolicy::public_app(),
            ClientKind::Confidential | ClientKind::ScimClient => GrantPolicy::web_app(),
            ClientKind::BearerOnly => GrantPolicy::default(),
            ClientKind::ServiceAccount => GrantPolicy::service_account(),
        }),
        auth_method: req.auth_method.unwrap_or(match kind {
            ClientKind::Public | ClientKind::SamlServiceProvider | ClientKind::BearerOnly => {
                ClientAuthMethod::None
            }
            ClientKind::Confidential
            | ClientKind::ServiceAccount
            | ClientKind::ScimClient => ClientAuthMethod::ClientSecretBasic,
        }),
        flow_binding: FlowBinding::default(),
        default_scopes: req.default_scopes,
        optional_scopes: req.optional_scopes,
        redirect_uris: req
            .redirect_uris
            .into_iter()
            .map(|uri| RedirectUri {
                uri,
                wildcard_path: false,
            })
            .collect(),
        post_logout_redirect_uris: vec![],
        web_origins: vec![],
        access_token_type: AccessTokenType::Jwt,
        consent: ConsentPolicy::default(),
        access_token_lifespan: None,
        refresh_token_lifespan: None,
        access_token_signing_alg: None,
        front_channel_logout_enabled: false,
        backchannel_logout_url: None,
        client_authentication_keys: vec![],
        pairwise_sub_algorithm: None,
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    state
        .storage
        .create_client(client.clone())
        .await
        .map_err(AdminError::from)?;
    Ok(Json(client))
}

pub async fn get(
    State(state): State<Arc<AdminState>>,
    Path((slug, client_id)): Path<(String, String)>,
) -> Result<Json<Client>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    state
        .storage
        .get_client_by_client_id(realm.id, &client_id)
        .await
        .map(Json)
        .map_err(AdminError::from)
}

pub async fn update(
    State(state): State<Arc<AdminState>>,
    Path((slug, client_id)): Path<(String, String)>,
    Json(mut client): Json<Client>,
) -> Result<Json<Client>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let existing = state
        .storage
        .get_client_by_client_id(realm.id, &client_id)
        .await
        .map_err(AdminError::from)?;
    // Identity + creation timestamp stay canonical; the `client_id`
    // string itself is immutable (rotating it would break every
    // existing OAuth registration). Caller mutates everything else.
    client.id = existing.id;
    client.realm_id = realm.id;
    client.client_id = existing.client_id;
    client.created_at = existing.created_at;
    client.updated_at = chrono::Utc::now();
    state
        .storage
        .update_client(client.clone())
        .await
        .map_err(AdminError::from)?;
    Ok(Json(client))
}

pub async fn delete_(
    State(state): State<Arc<AdminState>>,
    Path((slug, client_id)): Path<(String, String)>,
) -> Result<axum::http::StatusCode, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let existing = state
        .storage
        .get_client_by_client_id(realm.id, &client_id)
        .await
        .map_err(AdminError::from)?;
    state
        .storage
        .delete_client(realm.id, existing.id)
        .await
        .map_err(AdminError::from)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
