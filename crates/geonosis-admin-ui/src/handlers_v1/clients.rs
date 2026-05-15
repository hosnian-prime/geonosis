//! `/admin/v1/realms/:slug/clients` — OIDC / SAML client CRUD.
//!
//! Replaces the legacy list-only `handlers::api_clients_list`. The CLI
//! and admin UI both consume this single surface; audit emission +
//! bearer auth go through one place.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;

use geonosis_audit::Target;
use serde::Serialize;

use geonosis_core::id::ClientId;
use geonosis_core::{
    AccessTokenType, Client, ClientAuthMethod, ClientKind, ConsentPolicy, FlowBinding, GrantPolicy,
    RedirectUri, RedirectUriError,
};

use crate::audit_emit;

use crate::handlers_v1::extractors::realm_by_slug;
use crate::state::{AdminError, AdminState};

/// Response for client creation. Wraps the full `Client` and includes
/// the one-time `client_secret` for confidential / service-account
/// clients. The plaintext secret is **never** persisted — only the
/// BLAKE3-keyed hash is stored. Callers must capture this value on
/// creation; it cannot be retrieved later.
#[derive(Serialize)]
pub struct CreateClientResponse {
    #[serde(flatten)]
    pub client: Client,
    /// One-time plaintext secret. `None` for public / bearer-only clients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

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
    /// Optional SAML 2.0 SP config — required when
    /// `kind = SamlServiceProvider` if the SP is to participate in
    /// the SAML SSO endpoints. Validated against
    /// `geonosis_protocol_saml_idp::SamlSpClientConfig` schema on
    /// the way in (round-trip parse-then-serialise) so a bad blob
    /// fails fast with a 400.
    #[serde(default)]
    pub saml_sp_config: Option<serde_json::Value>,
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
) -> Result<Json<CreateClientResponse>, AdminError> {
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
            ClientKind::Confidential | ClientKind::ServiceAccount | ClientKind::ScimClient => {
                ClientAuthMethod::ClientSecretBasic
            }
        }),
        flow_binding: FlowBinding::default(),
        default_scopes: req.default_scopes,
        optional_scopes: req.optional_scopes,
        redirect_uris: validate_redirect_uris(req.redirect_uris)?,
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
        saml_sp_config: validate_saml_sp_config(&kind, req.saml_sp_config)?,
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    state
        .storage
        .create_client(client.clone())
        .await
        .map_err(AdminError::from)?;

    // Auto-generate a client_secret for confidential-like clients.
    // The plaintext is returned once; only the BLAKE3-keyed hash is
    // persisted. Matches Keycloak's create-client behaviour.
    let client_secret = match kind {
        ClientKind::Confidential | ClientKind::ServiceAccount | ClientKind::ScimClient => {
            let secret = geonosis_crypto::random::random_token();
            let hash = hex::encode(geonosis_crypto::hash::token_hash(
                &state.client_secret_hash_key,
                secret.as_bytes(),
            ));
            state
                .storage
                .store_client_secret_hash(realm.id, client.id, hash)
                .await
                .map_err(AdminError::from)?;
            Some(secret)
        }
        _ => None,
    };

    audit_emit::emit(
        &state,
        client.realm_id,
        "client.created",
        Some(Target::Client { id: client.id }),
        serde_json::json!({ "client_id": client.client_id, "kind": format!("{:?}", client.kind) }),
    );
    Ok(Json(CreateClientResponse {
        client,
        client_secret,
    }))
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
    audit_emit::emit(
        &state,
        client.realm_id,
        "client.updated",
        Some(Target::Client { id: client.id }),
        serde_json::json!({ "client_id": client.client_id }),
    );
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
    audit_emit::emit(
        &state,
        realm.id,
        "client.deleted",
        Some(Target::Client { id: existing.id }),
        serde_json::json!({ "client_id": existing.client_id }),
    );
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Per `docs/03-protocols-oidc.md` §"Conformance defaults": registered
/// redirect URIs must use https://, except for loopback hosts and
/// reverse-DNS native-app callback schemes. Rejecting non-loopback
/// http:// at registration time is the v0.1 contract gate; runtime
/// match in `authorize.rs` is exact-string but doesn't enforce scheme
/// (the registered list is trusted by then). Returns 400 with a
/// per-URI error so the admin sees which entry was wrong.
fn validate_redirect_uris(uris: Vec<String>) -> Result<Vec<RedirectUri>, AdminError> {
    uris.into_iter()
        .map(|uri| {
            RedirectUri::validate_scheme(&uri).map_err(|e| match e {
                RedirectUriError::HttpRequiresLoopback { ref host } => AdminError::InvalidInput(
                    format!("redirect_uri `{uri}`: http:// only allowed for loopback (got `{host}`); use https://"),
                ),
                RedirectUriError::UnsupportedScheme(_) | RedirectUriError::Unparseable(_) => {
                    AdminError::InvalidInput(format!("redirect_uri `{uri}`: {e}"))
                }
            })?;
            Ok(RedirectUri {
                uri,
                wildcard_path: false,
            })
        })
        .collect()
}

/// Round-trip the operator-supplied SAML config through the typed
/// schema to validate it. `None` is always accepted (an OIDC client
/// has no SAML config). When `Some` is supplied with a non-SAML
/// client kind we reject — config must match kind.
fn validate_saml_sp_config(
    kind: &ClientKind,
    raw: Option<serde_json::Value>,
) -> Result<Option<serde_json::Value>, AdminError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if !matches!(kind, ClientKind::SamlServiceProvider) {
        return Err(AdminError::Storage(
            "saml_sp_config supplied for a non-SAML client kind".into(),
        ));
    }
    // Parse the typed form to surface schema errors immediately, then
    // re-serialise so the persisted blob is the canonical layout.
    let typed = geonosis_protocol_saml_idp::SamlSpClientConfig::try_from_value(&raw)
        .map_err(|e| AdminError::Storage(format!("invalid saml_sp_config: {e}")))?;
    Ok(Some(typed.to_value()))
}
