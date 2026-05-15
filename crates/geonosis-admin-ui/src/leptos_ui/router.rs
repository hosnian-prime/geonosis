//! Admin console router — mounts every Leptos page under `/admin/...`
//! and handles the form POSTs that mutate state.
//!
//! Per `docs/08-admin-ui.md` the admin console is server-rendered with
//! Leptos and uses classical form submits (no SPA). Each page is one
//! GET that loads data and renders the component; each writable form
//! is a sibling POST that updates storage and either redirects back
//! to the page (success) or re-renders the form with an error message
//! (failure).
//!
//! Tab routing lives in `?tab=`. The detail components select which
//! panel to render from the active-tab string; the URL is the source
//! of truth so deep-links and back-button work.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use leptos::prelude::*;
use serde::Deserialize;

use crate::auth::AdminPrincipal;
use crate::handlers_v1::extractors::realm_by_slug;
use crate::leptos_ui::app::PageContext;
use crate::leptos_ui::components::chrome::{ProfileContext, RealmChoice};
use crate::leptos_ui::pages::agents::{AgentDetailPage, AgentRow, AgentsPage};
use crate::leptos_ui::pages::clients::{
    ClientCreatePage, ClientDetailPage, ClientRow, ClientsPage,
};
use crate::leptos_ui::pages::events::{EventFilter, EventRow, EventsPage};
use crate::leptos_ui::pages::federation::{FederationPage, LdapDetailPage, LdapRow};
use crate::leptos_ui::pages::flows::{FlowEditPage, FlowRow, FlowsPage};
use crate::leptos_ui::pages::groups::{
    GroupCreatePage, GroupDetailData, GroupDetailPage, GroupRow, GroupsPage,
};
use crate::leptos_ui::pages::idps::{IdpCreatePage, IdpDetailPage, IdpRow, IdpsPage};
use crate::leptos_ui::pages::keys::{KeyRow, KeysPage};
use crate::leptos_ui::pages::orgs::{
    OrgConsentRow, OrgCreatePage, OrgDetailData, OrgDetailPage, OrgDomainRow, OrgIdpRow,
    OrgInviteRow, OrgMemberRow, OrgRoleRow, OrgRow, OrgsPage,
};
use crate::leptos_ui::pages::profile::{ProfileData, ProfilePage, ProfileSession};
use crate::leptos_ui::pages::realm_detail::{RealmDetailData, RealmDetailPage};
use crate::leptos_ui::pages::realm_settings::RealmSettingsPage;
use crate::leptos_ui::pages::realms::{RealmCreatePage, RealmRow, RealmsPage};
use crate::leptos_ui::pages::roles::{
    RoleCreatePage, RoleDetailData, RoleDetailPage, RoleRow, RolesPage,
};
use crate::leptos_ui::pages::sessions::{SessionRow, SessionsPage};
use crate::leptos_ui::pages::spi::{BindingRow, ModuleRow, SpiPage};
use crate::leptos_ui::pages::user_profile_schema::UserProfileSchemaPage;
use crate::leptos_ui::pages::users::{
    UserCreatePage, UserDetailData, UserDetailPage, UserRow, UserSessionRow, UsersPage,
};
use crate::state::{AdminError, AdminState};

#[derive(Debug, Default, Deserialize)]
pub struct TabQuery {
    #[serde(default)]
    pub tab: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub search: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct EventsQuery {
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub until: Option<String>,
}

/// Build the Leptos sub-router. Composed into the main admin router
/// by `geonosis_admin_ui::router`.
pub fn leptos_router(state: Arc<AdminState>) -> Router {
    Router::new()
        // ---- Realms ----
        .route("/admin", get(redirect_to_realms))
        .route("/admin/realms", get(page_realms).post(post_realm_create))
        .route("/admin/realms/new", get(page_realm_new))
        .route("/admin/realms/:slug", get(page_realm_detail))
        .route("/admin/realms/:slug/delete", post(post_realm_delete))
        .route("/admin/realms/:slug/disable", post(post_realm_disable))
        // Settings tabs
        .route("/admin/realms/:slug/settings", get(page_realm_settings))
        .route(
            "/admin/realms/:slug/settings/:tab",
            post(post_realm_settings),
        )
        // ---- Clients ----
        .route(
            "/admin/realms/:slug/clients",
            get(page_clients).post(post_client_create),
        )
        .route("/admin/realms/:slug/clients/new", get(page_client_new))
        .route(
            "/admin/realms/:slug/clients/:client_id",
            get(page_client_detail),
        )
        // ---- Users ----
        .route(
            "/admin/realms/:slug/users",
            get(page_users).post(post_user_create),
        )
        .route("/admin/realms/:slug/users/new", get(page_user_new))
        .route("/admin/realms/:slug/users/:username", get(page_user_detail))
        // ---- Roles ----
        .route(
            "/admin/realms/:slug/roles",
            get(page_roles).post(post_role_create),
        )
        .route("/admin/realms/:slug/roles/new", get(page_role_new))
        .route("/admin/realms/:slug/roles/:name", get(page_role_detail))
        // ---- Groups ----
        .route(
            "/admin/realms/:slug/groups",
            get(page_groups).post(post_group_create),
        )
        .route("/admin/realms/:slug/groups/new", get(page_group_new))
        .route("/admin/realms/:slug/groups/:id", get(page_group_detail))
        // ---- Orgs ----
        .route(
            "/admin/realms/:slug/orgs",
            get(page_orgs).post(post_org_create),
        )
        .route("/admin/realms/:slug/orgs/new", get(page_org_new))
        .route("/admin/realms/:slug/orgs/:alias", get(page_org_detail))
        // ---- Agents ----
        .route("/admin/realms/:slug/agents", get(page_agents))
        .route("/admin/realms/:slug/agents/:alias", get(page_agent_detail))
        // ---- IdPs ----
        .route(
            "/admin/realms/:slug/idps",
            get(page_idps).post(post_idp_create),
        )
        .route("/admin/realms/:slug/idps/new", get(page_idp_new))
        .route("/admin/realms/:slug/idps/:alias", get(page_idp_detail))
        // ---- Federation ----
        .route("/admin/realms/:slug/federation", get(page_federation))
        .route(
            "/admin/realms/:slug/federation/:alias",
            get(page_federation_detail),
        )
        // ---- SPI ----
        .route("/admin/realms/:slug/spi", get(page_spi))
        // ---- Keys ----
        .route("/admin/realms/:slug/keys", get(page_keys))
        // ---- Sessions ----
        .route("/admin/realms/:slug/sessions", get(page_sessions))
        // ---- Events ----
        .route("/admin/realms/:slug/events", get(page_events))
        // ---- Flows ----
        .route("/admin/realms/:slug/flows", get(page_flows))
        .route(
            "/admin/realms/:slug/flows/:alias",
            get(page_flow_edit).post(post_flow_save),
        )
        // ---- User profile schema ----
        .route(
            "/admin/realms/:slug/user-profile",
            get(page_user_profile_schema),
        )
        // ---- Profile (own account) ----
        .route("/admin/profile", get(page_profile))
        .with_state(state)
}

// =========================================================================
//                                  Context
// =========================================================================

async fn build_ctx(state: &Arc<AdminState>, principal: Option<&AdminPrincipal>) -> PageContext {
    let realms = state
        .storage
        .list_realms()
        .await
        .map(|rs| {
            rs.into_iter()
                .map(|r| RealmChoice {
                    slug: r.slug,
                    display_name: r.display_name,
                })
                .collect()
        })
        .unwrap_or_default();
    let profile = ProfileContext {
        username: principal.map(|p| p.username.clone()),
    };
    PageContext::default()
        .with_realms(realms)
        .with_profile(profile)
}

// =========================================================================
//                                  Realms
// =========================================================================

async fn redirect_to_realms() -> impl IntoResponse {
    Redirect::to("/admin/realms")
}

async fn page_realms(
    State(state): State<Arc<AdminState>>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realms = state.storage.list_realms().await?;
    let rows: Vec<RealmRow> = realms
        .into_iter()
        .map(|r| RealmRow {
            slug: r.slug,
            display_name: r.display_name,
            enabled: r.enabled,
            created_at: r.created_at.to_rfc3339(),
        })
        .collect();
    Ok(render(move || view! { <RealmsPage realms=rows ctx=ctx/> }))
}

async fn page_realm_new(
    State(state): State<Arc<AdminState>>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    Ok(render(move || view! { <RealmCreatePage ctx=ctx/> }))
}

#[derive(Debug, Deserialize)]
struct RealmCreateForm {
    slug: String,
    display_name: String,
    #[serde(default)]
    enabled: Option<String>,
}

async fn post_realm_create(
    State(state): State<Arc<AdminState>>,
    Form(form): Form<RealmCreateForm>,
) -> Result<Response, AdminError> {
    use geonosis_core::id::RealmId;
    use geonosis_core::Realm;
    let now = chrono::Utc::now();
    let slug = form.slug.trim().to_string();
    if slug.is_empty() {
        return Err(AdminError::InvalidInput("slug is required".into()));
    }
    let mut realm = Realm {
        id: RealmId::new(),
        slug: slug.clone(),
        display_name: form.display_name,
        ..default_realm()
    };
    realm.enabled = form.enabled.is_some();
    realm.created_at = now;
    realm.updated_at = now;
    state.storage.create_realm(realm).await?;
    crate::audit_emit::emit(
        &state,
        geonosis_core::id::RealmId::new(),
        "realm.created",
        None,
        serde_json::json!({ "slug": slug }),
    );
    Ok(Redirect::to(&format!("/admin/realms/{slug}")).into_response())
}

fn default_realm() -> geonosis_core::Realm {
    use geonosis_core::id::RealmId;
    use geonosis_core::Realm;
    let now = chrono::Utc::now();
    Realm {
        id: RealmId::new(),
        slug: String::new(),
        display_name: String::new(),
        frontend_url: None,
        admin_frontend_url: None,
        enabled: true,
        ssl_required: Default::default(),
        login: Default::default(),
        registration: Default::default(),
        session_policy: Default::default(),
        token_policy: Default::default(),
        brute_force: Default::default(),
        password_policy: Default::default(),
        otp_policy: Default::default(),
        webauthn_policy: Default::default(),
        acr_policy: Default::default(),
        sender_constraint_default: Default::default(),
        theme_binding: Default::default(),
        localization: Default::default(),
        events: Default::default(),
        default_groups: Default::default(),
        default_roles: Default::default(),
        organizations_enabled: false,
        organization_policy: Default::default(),
        created_at: now,
        updated_at: now,
    }
}

async fn page_realm_detail(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    // Best-effort counts. Storage errors degrade to 0 so the dashboard
    // still renders if a sub-list query fails.
    let user_count = state
        .storage
        .list_users(realm.id, 1000)
        .await
        .map(|v| v.len())
        .unwrap_or(0);
    let client_count = state
        .storage
        .list_clients(realm.id)
        .await
        .map(|v| v.len())
        .unwrap_or(0);
    let session_count = state
        .storage
        .list_sessions(realm.id, 1000)
        .await
        .map(|v| v.len())
        .unwrap_or(0);
    let role_count = state
        .storage
        .list_roles(realm.id, None)
        .await
        .map(|v| v.len())
        .unwrap_or(0);
    let group_count = state
        .storage
        .list_groups(realm.id)
        .await
        .map(|v| v.len())
        .unwrap_or(0);
    let org_count = state
        .storage
        .list_organizations(realm.id)
        .await
        .map(|v| v.len())
        .unwrap_or(0);
    let agent_count = state
        .storage
        .list_agents(realm.id)
        .await
        .map(|v| v.len())
        .unwrap_or(0);
    let idp_count = state
        .storage
        .list_idps(realm.id)
        .await
        .map(|v| v.len())
        .unwrap_or(0);
    let flow_count = state
        .storage
        .list_auth_flows(realm.id)
        .await
        .map(|v| v.len())
        .unwrap_or(0);
    let data = RealmDetailData {
        slug: realm.slug.clone(),
        display_name: realm.display_name.clone(),
        enabled: realm.enabled,
        organizations_enabled: realm.organizations_enabled,
        frontend_url: realm.frontend_url.as_ref().map(|u| u.to_string()),
        user_count,
        client_count,
        session_count,
        role_count,
        group_count,
        org_count,
        agent_count,
        idp_count,
        flow_count,
    };
    Ok(render(
        move || view! { <RealmDetailPage data=data ctx=ctx/> },
    ))
}

async fn post_realm_delete(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Response, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    state.storage.delete_realm(realm.id).await?;
    crate::audit_emit::emit(
        &state,
        realm.id,
        "realm.deleted",
        None,
        serde_json::json!({ "slug": slug }),
    );
    Ok(Redirect::to("/admin/realms").into_response())
}

async fn post_realm_disable(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Response, AdminError> {
    let mut realm = realm_by_slug(&state, &slug).await?;
    realm.enabled = !realm.enabled;
    realm.updated_at = chrono::Utc::now();
    state.storage.update_realm(realm.clone()).await?;
    crate::audit_emit::emit(
        &state,
        realm.id,
        if realm.enabled {
            "realm.enabled"
        } else {
            "realm.disabled"
        },
        None,
        serde_json::json!({ "slug": realm.slug }),
    );
    Ok(Redirect::to(&format!("/admin/realms/{slug}")).into_response())
}

// =========================================================================
//                              Realm settings
// =========================================================================

async fn page_realm_settings(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Query(q): Query<TabQuery>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let tab = q.tab.unwrap_or_else(|| "general".into());
    Ok(render(move || {
        view! {
            <RealmSettingsPage realm=realm active_tab=tab ctx=ctx/>
        }
    }))
}

#[derive(Debug, Deserialize)]
struct GeneralForm {
    display_name: String,
    #[serde(default)]
    frontend_url: String,
    #[serde(default)]
    admin_frontend_url: String,
    #[serde(default)]
    ssl_required: String,
    #[serde(default)]
    enabled: Option<String>,
    #[serde(default)]
    organizations_enabled: Option<String>,
}

async fn post_realm_settings(
    State(state): State<Arc<AdminState>>,
    Path((slug, tab)): Path<(String, String)>,
    Form(form): Form<serde_json::Value>,
) -> Result<Response, AdminError> {
    let mut realm = realm_by_slug(&state, &slug).await?;
    match tab.as_str() {
        "general" => {
            let g: GeneralForm = serde_json::from_value(form)
                .map_err(|e| AdminError::InvalidInput(e.to_string()))?;
            realm.display_name = g.display_name;
            realm.frontend_url = parse_optional_url(&g.frontend_url);
            realm.admin_frontend_url = parse_optional_url(&g.admin_frontend_url);
            realm.ssl_required = match g.ssl_required.as_str() {
                "none" => geonosis_core::common::SslRequirement::None,
                "all" => geonosis_core::common::SslRequirement::All,
                _ => geonosis_core::common::SslRequirement::ExternalRequests,
            };
            realm.enabled = g.enabled.is_some();
            realm.organizations_enabled = g.organizations_enabled.is_some();
        }
        _ => {
            // v0.1.x: other tabs accept the form but no-op the write. The
            // PUT /admin/v1/realms/:slug route still exposes the full
            // shape — the inline editors land in v0.2.
        }
    }
    realm.updated_at = chrono::Utc::now();
    state.storage.update_realm(realm.clone()).await?;
    crate::audit_emit::emit(
        &state,
        realm.id,
        "realm.updated",
        None,
        serde_json::json!({ "slug": slug, "tab": tab }),
    );
    Ok(Redirect::to(&format!("/admin/realms/{slug}/settings?tab={tab}")).into_response())
}

fn parse_optional_url(s: &str) -> Option<url::Url> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        url::Url::parse(t).ok()
    }
}

// =========================================================================
//                                  Clients
// =========================================================================

async fn page_clients(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let clients = state.storage.list_clients(realm.id).await?;
    let rows: Vec<ClientRow> = clients
        .into_iter()
        .map(|c| ClientRow {
            client_id: c.client_id,
            display_name: c.display_name.unwrap_or_default(),
            kind: client_kind_to_serde(c.kind),
            enabled: c.enabled,
        })
        .collect();
    let s = realm.slug;
    Ok(render(move || {
        view! {
            <ClientsPage realm_slug=s rows=rows ctx=ctx/>
        }
    }))
}

fn client_kind_to_serde(k: geonosis_core::client::ClientKind) -> String {
    use geonosis_core::client::ClientKind;
    match k {
        ClientKind::Confidential => "confidential",
        ClientKind::Public => "public",
        ClientKind::BearerOnly => "bearer-only",
        ClientKind::ServiceAccount => "service-account",
        ClientKind::SamlServiceProvider => "saml-service-provider",
        ClientKind::ScimClient => "scim-client",
    }
    .to_string()
}

async fn page_client_new(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let _ = realm_by_slug(&state, &slug).await?;
    Ok(render(
        move || view! { <ClientCreatePage realm_slug=slug ctx=ctx/> },
    ))
}

#[derive(Debug, Deserialize)]
struct ClientCreateForm {
    client_id: String,
    #[serde(default)]
    display_name: Option<String>,
    kind: String,
    #[serde(default)]
    auth_method: Option<String>,
}

async fn post_client_create(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Form(form): Form<ClientCreateForm>,
) -> Result<Response, AdminError> {
    use geonosis_core::client::{
        AccessTokenType, Client, ClientAuthMethod, ClientKind, ConsentPolicy, FlowBinding,
        GrantPolicy,
    };
    use geonosis_core::id::ClientId;
    let realm = realm_by_slug(&state, &slug).await?;
    let kind = match form.kind.as_str() {
        "public" => ClientKind::Public,
        "bearer-only" => ClientKind::BearerOnly,
        "service-account" => ClientKind::ServiceAccount,
        "saml-service-provider" => ClientKind::SamlServiceProvider,
        "scim-client" => ClientKind::ScimClient,
        _ => ClientKind::Confidential,
    };
    let auth_method = match form.auth_method.as_deref().unwrap_or("client-secret-basic") {
        "client-secret-post" => ClientAuthMethod::ClientSecretPost,
        "client-secret-jwt" => ClientAuthMethod::ClientSecretJwt,
        "private-key-jwt" => ClientAuthMethod::PrivateKeyJwt,
        "none" => ClientAuthMethod::None,
        "tls-client-auth" => ClientAuthMethod::TlsClientAuth,
        _ => ClientAuthMethod::ClientSecretBasic,
    };
    let now = chrono::Utc::now();
    let client = Client {
        id: ClientId::new(),
        realm_id: realm.id,
        client_id: form.client_id.clone(),
        display_name: form.display_name,
        kind,
        grants: match kind {
            ClientKind::Public => GrantPolicy::public_app(),
            ClientKind::ServiceAccount => GrantPolicy::service_account(),
            _ => GrantPolicy::web_app(),
        },
        auth_method,
        flow_binding: FlowBinding::default(),
        default_scopes: vec![],
        optional_scopes: vec![],
        redirect_uris: vec![],
        post_logout_redirect_uris: vec![],
        web_origins: vec![],
        access_token_type: AccessTokenType::default(),
        consent: ConsentPolicy::default(),
        access_token_lifespan: None,
        refresh_token_lifespan: None,
        access_token_signing_alg: None,
        front_channel_logout_enabled: false,
        backchannel_logout_url: None,
        client_authentication_keys: vec![],
        pairwise_sub_algorithm: None,
        saml_sp_config: None,
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    state.storage.create_client(client.clone()).await?;
    crate::audit_emit::emit(
        &state,
        realm.id,
        "client.created",
        Some(geonosis_audit::Target::Client { id: client.id }),
        serde_json::json!({ "client_id": client.client_id }),
    );
    Ok(Redirect::to(&format!("/admin/realms/{slug}/clients/{}", form.client_id)).into_response())
}

async fn page_client_detail(
    State(state): State<Arc<AdminState>>,
    Path((slug, client_id)): Path<(String, String)>,
    Query(q): Query<TabQuery>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let client = state
        .storage
        .get_client_by_client_id(realm.id, &client_id)
        .await?;
    let tab = q.tab.unwrap_or_else(|| "general".into());
    Ok(render(move || {
        view! {
            <ClientDetailPage realm_slug=slug client=client active_tab=tab ctx=ctx/>
        }
    }))
}

// =========================================================================
//                                   Users
// =========================================================================

async fn page_users(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Query(q): Query<SearchQuery>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let users = state.storage.list_users(realm.id, 100).await?;
    let search = q.search.unwrap_or_default();
    let search_low = search.to_lowercase();
    let rows: Vec<UserRow> = users
        .into_iter()
        .filter(|u| {
            if search.is_empty() {
                true
            } else {
                u.username.to_lowercase().contains(&search_low)
                    || u.email
                        .as_deref()
                        .map(|e| e.to_lowercase().contains(&search_low))
                        .unwrap_or(false)
            }
        })
        .map(|u| UserRow {
            id: u.id.to_string(),
            username: u.username,
            email: u.email,
            enabled: u.enabled,
            created_at: u.created_at.to_rfc3339(),
        })
        .collect();
    let s = realm.slug;
    Ok(render(move || {
        view! {
            <UsersPage realm_slug=s rows=rows ctx=ctx search=search/>
        }
    }))
}

async fn page_user_new(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let _ = realm_by_slug(&state, &slug).await?;
    Ok(render(
        move || view! { <UserCreatePage realm_slug=slug ctx=ctx/> },
    ))
}

#[derive(Debug, Deserialize)]
struct UserCreateForm {
    username: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
    #[serde(default)]
    enabled: Option<String>,
    #[serde(default)]
    email_verified: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

async fn post_user_create(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Form(form): Form<UserCreateForm>,
) -> Result<Response, AdminError> {
    use geonosis_core::id::UserId;
    use geonosis_core::{PersonName, User};
    let realm = realm_by_slug(&state, &slug).await?;
    let now = chrono::Utc::now();
    let name = if form.first_name.is_some() || form.last_name.is_some() {
        Some(PersonName {
            given: form.first_name.clone(),
            family: form.last_name.clone(),
            middle: None,
            display: None,
        })
    } else {
        None
    };
    let user = User {
        id: UserId::new(),
        realm_id: realm.id,
        username: form.username.clone(),
        email: form.email.filter(|s| !s.is_empty()),
        email_verified: form.email_verified.is_some(),
        name,
        credentials: vec![],
        federation: None,
        attributes: Default::default(),
        required_actions: vec![],
        required_flow: None,
        organizations: vec![],
        enabled: form.enabled.is_some(),
        failed_attempts: 0,
        locked_until: None,
        last_failed_at: None,
        created_at: now,
        updated_at: now,
    };
    state.storage.create_user(user.clone()).await?;
    if let Some(pw) = form.password.filter(|s| !s.is_empty()) {
        let phc = geonosis_crypto::hash_password(&pw)
            .map_err(|e| AdminError::Storage(format!("hash_password: {e}")))?;
        state
            .storage
            .store_password_hash(realm.id, user.id, phc)
            .await?;
    }
    crate::audit_emit::emit(
        &state,
        realm.id,
        "user.created",
        Some(geonosis_audit::Target::User { id: user.id }),
        serde_json::json!({ "username": form.username }),
    );
    Ok(Redirect::to(&format!("/admin/realms/{slug}/users/{}", form.username)).into_response())
}

async fn page_user_detail(
    State(state): State<Arc<AdminState>>,
    Path((slug, username)): Path<(String, String)>,
    Query(q): Query<TabQuery>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let user = state
        .storage
        .get_user_by_username(realm.id, &username)
        .await?;
    let roles = state
        .storage
        .list_user_roles(realm.id, user.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.name)
        .collect::<Vec<_>>();
    let groups = state
        .storage
        .list_user_groups(realm.id, user.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|g| g.path)
        .collect::<Vec<_>>();
    let orgs = state
        .storage
        .list_user_orgs(realm.id, user.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|m| m.organization_id.to_string())
        .collect::<Vec<_>>();
    let sessions = state
        .storage
        .list_sessions(realm.id, 200)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|s| s.user_id == user.id)
        .map(|s| UserSessionRow {
            id: s.id.to_string(),
            started_at: s.started_at.to_rfc3339(),
            last_seen_at: s.last_seen_at.to_rfc3339(),
            client_count: s.clients.len(),
        })
        .collect::<Vec<_>>();
    let data = UserDetailData {
        user,
        roles,
        groups,
        orgs,
        sessions,
    };
    let tab = q.tab.unwrap_or_else(|| "general".into());
    Ok(render(move || {
        view! {
            <UserDetailPage realm_slug=slug data=data active_tab=tab ctx=ctx/>
        }
    }))
}

// =========================================================================
//                                  Roles
// =========================================================================

async fn page_roles(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let roles = state.storage.list_roles(realm.id, None).await?;
    let rows: Vec<RoleRow> = roles
        .into_iter()
        .map(|r| RoleRow {
            name: r.name,
            description: r.description,
            client_scope: r.client_id.map(|id| id.to_string()),
            composite_count: r.composites.realm_roles.len()
                + r.composites
                    .client_roles
                    .values()
                    .map(|v| v.len())
                    .sum::<usize>(),
        })
        .collect();
    let s = realm.slug;
    Ok(render(
        move || view! { <RolesPage realm_slug=s rows=rows ctx=ctx/> },
    ))
}

async fn page_role_new(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let _ = realm_by_slug(&state, &slug).await?;
    Ok(render(
        move || view! { <RoleCreatePage realm_slug=slug ctx=ctx/> },
    ))
}

#[derive(Debug, Deserialize)]
struct RoleCreateForm {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
}

async fn post_role_create(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Form(form): Form<RoleCreateForm>,
) -> Result<Response, AdminError> {
    use geonosis_core::id::RoleId;
    use geonosis_core::role::{CompositeRoles, Role};
    let realm = realm_by_slug(&state, &slug).await?;
    let now = chrono::Utc::now();
    let client_id = match form.client_id.filter(|s| !s.is_empty()) {
        Some(cid) => Some(
            state
                .storage
                .get_client_by_client_id(realm.id, &cid)
                .await?
                .id,
        ),
        None => None,
    };
    let role = Role {
        id: RoleId::new(),
        realm_id: realm.id,
        client_id,
        name: form.name.clone(),
        description: form.description.filter(|s| !s.is_empty()),
        composites: CompositeRoles::default(),
        attributes: Default::default(),
        created_at: now,
        updated_at: now,
    };
    state.storage.create_role(role.clone()).await?;
    crate::audit_emit::emit(
        &state,
        realm.id,
        "role.created",
        Some(geonosis_audit::Target::Other {
            entity: "role".into(),
            id: role.id.to_string(),
        }),
        serde_json::json!({ "name": role.name }),
    );
    Ok(Redirect::to(&format!("/admin/realms/{slug}/roles/{}", form.name)).into_response())
}

async fn page_role_detail(
    State(state): State<Arc<AdminState>>,
    Path((slug, name)): Path<(String, String)>,
    Query(q): Query<TabQuery>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let role = state
        .storage
        .get_role_by_name(realm.id, None, &name)
        .await?;
    let composites_realm = role
        .composites
        .realm_roles
        .iter()
        .map(|id| id.to_string())
        .collect();
    let composites_client = role
        .composites
        .client_roles
        .iter()
        .map(|(k, v)| (k.clone(), v.iter().map(|id| id.to_string()).collect()))
        .collect();
    let data = RoleDetailData {
        name: role.name.clone(),
        description: role.description.clone(),
        client_scope: role.client_id.map(|id| id.to_string()),
        composites_realm,
        composites_client,
        assigned_users: vec![],
        assigned_groups: vec![],
    };
    let tab = q.tab.unwrap_or_else(|| "general".into());
    Ok(render(move || {
        view! {
            <RoleDetailPage realm_slug=slug data=data active_tab=tab ctx=ctx/>
        }
    }))
}

// =========================================================================
//                                  Groups
// =========================================================================

async fn page_groups(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let groups = state.storage.list_groups(realm.id).await?;
    let rows: Vec<GroupRow> = groups
        .into_iter()
        .map(|g| GroupRow {
            id: g.id.to_string(),
            path: g.path,
            name: g.name,
            realm_role_count: g.realm_role_ids.len(),
            member_count: 0,
        })
        .collect();
    let s = realm.slug;
    Ok(render(move || {
        view! {
            <GroupsPage realm_slug=s rows=rows ctx=ctx/>
        }
    }))
}

async fn page_group_new(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let _ = realm_by_slug(&state, &slug).await?;
    Ok(render(
        move || view! { <GroupCreatePage realm_slug=slug ctx=ctx/> },
    ))
}

#[derive(Debug, Deserialize)]
struct GroupCreateForm {
    name: String,
    #[serde(default)]
    parent_id: Option<String>,
}

async fn post_group_create(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Form(form): Form<GroupCreateForm>,
) -> Result<Response, AdminError> {
    use geonosis_core::id::GroupId;
    use geonosis_core::Group;
    let realm = realm_by_slug(&state, &slug).await?;
    let parent_id = form
        .parent_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<GroupId>().ok());
    let now = chrono::Utc::now();
    let path = if let Some(pid) = parent_id {
        let parent = state.storage.get_group(realm.id, pid).await?;
        format!("{}/{}", parent.path.trim_end_matches('/'), form.name)
    } else {
        format!("/{}", form.name)
    };
    let group = Group {
        id: GroupId::new(),
        realm_id: realm.id,
        parent_id,
        name: form.name.clone(),
        path: path.clone(),
        attributes: Default::default(),
        realm_role_ids: vec![],
        client_role_ids: Default::default(),
        created_at: now,
        updated_at: now,
    };
    state.storage.create_group(group.clone()).await?;
    crate::audit_emit::emit(
        &state,
        realm.id,
        "group.created",
        Some(geonosis_audit::Target::Other {
            entity: "group".into(),
            id: group.id.to_string(),
        }),
        serde_json::json!({ "path": path }),
    );
    Ok(Redirect::to(&format!("/admin/realms/{slug}/groups/{}", group.id)).into_response())
}

async fn page_group_detail(
    State(state): State<Arc<AdminState>>,
    Path((slug, id)): Path<(String, String)>,
    Query(q): Query<TabQuery>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    use geonosis_core::id::GroupId;
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let group_id: GroupId = id.parse().map_err(|_| AdminError::NotFound)?;
    let group = state.storage.get_group(realm.id, group_id).await?;
    let data = GroupDetailData {
        id: group.id.to_string(),
        name: group.name.clone(),
        path: group.path.clone(),
        realm_role_count: group.realm_role_ids.len(),
        member_count: 0,
        members: vec![],
        realm_roles: group.realm_role_ids.iter().map(|r| r.to_string()).collect(),
    };
    let tab = q.tab.unwrap_or_else(|| "general".into());
    Ok(render(move || {
        view! {
            <GroupDetailPage realm_slug=slug data=data active_tab=tab ctx=ctx/>
        }
    }))
}

// =========================================================================
//                                  Orgs
// =========================================================================

async fn page_orgs(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let orgs = state.storage.list_organizations(realm.id).await?;
    let rows: Vec<OrgRow> = orgs
        .into_iter()
        .map(|o| OrgRow {
            alias: o.alias,
            display_name: o.display_name,
            default_idp_alias: o.default_idp_alias,
            enabled: o.enabled,
        })
        .collect();
    let s = realm.slug;
    Ok(render(move || {
        view! {
            <OrgsPage realm_slug=s rows=rows ctx=ctx/>
        }
    }))
}

async fn page_org_new(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let _ = realm_by_slug(&state, &slug).await?;
    Ok(render(
        move || view! { <OrgCreatePage realm_slug=slug ctx=ctx/> },
    ))
}

#[derive(Debug, Deserialize)]
struct OrgCreateForm {
    alias: String,
    display_name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    enabled: Option<String>,
}

async fn post_org_create(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Form(form): Form<OrgCreateForm>,
) -> Result<Response, AdminError> {
    use geonosis_core::id::OrganizationId;
    use geonosis_core::organization::{Organization, OrganizationBranding};
    let realm = realm_by_slug(&state, &slug).await?;
    let now = chrono::Utc::now();
    let org = Organization {
        id: OrganizationId::new(),
        realm_id: realm.id,
        alias: form.alias.clone(),
        display_name: form.display_name,
        description: form.description.filter(|s| !s.is_empty()),
        attributes: Default::default(),
        branding: OrganizationBranding::default(),
        default_idp_alias: None,
        redirect_url: None,
        enabled: form.enabled.is_some(),
        created_at: now,
        updated_at: now,
    };
    state.storage.create_organization(org.clone()).await?;
    crate::audit_emit::emit(
        &state,
        realm.id,
        "organization.created",
        Some(geonosis_audit::Target::Other {
            entity: "organization".into(),
            id: org.id.to_string(),
        }),
        serde_json::json!({ "alias": org.alias }),
    );
    Ok(Redirect::to(&format!("/admin/realms/{slug}/orgs/{}", form.alias)).into_response())
}

async fn page_org_detail(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
    Query(q): Query<TabQuery>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let org = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await?;
    let domains = state
        .storage
        .list_org_domains(realm.id, org.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|d| OrgDomainRow {
            domain: d.domain,
            verified: d.verified,
            verified_at: d.verified_at.map(|t| t.to_rfc3339()),
        })
        .collect();
    let members = state
        .storage
        .list_org_memberships(realm.id, org.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|m| OrgMemberRow {
            user_id: m.user_id.to_string(),
            username: None,
            email: None,
            state: m.state,
            roles: m.roles.iter().map(|r| r.to_string()).collect(),
            joined_at: m.joined_at.to_rfc3339(),
        })
        .collect();
    let invitations = state
        .storage
        .list_org_invitations(realm.id, org.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|i| OrgInviteRow {
            email: i.email,
            roles: i.roles.iter().map(|r| r.to_string()).collect(),
            expires_at: i.expires_at.to_rfc3339(),
            accepted: i.accepted_at.is_some(),
        })
        .collect();
    let roles = state
        .storage
        .list_org_roles(realm.id, org.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| OrgRoleRow {
            id: r.id.to_string(),
            name: r.name,
            description: r.description,
            permissions: r.permissions,
            built_in: r.built_in,
        })
        .collect();
    let idp_bindings = state
        .storage
        .list_org_idp_bindings(realm.id, org.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|b| OrgIdpRow {
            idp_alias: b.idp_alias,
            priority: b.priority,
        })
        .collect();
    let consent_policies = state
        .storage
        .list_org_consent_policies(realm.id, org.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|p| OrgConsentRow {
            client_id: p.client_id.to_string(),
            mode: p.mode,
            pre_approved: p
                .pre_approved_scopes
                .iter()
                .map(|s| s.as_str().to_string())
                .collect(),
            blocked: p
                .blocked_scopes
                .iter()
                .map(|s| s.as_str().to_string())
                .collect(),
        })
        .collect();
    let data = OrgDetailData {
        org,
        domains,
        members,
        invitations,
        roles,
        idp_bindings,
        consent_policies,
    };
    let tab = q.tab.unwrap_or_else(|| "general".into());
    Ok(render(move || {
        view! {
            <OrgDetailPage realm_slug=slug data=data active_tab=tab ctx=ctx/>
        }
    }))
}

// =========================================================================
//                                 Agents
// =========================================================================

async fn page_agents(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let agents = state.storage.list_agents(realm.id).await?;
    let rows: Vec<AgentRow> = agents
        .into_iter()
        .map(|a| AgentRow {
            alias: a.alias,
            display_name: a.display_name,
            kind: agent_kind_label(&a.kind),
            vendor: a.vendor,
            model_hint: a.model_hint,
            enabled: a.enabled,
        })
        .collect();
    let s = realm.slug;
    Ok(render(move || {
        view! {
            <AgentsPage realm_slug=s rows=rows ctx=ctx/>
        }
    }))
}

fn agent_kind_label(k: &geonosis_core::agent::AgentKind) -> String {
    use geonosis_core::agent::AgentKind;
    match k {
        AgentKind::Assistant => "Assistant".into(),
        AgentKind::Scraper => "Scraper".into(),
        AgentKind::Webhook => "Webhook".into(),
        AgentKind::Batch => "Batch".into(),
        AgentKind::Custom(s) => s.clone(),
    }
}

async fn page_agent_detail(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
    Query(q): Query<TabQuery>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let agent = state.storage.get_agent_by_alias(realm.id, &alias).await?;
    let tab = q.tab.unwrap_or_else(|| "general".into());
    Ok(render(move || {
        view! {
            <AgentDetailPage realm_slug=slug agent=agent active_tab=tab ctx=ctx/>
        }
    }))
}

// =========================================================================
//                                  IdPs
// =========================================================================

async fn page_idps(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    use geonosis_broker::types::IdpKind;
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let idps = state.storage.list_idps(realm.id).await?;
    let rows: Vec<IdpRow> = idps
        .into_iter()
        .map(|i| IdpRow {
            alias: i.alias,
            display_name: i.display_name,
            kind: match i.kind {
                IdpKind::Oidc => "oidc",
                IdpKind::Saml => "saml",
            }
            .into(),
            enabled: i.enabled,
        })
        .collect();
    let s = realm.slug;
    Ok(render(
        move || view! { <IdpsPage realm_slug=s rows=rows ctx=ctx/> },
    ))
}

async fn page_idp_new(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let _ = realm_by_slug(&state, &slug).await?;
    Ok(render(
        move || view! { <IdpCreatePage realm_slug=slug ctx=ctx/> },
    ))
}

#[derive(Debug, Deserialize)]
struct IdpCreateForm {
    alias: String,
    display_name: String,
    kind: String,
}

async fn post_idp_create(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Form(form): Form<IdpCreateForm>,
) -> Result<Response, AdminError> {
    use geonosis_broker::types::{
        ClientAuthMethod, IdentityProvider, IdpConfig, IdpKind, OidcIdpConfig, SamlIdpConfig,
    };
    use geonosis_core::id::IdpId;
    let realm = realm_by_slug(&state, &slug).await?;
    let kind = match form.kind.as_str() {
        "saml" => IdpKind::Saml,
        _ => IdpKind::Oidc,
    };
    let config = match kind {
        IdpKind::Oidc => IdpConfig::Oidc(OidcIdpConfig {
            issuer: String::new(),
            discovery_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None,
            client_id: String::new(),
            client_auth: ClientAuthMethod::default(),
            client_secret: None,
            client_assertion_key: None,
            scopes: vec!["openid".into()],
            pkce: true,
            accept_unsigned_userinfo: false,
            prompt: None,
            response_mode: None,
        }),
        IdpKind::Saml => IdpConfig::Saml(SamlIdpConfig {
            entity_id: String::new(),
            sso_url: String::new(),
            slo_url: None,
            signing_cert_pems: vec![],
            binding_outbound: geonosis_saml_types::SamlBinding::HttpRedirect,
            binding_inbound: geonosis_saml_types::SamlBinding::HttpPost,
            name_id_format: geonosis_saml_types::NameIdFormat::Persistent,
            want_assertions_signed: true,
            want_responses_signed: true,
        }),
    };
    let idp = IdentityProvider {
        id: IdpId::new(),
        realm_id: realm.id,
        alias: form.alias.clone(),
        display_name: form.display_name,
        kind,
        config,
        first_login_flow_alias: "browser".into(),
        post_login_flow_alias: None,
        link_only: false,
        adapter_urn: None,
        enabled: true,
    };
    state.storage.create_idp(idp.clone()).await?;
    crate::audit_emit::emit(
        &state,
        realm.id,
        "idp.created",
        Some(geonosis_audit::Target::Other {
            entity: "idp".into(),
            id: idp.id.to_string(),
        }),
        serde_json::json!({ "alias": form.alias }),
    );
    Ok(Redirect::to(&format!("/admin/realms/{slug}/idps/{}", form.alias)).into_response())
}

async fn page_idp_detail(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
    Query(q): Query<TabQuery>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let idp = state.storage.get_idp_by_alias(realm.id, &alias).await?;
    let tab = q.tab.unwrap_or_else(|| "general".into());
    Ok(render(move || {
        view! {
            <IdpDetailPage realm_slug=slug idp=idp active_tab=tab ctx=ctx/>
        }
    }))
}

// =========================================================================
//                                Federation
// =========================================================================

async fn page_federation(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let sources = state.storage.list_ldap_sources(realm.id).await?;
    let rows: Vec<LdapRow> = sources
        .into_iter()
        .map(|s| LdapRow {
            alias: s.alias,
            server: s.urls.first().cloned().unwrap_or_default(),
            base_dn: s.base_dn,
            priority: s.priority,
            enabled: s.enabled,
        })
        .collect();
    let s = realm.slug;
    Ok(render(move || {
        view! {
            <FederationPage realm_slug=s rows=rows ctx=ctx/>
        }
    }))
}

async fn page_federation_detail(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
    Query(q): Query<TabQuery>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let cfg = state.storage.get_ldap_source(realm.id, &alias).await?;
    let tab = q.tab.unwrap_or_else(|| "connection".into());
    Ok(render(move || {
        view! {
            <LdapDetailPage realm_slug=slug cfg=cfg active_tab=tab ctx=ctx/>
        }
    }))
}

// =========================================================================
//                                   SPI
// =========================================================================

async fn page_spi(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let modules = state
        .storage
        .list_wasm_modules(realm.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|m| ModuleRow {
            alias: m.alias,
            interface: m.interface,
            size_bytes: m.size_bytes,
            created_at: m.created_at.to_rfc3339(),
        })
        .collect();
    // The trait wants an interface filter per call; aggregate across
    // the small known interface set so the SPI page shows every
    // bound provider in one table.
    let known_interfaces: &[&str] = &[
        "broker-adapter",
        "user-federation",
        "authenticator",
        "mapper",
        "event-listener",
        "policy",
    ];
    let mut all_bindings: Vec<crate::leptos_ui::pages::spi::BindingRow> = Vec::new();
    for iface in known_interfaces {
        let rows = state
            .storage
            .list_spi_bindings(realm.id, iface)
            .await
            .unwrap_or_default();
        for b in rows {
            all_bindings.push(BindingRow {
                interface: b.interface.clone(),
                provider_urn: b.provider_urn.clone(),
                origin: if b.provider_urn_starts_with_wasm() {
                    "wasm".into()
                } else {
                    "builtin".into()
                },
                priority: b.priority,
                enabled: b.enabled,
            });
        }
    }
    let bindings = all_bindings;
    let s = realm.slug;
    Ok(render(move || {
        view! {
            <SpiPage realm_slug=s modules=modules bindings=bindings ctx=ctx/>
        }
    }))
}

// =========================================================================
//                                   Keys
// =========================================================================

async fn page_keys(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let _ = realm_by_slug(&state, &slug).await?;
    // v0.1.x: the admin API GET /keys endpoint exists but full key list
    // lands once the KMS surface stabilises. Return an empty list so the
    // page renders cleanly.
    let rows: Vec<KeyRow> = vec![];
    let s = slug;
    Ok(render(
        move || view! { <KeysPage realm_slug=s rows=rows ctx=ctx/> },
    ))
}

// =========================================================================
//                                Sessions
// =========================================================================

async fn page_sessions(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let sessions = state.storage.list_sessions(realm.id, 200).await?;
    let rows: Vec<SessionRow> = sessions
        .into_iter()
        .map(|s| SessionRow {
            id: s.id.to_string(),
            user_id: s.user_id.to_string(),
            authn_level: format!("{:?}", s.authn_level),
            idp_alias: s.idp_alias,
            started_at: s.started_at.to_rfc3339(),
            last_seen_at: s.last_seen_at.to_rfc3339(),
            client_count: s.clients.len(),
        })
        .collect();
    let s = realm.slug;
    Ok(render(move || {
        view! {
            <SessionsPage realm_slug=s rows=rows ctx=ctx/>
        }
    }))
}

// =========================================================================
//                                Events
// =========================================================================

fn parse_optional_rfc3339(
    s: &Option<String>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, AdminError> {
    match s {
        None => Ok(None),
        Some(raw) if raw.is_empty() => Ok(None),
        Some(raw) => {
            let parsed = chrono::DateTime::parse_from_rfc3339(raw)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .or_else(|_| {
                    chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M")
                        .map(|n| n.and_utc())
                        .map_err(|e| AdminError::Storage(format!("bad datetime `{raw}`: {e}")))
                })
                .map_err(|e| match e {
                    err @ AdminError::Storage(_) => err,
                    _ => AdminError::Storage(format!("bad datetime `{raw}`")),
                })?;
            Ok(Some(parsed))
        }
    }
}

async fn page_events(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Query(q): Query<EventsQuery>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let from = parse_optional_rfc3339(&q.from)?;
    let until = parse_optional_rfc3339(&q.until)?;
    let filter = geonosis_storage::AuditEventFilter {
        action: q.action.as_deref(),
        actor: q.actor.as_deref(),
        from,
        until,
    };
    let raw = state
        .storage
        .list_audit_events(realm.id, &filter, 200)
        .await?;
    let rows: Vec<EventRow> = raw
        .into_iter()
        .map(|r| EventRow {
            occurred_at: r.occurred_at.to_rfc3339(),
            actor: r
                .actor
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            action: r.action,
            target: r
                .target
                .as_ref()
                .and_then(|t| {
                    t.get("kind")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_else(|| "—".to_string()),
        })
        .collect();
    let filter_view = EventFilter {
        action: q.action,
        actor: q.actor,
        from: q.from,
        until: q.until,
    };
    let s = realm.slug;
    Ok(render(move || {
        view! {
            <EventsPage realm_slug=s filter=filter_view rows=rows ctx=ctx/>
        }
    }))
}

// =========================================================================
//                                 Flows
// =========================================================================

async fn page_flows(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let flows = state.storage.list_auth_flows(realm.id).await?;
    let rows: Vec<FlowRow> = flows
        .into_iter()
        .map(|f| FlowRow {
            alias: f.alias,
            display_name: f.display_name,
            version: f.version,
            node_count: f.nodes.len(),
        })
        .collect();
    let s = realm.slug;
    Ok(render(
        move || view! { <FlowsPage realm_slug=s rows=rows ctx=ctx/> },
    ))
}

async fn page_flow_edit(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let flow = state
        .storage
        .get_auth_flow_by_alias(realm.id, &alias)
        .await?;
    let json =
        serde_json::to_string_pretty(&flow).map_err(|e| AdminError::Storage(e.to_string()))?;
    let s = realm.slug;
    let flow_for_view = Some(flow);
    Ok(render(move || {
        view! {
            <FlowEditPage realm_slug=s alias=alias flow=flow_for_view json=json ctx=ctx/>
        }
    }))
}

#[derive(Debug, Deserialize)]
struct FlowSaveForm {
    definition: String,
}

async fn post_flow_save(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
    principal: Option<axum::Extension<AdminPrincipal>>,
    Form(form): Form<FlowSaveForm>,
) -> Result<Response, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let parsed = serde_json::from_str::<geonosis_flow::FlowDefinition>(&form.definition);
    let validated = parsed
        .map_err(|e| format!("invalid JSON: {e}"))
        .and_then(|def| {
            if def.alias != alias {
                return Err(format!(
                    "alias mismatch: body says `{}`, path says `{}`",
                    def.alias, alias
                ));
            }
            geonosis_flow::compile(def.clone()).map_err(|e| e.to_string())?;
            Ok(def)
        });
    match validated {
        Ok(def) => {
            let flow_id = def.id;
            state.storage.save_auth_flow(def).await?;
            crate::audit_emit::emit(
                &state,
                realm.id,
                "flow.updated",
                Some(geonosis_audit::Target::Flow { id: flow_id }),
                serde_json::json!({ "alias": alias }),
            );
            Ok(Redirect::to(&format!("/admin/realms/{slug}/flows/{alias}")).into_response())
        }
        Err(error) => {
            let flow_for_view =
                serde_json::from_str::<geonosis_flow::FlowDefinition>(&form.definition).ok();
            let s = realm.slug;
            let body = render(move || {
                view! {
                    <FlowEditPage
                        realm_slug=s
                        alias=alias
                        flow=flow_for_view
                        json=form.definition
                        ctx=ctx
                        error=error
                    />
                }
            });
            Ok(body.into_response())
        }
    }
}

// =========================================================================
//                          User profile schema
// =========================================================================

async fn page_user_profile_schema(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    principal: Option<axum::Extension<AdminPrincipal>>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, principal.as_deref()).await;
    let realm = realm_by_slug(&state, &slug).await?;
    let profile = state.storage.get_user_profile_schema(realm.id).await?;
    let s = realm.slug;
    Ok(render(move || {
        view! {
            <UserProfileSchemaPage realm_slug=s profile=profile ctx=ctx/>
        }
    }))
}

// =========================================================================
//                              Own profile
// =========================================================================

async fn page_profile(
    State(state): State<Arc<AdminState>>,
    Query(q): Query<TabQuery>,
    principal: axum::Extension<AdminPrincipal>,
) -> Result<Html<String>, AdminError> {
    let ctx = build_ctx(&state, Some(&principal)).await;
    let user = state
        .storage
        .get_user(principal.realm_id, principal.user_id)
        .await?;
    let sessions = state
        .storage
        .list_sessions(principal.realm_id, 200)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|s| s.user_id == principal.user_id)
        .map(|s| ProfileSession {
            id: s.id.to_string(),
            started_at: s.started_at.to_rfc3339(),
            last_seen_at: s.last_seen_at.to_rfc3339(),
            current: false,
        })
        .collect();
    let data = ProfileData { user, sessions };
    let tab = q.tab.unwrap_or_else(|| "general".into());
    Ok(render(move || {
        view! {
            <ProfilePage data=data active_tab=tab ctx=ctx/>
        }
    }))
}

// =========================================================================
//                                Render
// =========================================================================

fn render<F, V>(view_fn: F) -> Html<String>
where
    F: FnOnce() -> V,
    V: leptos::prelude::RenderHtml + Send + 'static,
{
    let owner = leptos::prelude::Owner::new();
    let body = owner.with(|| view_fn().to_html());
    Html(format!("<!DOCTYPE html>{body}"))
}

// =========================================================================
//                          SpiBindingRow helper
// =========================================================================

// The storage row stores both `provider_urn` and `enabled`. The "origin"
// surfaced by the UI ("wasm" vs "builtin") is inferred from the URN
// scheme — `wasm:<alias>` is a hot-loaded module, anything else is
// resolved against the built-in registry.
trait SpiBindingRowExt {
    fn provider_urn_starts_with_wasm(&self) -> bool;
}

impl SpiBindingRowExt for geonosis_storage::SpiBindingRow {
    fn provider_urn_starts_with_wasm(&self) -> bool {
        self.provider_urn.starts_with("wasm:")
    }
}
