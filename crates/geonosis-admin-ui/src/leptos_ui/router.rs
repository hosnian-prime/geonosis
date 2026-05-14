//! Axum router that mounts the Leptos pages under `/admin-next/...`.
//!
//! Lives alongside the Maud-backed `/admin/...` routes during the
//! v0.1.x migration. Once every Maud page is ported, the legacy paths
//! retire and the Leptos paths take over `/admin/...`.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use leptos::prelude::*;

use crate::handlers_v1::extractors::realm_by_slug;
use crate::leptos_ui::pages::agents::{AgentRow, AgentsPage};
use crate::leptos_ui::pages::clients::{ClientRow, ClientsPage};
use crate::leptos_ui::pages::idps::{IdpRow, IdpsPage};
use crate::leptos_ui::pages::orgs::{OrgRow, OrgsPage};
use crate::leptos_ui::pages::realm_detail::{RealmDetailData, RealmDetailPage};
use crate::leptos_ui::pages::realms::{RealmRow, RealmsPage};
use crate::leptos_ui::pages::users::{UserRow, UsersPage};
use crate::state::{AdminError, AdminState};

/// Build the Leptos sub-router. Composed into the main admin router by
/// `geonosis_admin_ui::router`.
pub fn leptos_router(state: Arc<AdminState>) -> Router {
    Router::new()
        .route("/admin-next/realms", get(page_realms))
        .route("/admin-next/realms/:slug", get(page_realm_detail))
        .route("/admin-next/realms/:slug/clients", get(page_clients))
        .route("/admin-next/realms/:slug/users", get(page_users))
        .route("/admin-next/realms/:slug/orgs", get(page_orgs))
        .route("/admin-next/realms/:slug/agents", get(page_agents))
        .route("/admin-next/realms/:slug/idps", get(page_idps))
        .with_state(state)
}

async fn page_realms(
    State(state): State<Arc<AdminState>>,
) -> Result<Html<String>, AdminError> {
    let realms = state.storage.list_realms().await?;
    let rows: Vec<RealmRow> = realms
        .into_iter()
        .map(|r| RealmRow {
            slug: r.slug,
            display_name: r.display_name,
            enabled: r.enabled,
        })
        .collect();
    Ok(render(move || view! { <RealmsPage realms=rows/> }))
}

async fn page_realm_detail(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Html<String>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let data = RealmDetailData {
        slug: realm.slug,
        display_name: realm.display_name,
        enabled: realm.enabled,
        organizations_enabled: realm.organizations_enabled,
    };
    Ok(render(move || view! { <RealmDetailPage data=data/> }))
}

async fn page_clients(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Html<String>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let clients = state.storage.list_clients(realm.id).await?;
    let rows: Vec<ClientRow> = clients
        .into_iter()
        .map(|c| ClientRow {
            client_id: c.client_id,
            display_name: c.display_name.unwrap_or_default(),
            kind: format!("{:?}", c.kind).to_lowercase(),
            enabled: c.enabled,
        })
        .collect();
    let s = realm.slug;
    Ok(render(move || view! { <ClientsPage realm_slug=s rows=rows/> }))
}

async fn page_users(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Html<String>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let users = state.storage.list_users(realm.id, 100).await?;
    let rows: Vec<UserRow> = users
        .into_iter()
        .map(|u| UserRow {
            id: u.id.to_string(),
            username: u.username,
            email: u.email,
            enabled: u.enabled,
        })
        .collect();
    let s = realm.slug;
    Ok(render(move || view! { <UsersPage realm_slug=s rows=rows/> }))
}

async fn page_orgs(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Html<String>, AdminError> {
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
    Ok(render(move || view! { <OrgsPage realm_slug=s rows=rows/> }))
}

async fn page_agents(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Html<String>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let agents = state.storage.list_agents(realm.id).await?;
    let rows: Vec<AgentRow> = agents
        .into_iter()
        .map(|a| AgentRow {
            alias: a.alias,
            display_name: a.display_name,
            kind: format!("{:?}", a.kind).to_lowercase(),
            vendor: a.vendor,
            model_hint: a.model_hint,
            enabled: a.enabled,
        })
        .collect();
    let s = realm.slug;
    Ok(render(move || view! { <AgentsPage realm_slug=s rows=rows/> }))
}

async fn page_idps(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Html<String>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let idps = state.storage.list_idps(realm.id).await?;
    let rows: Vec<IdpRow> = idps
        .into_iter()
        .map(|i| IdpRow {
            alias: i.alias,
            display_name: i.display_name,
            kind: format!("{:?}", i.kind).to_lowercase(),
            enabled: i.enabled,
        })
        .collect();
    let s = realm.slug;
    Ok(render(move || view! { <IdpsPage realm_slug=s rows=rows/> }))
}

/// Render a Leptos view tree to a complete HTML document string.
///
/// Leptos 0.7 routes view rendering through `RenderHtml::to_html`. We
/// wrap the call in a fresh `Owner` so any contexts the view uses
/// (`provide_meta_context`, suspense scopes, ...) have a reactive
/// runtime to anchor to. `<!DOCTYPE html>` is prepended outside the
/// view tree because the 0.7 `view!` macro treats it as text.
fn render<F, V>(view_fn: F) -> Html<String>
where
    F: FnOnce() -> V,
    V: leptos::prelude::RenderHtml + Send + 'static,
{
    let owner = leptos::prelude::Owner::new();
    let body = owner.with(|| view_fn().to_html());
    Html(format!("<!DOCTYPE html>{body}"))
}
