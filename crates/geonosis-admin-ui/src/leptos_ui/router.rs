//! Axum router that mounts the Leptos pages under `/admin-next/...`.
//!
//! Lives alongside the Maud-backed `/admin/...` routes during the
//! v0.1.x migration. Once every Maud page is ported, the legacy paths
//! retire and the Leptos paths take over `/admin/...`.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use leptos::prelude::*;
use serde::Deserialize;

use crate::handlers_v1::extractors::realm_by_slug;
use crate::leptos_ui::pages::agents::{AgentRow, AgentsPage};
use crate::leptos_ui::pages::clients::{ClientRow, ClientsPage};
use crate::leptos_ui::pages::events::{EventFilter, EventRow, EventsPage};
use crate::leptos_ui::pages::groups::{GroupRow, GroupsPage};
use crate::leptos_ui::pages::idps::{IdpRow, IdpsPage};
use crate::leptos_ui::pages::orgs::{OrgRow, OrgsPage};
use crate::leptos_ui::pages::realm_detail::{RealmDetailData, RealmDetailPage};
use crate::leptos_ui::pages::realms::{RealmRow, RealmsPage};
use crate::leptos_ui::pages::roles::{RoleRow, RolesPage};
use crate::leptos_ui::pages::sessions::{SessionRow, SessionsPage};
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
        .route("/admin-next/realms/:slug/roles", get(page_roles))
        .route("/admin-next/realms/:slug/groups", get(page_groups))
        .route("/admin-next/realms/:slug/events", get(page_events))
        .route("/admin-next/realms/:slug/sessions", get(page_sessions))
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

async fn page_roles(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Html<String>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let roles = state.storage.list_roles(realm.id, None).await?;
    let rows: Vec<RoleRow> = roles
        .into_iter()
        .map(|r| RoleRow {
            name: r.name,
            description: r.description,
            client_scope: r.client_id.map(|id| id.to_string()),
        })
        .collect();
    let s = realm.slug;
    Ok(render(move || view! { <RolesPage realm_slug=s rows=rows/> }))
}

async fn page_groups(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Html<String>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let groups = state.storage.list_groups(realm.id).await?;
    let rows: Vec<GroupRow> = groups
        .into_iter()
        .map(|g| GroupRow {
            path: g.path,
            name: g.name,
            realm_role_count: g.realm_role_ids.len(),
        })
        .collect();
    let s = realm.slug;
    Ok(render(move || view! { <GroupsPage realm_slug=s rows=rows/> }))
}

#[derive(Debug, Default, Deserialize)]
struct EventsQuery {
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    until: Option<String>,
}

fn parse_optional_rfc3339(
    s: &Option<String>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, AdminError> {
    match s {
        None => Ok(None),
        Some(raw) if raw.is_empty() => Ok(None),
        Some(raw) => {
            // `<input type="datetime-local">` posts `YYYY-MM-DDTHH:MM`
            // without an offset. Treat naive values as UTC for the
            // filter window; explicit `+hh:mm` offsets parse via the
            // RFC-3339 branch.
            let parsed = chrono::DateTime::parse_from_rfc3339(raw)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .or_else(|_| {
                    chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M")
                        .map(|n| n.and_utc())
                        .map_err(|e| {
                            AdminError::Storage(format!("bad datetime `{raw}`: {e}"))
                        })
                })
                .map_err(|e| match e {
                    err @ AdminError::Storage(_) => err,
                    _ => AdminError::Storage(format!("bad datetime `{raw}`")),
                })?;
            Ok(Some(parsed))
        }
    }
}

async fn page_sessions(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Html<String>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let sessions = state.storage.list_sessions(realm.id, 200).await?;
    let rows: Vec<SessionRow> = sessions
        .into_iter()
        .map(|s| SessionRow {
            id: s.id.to_string(),
            user_id: s.user_id.to_string(),
            authn_level: format!("{:?}", s.authn_level).to_lowercase(),
            idp_alias: s.idp_alias,
            started_at: s.started_at.to_rfc3339(),
            last_seen_at: s.last_seen_at.to_rfc3339(),
            client_count: s.clients.len(),
        })
        .collect();
    let slug = realm.slug;
    Ok(render(move || view! { <SessionsPage realm_slug=slug rows=rows/> }))
}

async fn page_events(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Query(q): Query<EventsQuery>,
) -> Result<Html<String>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let from = parse_optional_rfc3339(&q.from)?;
    let until = parse_optional_rfc3339(&q.until)?;
    let filter = geonosis_storage::AuditEventFilter {
        action: q.action.as_deref(),
        actor: q.actor.as_deref(),
        from,
        until,
    };
    let raw = state.storage.list_audit_events(realm.id, &filter, 200).await?;
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
                .and_then(|t| t.get("kind").and_then(|v| v.as_str()).map(|s| s.to_string()))
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
        view! { <EventsPage realm_slug=s filter=filter_view rows=rows/> }
    }))
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
