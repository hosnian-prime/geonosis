//! Admin REST API v1 — JSON endpoints under `/admin/v1/...`.
//!
//! Lives alongside the legacy `handlers.rs` so the HTML / Maud
//! handlers keep working during the Leptos migration window. Once
//! every page is ported, the JSON endpoints stay as the
//! framework-agnostic backplane that `geoctl` and the Leptos pages
//! both consume.
//!
//! Design choices that follow throughout:
//! - **Realm lookup once per request** via [`extract_realm`]. Handlers
//!   never re-look up the realm.
//! - **No DTO layer for v0.1.x**. Core types already implement
//!   `Serialize`/`Deserialize`; introducing per-endpoint wrappers
//!   would duplicate fields without buying stability we need. When
//!   the public API freezes for v1.0 we'll re-evaluate.
//! - **Audit emission per write**. Each create/update/delete handler
//!   pushes an `AuditEvent` describing the change. v0.1.x adds the
//!   actor extraction (currently anonymous); the audit pipeline
//!   itself is already wired through `state.audit`.

use std::sync::Arc;

use axum::routing::{delete, get, post, put};
use axum::Router;

use crate::state::AdminState;

pub mod agents;
pub mod clients;
pub mod events;
pub mod extractors;
pub mod groups;
pub mod idps;
pub mod keys;
pub mod orgs;
pub mod realms;
pub mod roles;
pub mod sessions;
pub mod user_profile;
pub mod users;

/// Build the v1 admin REST sub-router. Composed into
/// `geonosis_admin_ui::router` so the existing `/admin/v1/realms/...`
/// surface keeps responding from one place.
pub fn router(state: Arc<AdminState>) -> Router {
    Router::new()
        // ---- Realms (top-level — no realm slug in path) ----
        .route(
            "/admin/v1/realms",
            get(realms::list).post(realms::create),
        )
        .route(
            "/admin/v1/realms/:slug",
            get(realms::get).put(realms::update).delete(realms::delete_),
        )
        // ---- Clients (OIDC + SAML SP) ----
        .route(
            "/admin/v1/realms/:slug/clients",
            get(clients::list).post(clients::create),
        )
        .route(
            "/admin/v1/realms/:slug/clients/:client_id",
            get(clients::get).put(clients::update).delete(clients::delete_),
        )
        // ---- Users ----
        .route(
            "/admin/v1/realms/:slug/users",
            get(users::list).post(users::create),
        )
        .route(
            "/admin/v1/realms/:slug/users/:username",
            get(users::get).put(users::update).delete(users::delete_),
        )
        .route(
            "/admin/v1/realms/:slug/users/:username/verify-email",
            post(users::verify_email),
        )
        .route(
            "/admin/v1/realms/:slug/users/:username/password",
            put(users::set_password),
        )
        // ---- User profile (single schema per realm) ----
        .route(
            "/admin/v1/realms/:slug/user-profile",
            get(user_profile::get_schema).put(user_profile::put_schema),
        )
        // ---- Roles (realm-scoped) ----
        .route(
            "/admin/v1/realms/:slug/roles",
            get(roles::list).post(roles::create),
        )
        .route(
            "/admin/v1/realms/:slug/roles/:name",
            get(roles::get).put(roles::update).delete(roles::delete_),
        )
        .route(
            "/admin/v1/realms/:slug/users/:user_id/roles",
            get(roles::list_user_roles).post(roles::assign_user_role),
        )
        .route(
            "/admin/v1/realms/:slug/users/:user_id/roles/:role_id",
            delete(roles::unassign_user_role),
        )
        // ---- Groups ----
        .route(
            "/admin/v1/realms/:slug/groups",
            get(groups::list).post(groups::create),
        )
        .route(
            "/admin/v1/realms/:slug/groups/:id",
            get(groups::get).put(groups::update).delete(groups::delete_),
        )
        .route(
            "/admin/v1/realms/:slug/users/:user_id/groups",
            get(groups::list_user_groups).post(groups::assign_user_group),
        )
        .route(
            "/admin/v1/realms/:slug/users/:user_id/groups/:group_id",
            delete(groups::unassign_user_group),
        )
        .route(
            "/admin/v1/realms/:slug/groups/:id/roles",
            get(groups::list_group_roles).post(groups::assign_group_role),
        )
        .route(
            "/admin/v1/realms/:slug/groups/:id/roles/:role_id",
            delete(groups::unassign_group_role),
        )
        // ---- Agents (AI / M2M identities) ----
        .route(
            "/admin/v1/realms/:slug/agents",
            get(agents::list).post(agents::create),
        )
        .route(
            "/admin/v1/realms/:slug/agents/:alias",
            get(agents::get).put(agents::update).delete(agents::revoke),
        )
        // ---- Identity providers (broker) ----
        .route(
            "/admin/v1/realms/:slug/idps",
            get(idps::list).post(idps::create),
        )
        .route(
            "/admin/v1/realms/:slug/idps/:alias",
            get(idps::get).put(idps::update).delete(idps::delete_),
        )
        // ---- Organizations + sub-resources ----
        .route(
            "/admin/v1/realms/:slug/orgs",
            get(orgs::list).post(orgs::create),
        )
        .route(
            "/admin/v1/realms/:slug/orgs/:alias",
            get(orgs::get).put(orgs::update).delete(orgs::delete_),
        )
        .route(
            "/admin/v1/realms/:slug/orgs/:alias/domains",
            get(orgs::list_domains).post(orgs::add_domain),
        )
        .route(
            "/admin/v1/realms/:slug/orgs/:alias/domains/:domain",
            delete(orgs::remove_domain),
        )
        .route(
            "/admin/v1/realms/:slug/orgs/:alias/domains/:domain/verify",
            post(orgs::mark_domain_verified),
        )
        .route(
            "/admin/v1/realms/:slug/orgs/:alias/memberships",
            get(orgs::list_memberships).post(orgs::add_member),
        )
        .route(
            "/admin/v1/realms/:slug/orgs/:alias/memberships/:user_id",
            delete(orgs::remove_member),
        )
        .route(
            "/admin/v1/realms/:slug/orgs/:alias/invitations",
            get(orgs::list_invitations).post(orgs::create_invitation),
        )
        .route(
            "/admin/v1/realms/:slug/orgs/:alias/invitations/accept/:token",
            post(orgs::accept_invitation),
        )
        .route(
            "/admin/v1/realms/:slug/orgs/:alias/roles",
            get(orgs::list_roles).post(orgs::create_role),
        )
        .route(
            "/admin/v1/realms/:slug/orgs/:alias/roles/:role_id",
            put(orgs::update_role).delete(orgs::delete_role),
        )
        .route(
            "/admin/v1/realms/:slug/orgs/:alias/consent-policies",
            get(orgs::list_consent_policies).post(orgs::upsert_consent_policy),
        )
        .route(
            "/admin/v1/realms/:slug/orgs/:alias/consent-policies/:client_id",
            delete(orgs::delete_consent_policy),
        )
        .route(
            "/admin/v1/realms/:slug/orgs/:alias/idps",
            get(orgs::list_idp_bindings).post(orgs::upsert_idp_binding),
        )
        .route(
            "/admin/v1/realms/:slug/orgs/:alias/idps/:idp_alias",
            delete(orgs::remove_idp_binding),
        )
        // ---- Sessions ----
        .route(
            "/admin/v1/realms/:slug/sessions/:session_id",
            delete(sessions::revoke),
        )
        // ---- Keys ----
        .route("/admin/v1/realms/:slug/keys", get(keys::list))
        // ---- Events (audit explorer query) ----
        .route("/admin/v1/realms/:slug/events", get(events::list))
        .with_state(state)
}
