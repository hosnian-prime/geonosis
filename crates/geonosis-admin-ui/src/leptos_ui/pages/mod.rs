//! Admin console pages. Each module is the view layer for one
//! entity (or one top-level concern). The route handlers in
//! `leptos_ui::router` load the data, build the page context, and
//! invoke the matching component.

pub mod agents;
pub mod clients;
pub mod events;
pub mod federation;
pub mod flows;
pub mod groups;
pub mod idps;
pub mod keys;
pub mod orgs;
pub mod profile;
pub mod realm_detail;
pub mod realm_settings;
pub mod realms;
pub mod roles;
pub mod sessions;
pub mod spi;
pub mod user_profile_schema;
pub mod users;
