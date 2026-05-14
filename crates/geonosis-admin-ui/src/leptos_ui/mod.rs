//! Leptos-based admin UI surface.
//!
//! v0.1.x bring-up plan (this module is the entry):
//! - Phase 0.5 (this commit): mount Leptos alongside Maud under
//!   `/admin-next/...` paths. Single proof-of-concept page (realms list)
//!   rendered server-side; no hydration islands yet.
//! - Phase 3: port each Maud page to a Leptos `#[component]`, swap
//!   `/admin/...` → `/admin-next/...` host paths, retire Maud handlers.
//! - Phase 3+: add hydration islands for interactive surfaces
//!   (flow editor canvas, live event explorer).
//!
//! Rendering strategy: `leptos::ssr::render_to_string` produces a
//! complete document string we wrap in `axum::response::Html`. This is
//! the same shape `geonosis-admin-ui::handlers` already returns for the
//! Maud pages, so the security-headers + CSP middleware applies
//! uniformly.

pub mod app;
pub mod components;
pub mod pages;
pub mod router;

pub use router::leptos_router;
