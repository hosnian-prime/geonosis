//! Axum router that mounts the Leptos pages under `/admin-next/...`.
//!
//! Lives alongside the Maud-backed `/admin/...` routes during the
//! v0.1.x migration. Once every Maud page is ported, the legacy paths
//! retire and the Leptos paths take over `/admin/...`.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use leptos::prelude::*;

use crate::leptos_ui::pages::realms::{RealmRow, RealmsPage};
use crate::state::{AdminError, AdminState};

/// Build the Leptos sub-router. Composed into the main admin router by
/// `geonosis_admin_ui::router`.
pub fn leptos_router(state: Arc<AdminState>) -> Router {
    Router::new()
        .route("/admin-next/realms", get(page_realms))
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
