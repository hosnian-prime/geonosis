//! Reusable extractors + small helpers for the v1 REST handlers.
//!
//! The realm lookup is the single piece of shared work every endpoint
//! does, so it lives here. Pulling it out keeps each handler focused
//! on its entity, and centralizes the storage error → HTTP mapping.

use std::sync::Arc;

use axum::extract::{Path, State};

use geonosis_core::Realm;
use geonosis_storage::Storage;

use crate::state::{AdminError, AdminState};

/// Look up a realm by URL-path slug. Returns `AdminError::NotFound`
/// (→ HTTP 404) when missing; the storage layer's `StorageError`
/// already maps cleanly via the `From` impl on `AdminError`.
pub async fn realm_by_slug(
    state: &Arc<AdminState>,
    slug: &str,
) -> Result<Realm, AdminError> {
    state
        .storage
        .get_realm_by_slug(slug)
        .await
        .map_err(AdminError::from)
}

/// Convenience wrapper: the most common axum extractor signature for
/// our handlers. Pull the realm slug from the path and resolve it.
///
/// Used wherever a handler only needs the realm and nothing else.
pub async fn realm_only(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<(Arc<AdminState>, Realm), AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    Ok((state, realm))
}

/// Storage accessor so handler modules don't need to know about the
/// concrete `Storage` dyn pointer shape.
pub fn storage(state: &Arc<AdminState>) -> &dyn Storage {
    state.storage.as_ref()
}
