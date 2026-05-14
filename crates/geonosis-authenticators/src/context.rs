//! `AuthnContext` — the slice of flow state that authenticators see.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::Value;

use geonosis_core::{Amr, Client, RealmId, SessionId, UserId};
use geonosis_storage::Storage;

/// Subset of `geonosis_flow::FlowContext` exposed to authenticators plus
/// the wired references they need (storage, signing keys, the current
/// realm + client). Authenticators do not touch unrelated flow state.
pub struct AuthnContext {
    pub realm_id: RealmId,
    pub client: Arc<Client>,
    pub storage: Arc<dyn Storage>,
    /// Per-realm BLAKE3-keyed hash key (refresh tokens share this).
    pub realm_hash_key: [u8; 32],
    /// Resolved user (if a prior step identified one).
    pub user_id: Option<UserId>,
    /// Existing SSO session id (if any).
    pub session_id: Option<SessionId>,
    /// AMR collected by previous nodes.
    pub amr: Vec<Amr>,
    /// Free-form locals stash (the rendered template gets these).
    pub locals: BTreeMap<String, Value>,
    /// Server clock at step entry — authenticators that need "now"
    /// must use this so tests can pin it.
    pub now: DateTime<Utc>,
}

impl AuthnContext {
    pub fn record_amr(&mut self, amr: Amr) {
        if !self.amr.contains(&amr) {
            self.amr.push(amr);
        }
    }
}
