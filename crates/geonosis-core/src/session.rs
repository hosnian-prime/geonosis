//! Browser SSO session entity.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::AuthnLevel;
use crate::id::{ClientId, RealmId, SessionId, UserId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    pub realm_id: RealmId,
    pub user_id: UserId,
    pub authn_level: AuthnLevel,
    pub idp_alias: Option<String>,
    pub started_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Per-application session participation (for SSO logout fan-out).
    pub clients: Vec<ClientSessionRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSessionRef {
    pub client_id: ClientId,
    pub last_seen_at: DateTime<Utc>,
    pub frontchannel_logout: bool,
    pub backchannel_logout: bool,
}
