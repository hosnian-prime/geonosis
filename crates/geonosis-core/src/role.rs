//! Role + composite role.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::attribute::AttributeValue;
use crate::id::{ClientId, RealmId, RoleId};

/// A role (realm-level or client-level).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub realm_id: RealmId,
    /// `None` => realm role. `Some` => client-scoped role.
    pub client_id: Option<ClientId>,
    pub name: String,
    pub description: Option<String>,
    /// Composite-role expansion. Empty for leaf roles.
    pub composites: CompositeRoles,
    /// Role attributes (consumed by built-in mappers).
    pub attributes: BTreeMap<String, AttributeValue>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompositeRoles {
    pub realm_roles: Vec<RoleId>,
    pub client_roles: BTreeMap<String, Vec<RoleId>>,
}
