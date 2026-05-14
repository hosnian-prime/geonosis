//! Hierarchical group.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::attribute::AttributeValue;
use crate::id::{GroupId, RealmId, RoleId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: GroupId,
    pub realm_id: RealmId,
    pub parent_id: Option<GroupId>,
    pub name: String,
    pub path: String,
    pub attributes: BTreeMap<String, AttributeValue>,
    /// Realm roles assigned to every member.
    pub realm_role_ids: Vec<RoleId>,
    /// Client-scoped roles assigned to every member.
    pub client_role_ids: BTreeMap<String, Vec<RoleId>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
