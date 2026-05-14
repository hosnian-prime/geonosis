//! Organization (B2B SaaS sub-tenant) entities.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::attribute::AttributeValue;
use crate::id::{
    ClientId, OrgDomainId, OrgInvitationId, OrgRoleId, OrganizationId, RealmId, UserId,
};
use crate::scope::ScopeName;
use crate::secret::Secret;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: OrganizationId,
    pub realm_id: RealmId,
    /// Stable URL-safe alias.
    pub alias: String,
    pub display_name: String,
    pub description: Option<String>,
    pub attributes: BTreeMap<String, AttributeValue>,
    pub branding: OrganizationBranding,
    pub default_idp_alias: Option<String>,
    pub redirect_url: Option<Url>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrganizationBranding {
    pub logo_url: Option<Url>,
    pub primary_color: Option<String>,
    pub theme: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgDomain {
    pub id: OrgDomainId,
    pub organization_id: OrganizationId,
    pub realm_id: RealmId,
    pub domain: String,
    pub verified: bool,
    pub verification_token: Option<String>,
    pub verified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgMembership {
    pub organization_id: OrganizationId,
    pub realm_id: RealmId,
    pub user_id: UserId,
    pub roles: Vec<OrgRoleId>,
    pub joined_at: DateTime<Utc>,
    pub invited_by: Option<UserId>,
    pub state: MembershipState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MembershipState {
    Active,
    Invited,
    Suspended,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgInvitation {
    pub id: OrgInvitationId,
    pub organization_id: OrganizationId,
    pub realm_id: RealmId,
    pub email: String,
    pub roles: Vec<OrgRoleId>,
    pub invited_by: UserId,
    pub token: Secret<String>,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgRole {
    pub id: OrgRoleId,
    pub organization_id: OrganizationId,
    pub realm_id: RealmId,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<OrgPermission>,
    /// Seeded roles (`owner`/`admin`/`member`) cannot be deleted.
    pub built_in: bool,
}

/// Org-scoped permissions. `Admin` implies all others.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OrgPermission {
    Admin,
    InviteMembers,
    ManageDomains,
    ManageIdps,
    ManageRoles,
    ManageConsent,
    ViewMembers,
    #[serde(untagged)]
    Custom(String),
}

/// How consent is handled for a client inside an organization context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgConsentPolicy {
    pub id: crate::id::ConsentGrantId,
    pub organization_id: OrganizationId,
    pub realm_id: RealmId,
    pub client_id: ClientId,
    pub mode: OrgConsentMode,
    pub pre_approved_scopes: Vec<ScopeName>,
    pub blocked_scopes: Vec<ScopeName>,
    pub require_admin_approval: bool,
    pub created_by: UserId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OrgConsentMode {
    /// Standard per-user prompt.
    UserDecides,
    /// Pre-approved scopes skip the prompt.
    OrgPreApproved,
    /// Admin decides for all org members; no user prompt.
    OrgManaged,
}

/// Realm-level toggle for whether Organizations are usable at all.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrganizationPolicy {
    pub default_invitation_ttl_days: u32,
    pub default_role_for_self_signup: Option<String>,
    pub require_domain_verification: bool,
    /// When `true`, a user whose verified email matches a verified
    /// `OrgDomain` is automatically enrolled into that organization at
    /// first login. Per `docs/15-organizations.md` §"Self-service join
    /// via domain match" (lines 115-118). Default `false` — admins
    /// must opt in.
    #[serde(default)]
    pub auto_join_on_domain_match: bool,
}
