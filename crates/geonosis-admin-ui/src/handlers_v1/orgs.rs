//! `/admin/v1/realms/:slug/orgs` — Organizations + domains + memberships +
//! invitations + per-org roles + consent policies + IdP bindings.
//!
//! Per doc 15: Organizations are sub-tenants inside a realm. The
//! handlers here always scope every operation to the realm extracted
//! from the path and re-resolve the org by alias under that realm.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;

use geonosis_core::id::{OrgDomainId, OrgInvitationId, OrgRoleId};
use geonosis_core::organization::OrganizationBranding;
use geonosis_core::{
    ClientId, MembershipState, OrgConsentMode, OrgConsentPolicy, OrgDomain, OrgInvitation,
    OrgMembership, OrgPermission, OrgRole, Organization, Secret, UserId,
};
use geonosis_storage::traits::OrgIdpBinding;

use crate::handlers_v1::extractors::realm_by_slug;
use crate::state::{AdminError, AdminState};

// ---------- Organization CRUD ----------

#[derive(Debug, Deserialize)]
pub struct CreateOrgRequest {
    pub alias: String,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub branding: OrganizationBranding,
    #[serde(default)]
    pub default_idp_alias: Option<String>,
    #[serde(default)]
    pub redirect_url: Option<url::Url>,
}

pub async fn list(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Json<Vec<Organization>>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let orgs = state
        .storage
        .list_organizations(realm.id)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(orgs))
}

pub async fn create(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Json(req): Json<CreateOrgRequest>,
) -> Result<Json<Organization>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let now = chrono::Utc::now();
    let org = Organization {
        id: geonosis_core::OrganizationId::new(),
        realm_id: realm.id,
        alias: req.alias,
        display_name: req.display_name,
        description: req.description,
        attributes: BTreeMap::new(),
        branding: req.branding,
        default_idp_alias: req.default_idp_alias,
        redirect_url: req.redirect_url,
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    state
        .storage
        .create_organization(org.clone())
        .await
        .map_err(AdminError::from)?;
    Ok(Json(org))
}

pub async fn get(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
) -> Result<Json<Organization>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let org = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(org))
}

pub async fn update(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
    Json(mut org): Json<Organization>,
) -> Result<Json<Organization>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let existing = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    org.id = existing.id;
    org.realm_id = realm.id;
    org.created_at = existing.created_at;
    org.updated_at = chrono::Utc::now();
    state
        .storage
        .update_organization(org.clone())
        .await
        .map_err(AdminError::from)?;
    Ok(Json(org))
}

pub async fn delete_(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
) -> Result<axum::http::StatusCode, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let existing = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    state
        .storage
        .delete_organization(realm.id, existing.id)
        .await
        .map_err(AdminError::from)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------- Domains ----------

#[derive(Debug, Deserialize)]
pub struct AddDomainRequest {
    pub domain: String,
}

pub async fn list_domains(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
) -> Result<Json<Vec<OrgDomain>>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let org = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    let domains = state
        .storage
        .list_org_domains(realm.id, org.id)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(domains))
}

pub async fn add_domain(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
    Json(req): Json<AddDomainRequest>,
) -> Result<Json<OrgDomain>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let org = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    let token = generate_verification_token();
    let domain = OrgDomain {
        id: OrgDomainId::new(),
        organization_id: org.id,
        realm_id: realm.id,
        domain: req.domain.to_ascii_lowercase(),
        verified: false,
        verification_token: Some(token),
        verified_at: None,
    };
    state
        .storage
        .upsert_org_domain(domain.clone())
        .await
        .map_err(AdminError::from)?;
    Ok(Json(domain))
}

pub async fn remove_domain(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias, domain)): Path<(String, String, String)>,
) -> Result<axum::http::StatusCode, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let org = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    state
        .storage
        .delete_org_domain(realm.id, org.id, &domain.to_ascii_lowercase())
        .await
        .map_err(AdminError::from)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub async fn mark_domain_verified(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias, domain)): Path<(String, String, String)>,
) -> Result<Json<OrgDomain>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let org = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    let mut domains = state
        .storage
        .list_org_domains(realm.id, org.id)
        .await
        .map_err(AdminError::from)?;
    let domain_l = domain.to_ascii_lowercase();
    let target = domains
        .iter_mut()
        .find(|d| d.domain == domain_l)
        .ok_or(AdminError::NotFound)?;
    target.verified = true;
    target.verified_at = Some(chrono::Utc::now());
    target.verification_token = None;
    state
        .storage
        .upsert_org_domain(target.clone())
        .await
        .map_err(AdminError::from)?;
    Ok(Json(target.clone()))
}

// ---------- Memberships ----------

#[derive(Debug, Deserialize)]
pub struct AddMemberRequest {
    pub user_id: UserId,
    #[serde(default)]
    pub roles: Vec<OrgRoleId>,
}

pub async fn list_memberships(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
) -> Result<Json<Vec<OrgMembership>>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let org = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    let m = state
        .storage
        .list_org_memberships(realm.id, org.id)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(m))
}

pub async fn add_member(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
    Json(req): Json<AddMemberRequest>,
) -> Result<Json<OrgMembership>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let org = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    let membership = OrgMembership {
        organization_id: org.id,
        realm_id: realm.id,
        user_id: req.user_id,
        roles: req.roles,
        joined_at: chrono::Utc::now(),
        invited_by: None,
        state: MembershipState::Active,
    };
    state
        .storage
        .upsert_org_membership(membership.clone())
        .await
        .map_err(AdminError::from)?;
    Ok(Json(membership))
}

pub async fn remove_member(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias, user_id)): Path<(String, String, UserId)>,
) -> Result<axum::http::StatusCode, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let org = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    state
        .storage
        .delete_org_membership(realm.id, org.id, user_id)
        .await
        .map_err(AdminError::from)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------- Invitations ----------

#[derive(Debug, Deserialize)]
pub struct CreateInvitationRequest {
    pub email: String,
    #[serde(default)]
    pub roles: Vec<OrgRoleId>,
    pub invited_by: UserId,
    #[serde(default = "default_invitation_ttl_days")]
    pub expires_in_days: i64,
}

fn default_invitation_ttl_days() -> i64 {
    14
}

pub async fn list_invitations(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
) -> Result<Json<Vec<OrgInvitation>>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let org = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    let invs = state
        .storage
        .list_org_invitations(realm.id, org.id)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(invs))
}

pub async fn create_invitation(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
    Json(req): Json<CreateInvitationRequest>,
) -> Result<Json<OrgInvitation>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let org = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    let token = generate_invitation_token();
    let invitation = OrgInvitation {
        id: OrgInvitationId::new(),
        organization_id: org.id,
        realm_id: realm.id,
        email: req.email,
        roles: req.roles,
        invited_by: req.invited_by,
        token: Secret::new(token),
        expires_at: chrono::Utc::now() + chrono::Duration::days(req.expires_in_days),
        accepted_at: None,
    };
    state
        .storage
        .create_org_invitation(invitation.clone())
        .await
        .map_err(AdminError::from)?;
    Ok(Json(invitation))
}

pub async fn accept_invitation(
    State(state): State<Arc<AdminState>>,
    Path((_slug, _alias, token)): Path<(String, String, String)>,
) -> Result<Json<OrgInvitation>, AdminError> {
    let invitation = state
        .storage
        .get_org_invitation_by_token(&token)
        .await
        .map_err(AdminError::from)?;
    if invitation.expires_at < chrono::Utc::now() {
        return Err(AdminError::Storage("invitation expired".into()));
    }
    state
        .storage
        .mark_org_invitation_accepted(invitation.id)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(invitation))
}

// ---------- Org-scoped roles ----------

#[derive(Debug, Deserialize)]
pub struct CreateOrgRoleRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub permissions: Vec<OrgPermission>,
}

pub async fn list_roles(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
) -> Result<Json<Vec<OrgRole>>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let org = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    let roles = state
        .storage
        .list_org_roles(realm.id, org.id)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(roles))
}

pub async fn create_role(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
    Json(req): Json<CreateOrgRoleRequest>,
) -> Result<Json<OrgRole>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let org = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    let role = OrgRole {
        id: OrgRoleId::new(),
        organization_id: org.id,
        realm_id: realm.id,
        name: req.name,
        description: req.description,
        permissions: req.permissions,
        built_in: false,
    };
    state
        .storage
        .create_org_role(role.clone())
        .await
        .map_err(AdminError::from)?;
    Ok(Json(role))
}

pub async fn update_role(
    State(state): State<Arc<AdminState>>,
    Path((slug, _alias, role_id)): Path<(String, String, OrgRoleId)>,
    Json(mut role): Json<OrgRole>,
) -> Result<Json<OrgRole>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let existing = state
        .storage
        .get_org_role(realm.id, role_id)
        .await
        .map_err(AdminError::from)?;
    role.id = existing.id;
    role.realm_id = realm.id;
    role.organization_id = existing.organization_id;
    role.built_in = existing.built_in;
    state
        .storage
        .update_org_role(role.clone())
        .await
        .map_err(AdminError::from)?;
    Ok(Json(role))
}

pub async fn delete_role(
    State(state): State<Arc<AdminState>>,
    Path((slug, _alias, role_id)): Path<(String, String, OrgRoleId)>,
) -> Result<axum::http::StatusCode, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let existing = state
        .storage
        .get_org_role(realm.id, role_id)
        .await
        .map_err(AdminError::from)?;
    if existing.built_in {
        return Err(AdminError::Storage(
            "built-in org roles cannot be deleted".into(),
        ));
    }
    state
        .storage
        .delete_org_role(realm.id, role_id)
        .await
        .map_err(AdminError::from)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------- Org-level consent policies ----------

#[derive(Debug, Deserialize)]
pub struct UpsertConsentPolicyRequest {
    pub client_id: ClientId,
    pub mode: OrgConsentMode,
    #[serde(default)]
    pub pre_approved_scopes: Vec<geonosis_core::ScopeName>,
    #[serde(default)]
    pub blocked_scopes: Vec<geonosis_core::ScopeName>,
    #[serde(default)]
    pub require_admin_approval: bool,
    pub created_by: UserId,
}

pub async fn list_consent_policies(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
) -> Result<Json<Vec<OrgConsentPolicy>>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let org = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    let policies = state
        .storage
        .list_org_consent_policies(realm.id, org.id)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(policies))
}

pub async fn upsert_consent_policy(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
    Json(req): Json<UpsertConsentPolicyRequest>,
) -> Result<Json<OrgConsentPolicy>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let org = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    let now = chrono::Utc::now();
    let policy = OrgConsentPolicy {
        id: geonosis_core::ConsentGrantId::new(),
        organization_id: org.id,
        realm_id: realm.id,
        client_id: req.client_id,
        mode: req.mode,
        pre_approved_scopes: req.pre_approved_scopes,
        blocked_scopes: req.blocked_scopes,
        require_admin_approval: req.require_admin_approval,
        created_by: req.created_by,
        created_at: now,
        updated_at: now,
    };
    state
        .storage
        .upsert_org_consent_policy(policy.clone())
        .await
        .map_err(AdminError::from)?;
    Ok(Json(policy))
}

pub async fn delete_consent_policy(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias, client_id)): Path<(String, String, ClientId)>,
) -> Result<axum::http::StatusCode, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let org = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    state
        .storage
        .delete_org_consent_policy(realm.id, org.id, client_id)
        .await
        .map_err(AdminError::from)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------- Per-org IdP bindings ----------

#[derive(Debug, Deserialize)]
pub struct UpsertIdpBindingRequest {
    pub idp_alias: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default = "true_default")]
    pub enabled: bool,
}

fn true_default() -> bool {
    true
}

#[derive(Debug, serde::Serialize)]
pub struct IdpBindingView {
    pub idp_alias: String,
    pub priority: i32,
    pub enabled: bool,
}

impl From<OrgIdpBinding> for IdpBindingView {
    fn from(b: OrgIdpBinding) -> Self {
        Self {
            idp_alias: b.idp_alias,
            priority: b.priority,
            enabled: b.enabled,
        }
    }
}

pub async fn list_idp_bindings(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
) -> Result<Json<Vec<IdpBindingView>>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let org = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    let bindings = state
        .storage
        .list_org_idp_bindings(realm.id, org.id)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(bindings.into_iter().map(IdpBindingView::from).collect()))
}

pub async fn upsert_idp_binding(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
    Json(req): Json<UpsertIdpBindingRequest>,
) -> Result<Json<IdpBindingView>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let org = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    let binding = OrgIdpBinding {
        organization_id: org.id,
        realm_id: realm.id,
        idp_alias: req.idp_alias,
        priority: req.priority,
        enabled: req.enabled,
    };
    state
        .storage
        .upsert_org_idp_binding(binding.clone())
        .await
        .map_err(AdminError::from)?;
    Ok(Json(binding.into()))
}

pub async fn remove_idp_binding(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias, idp_alias)): Path<(String, String, String)>,
) -> Result<axum::http::StatusCode, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let org = state
        .storage
        .get_organization_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    state
        .storage
        .delete_org_idp_binding(realm.id, org.id, &idp_alias)
        .await
        .map_err(AdminError::from)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------- Helpers ----------

fn generate_verification_token() -> String {
    // 32-char base32 token; matches the SessionId entropy and is
    // accepted as a DNS TXT challenge value.
    geonosis_core::id::SessionId::new_random().0
}

fn generate_invitation_token() -> String {
    // Separate function so the audit log distinguishes invitation
    // tokens from domain-verification tokens even though they're the
    // same shape today.
    geonosis_core::id::SessionId::new_random().0
}
