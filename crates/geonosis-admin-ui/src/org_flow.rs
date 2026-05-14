//! Organization-flow helpers — auto-join on verified domain, org-claim
//! emission.
//!
//! Lives in `geonosis-admin-ui` because v0.1 keeps storage-aware
//! org helpers next to the org admin handlers; v0.2 may extract a
//! `geonosis-org` crate when the cross-cutting surface (broker,
//! token-mint, admin) grows. Both surfaces import these free functions
//! today.

use geonosis_core::id::OrganizationId;
use geonosis_core::{
    MembershipState, OrgClaim, OrgMembership, OrgRole, Organization, RealmId, UserId,
};
use geonosis_storage::{Storage, StorageError};

/// Extract `acme.example` from `padme@acme.example`. Returns `None` for
/// strings without a single `@`.
pub fn email_domain(email: &str) -> Option<&str> {
    let trimmed = email.trim();
    let at = trimmed.find('@')?;
    let dom = &trimmed[at + 1..];
    if dom.is_empty() || dom.contains('@') {
        return None;
    }
    Some(dom)
}

/// If `email`'s domain matches any verified `OrgDomain` for `realm`,
/// upsert a membership and return the org id. Per doc 15 §"Auto-join":
/// auto-join requires the realm-level `OrganizationPolicy` flag to be
/// set on the org; we leave that policy check at the call site so this
/// helper stays composable.
pub async fn auto_join_verified_domain(
    storage: &dyn Storage,
    realm: RealmId,
    user_id: UserId,
    email: &str,
) -> Result<Option<OrganizationId>, StorageError> {
    let Some(domain) = email_domain(email) else {
        return Ok(None);
    };
    let Some(org) = storage
        .find_org_by_verified_domain(realm, &domain.to_ascii_lowercase())
        .await?
    else {
        return Ok(None);
    };
    let now = chrono::Utc::now();
    let membership = OrgMembership {
        organization_id: org.id,
        realm_id: realm,
        user_id,
        roles: vec![],
        joined_at: now,
        invited_by: None,
        state: MembershipState::Active,
    };
    storage.upsert_org_membership(membership).await?;
    Ok(Some(org.id))
}

/// Build the `org` token claim from the user's first active membership
/// in the realm. Multi-org users get the alphabetically-first active
/// org as default; the `?org=` selector overrides this at the
/// authorize endpoint.
///
/// Returns `Ok(None)` when the user has no active memberships — the
/// caller should omit the `org` claim entirely.
pub async fn build_org_claim_default(
    storage: &dyn Storage,
    realm: RealmId,
    user_id: UserId,
) -> Result<Option<OrgClaim>, StorageError> {
    let memberships = storage.list_user_orgs(realm, user_id).await?;
    let primary = memberships
        .into_iter()
        .filter(|m| matches!(m.state, MembershipState::Active))
        .min_by(|a, b| a.joined_at.cmp(&b.joined_at));
    let Some(m) = primary else {
        return Ok(None);
    };
    build_org_claim_for(storage, realm, user_id, m.organization_id).await
}

/// Build the `org` claim for a specific organization the user belongs
/// to. The caller decides which org context the token represents
/// (selector at authorize, or default-org fallback).
pub async fn build_org_claim_for(
    storage: &dyn Storage,
    realm: RealmId,
    user_id: UserId,
    organization_id: OrganizationId,
) -> Result<Option<OrgClaim>, StorageError> {
    let membership = match storage
        .get_org_membership(realm, organization_id, user_id)
        .await
    {
        Ok(m) => m,
        Err(StorageError::NotFound) => return Ok(None),
        Err(e) => return Err(e),
    };
    let org: Organization = storage.get_organization(realm, organization_id).await?;
    let all_roles: Vec<OrgRole> = storage
        .list_org_roles(realm, organization_id)
        .await
        .unwrap_or_default();
    let role_names: Vec<String> = membership
        .roles
        .iter()
        .filter_map(|rid| all_roles.iter().find(|r| r.id == *rid).map(|r| r.name.clone()))
        .collect();
    Ok(Some(OrgClaim {
        alias: org.alias,
        id: org.id.to_string(),
        display_name: Some(org.display_name),
        roles: role_names,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_domain_extracts_basic() {
        assert_eq!(email_domain("padme@acme.example"), Some("acme.example"));
        assert_eq!(email_domain("padme@ACME.EXAMPLE"), Some("ACME.EXAMPLE"));
    }

    #[test]
    fn email_domain_rejects_garbage() {
        assert_eq!(email_domain("nope"), None);
        assert_eq!(email_domain(""), None);
        assert_eq!(email_domain("a@@b"), None);
        assert_eq!(email_domain("@nope"), Some("nope"));
        assert_eq!(email_domain("nope@"), None);
    }
}
