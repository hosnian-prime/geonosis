//! User + group lookups against the federated source.

use std::collections::BTreeMap;

use ldap3::{Scope, SearchEntry};

use geonosis_core::id::RealmId;
use geonosis_core::user::User;

use crate::error::LdapError;
use crate::mapper::{entry_to_user, EntryAttributes};
use crate::pool::LdapPool;

/// Outcome of a user-lookup search — the typed `User` (when the
/// configured attribute map can produce one) plus the raw entry.
pub struct SearchedUser {
    pub user: User,
    pub dn: String,
    pub groups: Vec<String>,
}

/// Find a single user by username. Returns `Ok(None)` when no entry
/// matches; reserved for the `FirstMatch` provider chain to delegate
/// to the next storage provider.
pub async fn find_user(
    pool: &LdapPool,
    realm_id: RealmId,
    username: &str,
) -> Result<Option<SearchedUser>, LdapError> {
    let cfg = pool.config();
    let filter = cfg.render_user_filter(username);
    let attrs = cfg.attribute_map.request_attrs();
    let mut attrs_with_membership = attrs.clone();
    if let Some(gs) = &cfg.group_sync {
        attrs_with_membership.push(gs.membership_attribute.clone());
    }

    let mut conn = pool.acquire().await?;
    let (rs, _res) = tokio::time::timeout(
        cfg.search_timeout(),
        conn.ldap.search(
            &cfg.base_dn,
            Scope::Subtree,
            &filter,
            attrs_with_membership.clone(),
        ),
    )
    .await
    .map_err(|_| LdapError::Timeout {
        ms: cfg.search_timeout_ms,
    })?
    .map_err(LdapError::from)?
    .success()
    .map_err(LdapError::from)?;

    let mut iter = rs.into_iter();
    let Some(raw) = iter.next() else {
        return Ok(None);
    };
    let entry = SearchEntry::construct(raw);
    let groups = if let Some(gs) = &cfg.group_sync {
        entry
            .attrs
            .get(&gs.membership_attribute)
            .cloned()
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let dn = entry.dn.clone();
    let typed_entry = EntryAttributes {
        dn: dn.clone(),
        values: entry.attrs.into_iter().collect::<BTreeMap<_, _>>(),
    };
    let user = entry_to_user(realm_id, &cfg.alias, &cfg.attribute_map, &typed_entry)
        .ok_or(LdapError::NotFound)?;
    Ok(Some(SearchedUser { user, dn, groups }))
}

/// Resolve a list of group DNs into human-readable group names using
/// the configured `group_name_attribute`. Used by the sync path to
/// project memberOf -> Geonosis group names.
pub async fn search_groups(
    pool: &LdapPool,
    group_dns: &[String],
) -> Result<Vec<String>, LdapError> {
    let cfg = pool.config();
    let Some(gs) = &cfg.group_sync else {
        return Ok(Vec::new());
    };
    if group_dns.is_empty() {
        return Ok(Vec::new());
    }

    let mut conn = pool.acquire().await?;
    let mut names = Vec::with_capacity(group_dns.len());
    for dn in group_dns {
        let (rs, _res) = tokio::time::timeout(
            cfg.search_timeout(),
            conn.ldap.search(
                dn,
                Scope::Base,
                &gs.group_filter,
                vec![gs.group_name_attribute.clone()],
            ),
        )
        .await
        .map_err(|_| LdapError::Timeout {
            ms: cfg.search_timeout_ms,
        })?
        .map_err(LdapError::from)?
        .success()
        .map_err(LdapError::from)?;

        if let Some(raw) = rs.into_iter().next() {
            let e = SearchEntry::construct(raw);
            if let Some(vals) = e.attrs.get(&gs.group_name_attribute) {
                if let Some(name) = vals.first() {
                    names.push(name.clone());
                }
            }
        }
    }
    Ok(names)
}
