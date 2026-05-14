//! Full + incremental sync runs.
//!
//! `run_full_sync` walks the entire `(base_dn, user_filter)` tree and
//! emits one `SyncOutcome` per user. The caller (typically `geoctl
//! federation sync`) decides whether the entity already exists locally
//! and dispatches insert vs update.
//!
//! `run_incremental_sync` narrows the filter with `changed_attribute
//! >= since`, suitable for cron-driven incremental jobs.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use ldap3::{Scope, SearchEntry};
use serde::{Deserialize, Serialize};

use geonosis_core::id::RealmId;
use geonosis_core::user::User;

use crate::error::LdapError;
use crate::mapper::{entry_to_user, EntryAttributes};
use crate::pool::LdapPool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncReport {
    pub scanned: usize,
    pub mapped: usize,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SyncOutcome {
    pub user: User,
    pub dn: String,
    pub groups: Vec<String>,
}

/// Yield every user under the configured `base_dn` matching
/// `user_filter`. Caller collects.
pub async fn run_full_sync(
    pool: &LdapPool,
    realm_id: RealmId,
) -> Result<(SyncReport, Vec<SyncOutcome>), LdapError> {
    let cfg = pool.config();
    let started = Utc::now();
    let filter = cfg
        .user_filter
        // `geoctl federation sync` walks the entire tree; the
        // username placeholder is replaced by the wildcard form.
        .replace("{username}", "*");
    let attrs = {
        let mut a = cfg.attribute_map.request_attrs();
        if let Some(gs) = &cfg.group_sync {
            a.push(gs.membership_attribute.clone());
        }
        a
    };
    let outcomes = paged_search(pool, &filter, &attrs, realm_id).await?;
    let report = SyncReport {
        scanned: outcomes.len(),
        mapped: outcomes.len(),
        started_at: started,
        finished_at: Utc::now(),
    };
    Ok((report, outcomes))
}

/// Walk only entries whose `changed_attribute` is ≥ `since`. Returns
/// `Err(LdapError::Other)` when the source is configured `OnDemand`
/// (no `changed_attribute` is set).
pub async fn run_incremental_sync(
    pool: &LdapPool,
    realm_id: RealmId,
    since: DateTime<Utc>,
) -> Result<(SyncReport, Vec<SyncOutcome>), LdapError> {
    let cfg = pool.config();
    let attr = match &cfg.sync_policy {
        crate::config::SyncPolicy::Periodic {
            changed_attribute, ..
        } => changed_attribute.clone(),
        crate::config::SyncPolicy::OnDemand => {
            return Err(LdapError::Other(
                "incremental sync requires SyncPolicy::Periodic".into(),
            ));
        }
    };
    let started = Utc::now();
    // Generalized Time per RFC 4517 §3.3.13 — `YYYYMMDDHHMMSSZ`.
    let since_gt = since.format("%Y%m%d%H%M%SZ").to_string();
    let filter = format!("(&{}({attr}>={since_gt}))", cfg.render_user_filter("*"),);
    let attrs = {
        let mut a = cfg.attribute_map.request_attrs();
        if let Some(gs) = &cfg.group_sync {
            a.push(gs.membership_attribute.clone());
        }
        a
    };
    let outcomes = paged_search(pool, &filter, &attrs, realm_id).await?;
    let report = SyncReport {
        scanned: outcomes.len(),
        mapped: outcomes.len(),
        started_at: started,
        finished_at: Utc::now(),
    };
    Ok((report, outcomes))
}

/// AD tombstone detection (`docs/04-federation-ldap.md` §"Tombstones").
/// Queries `CN=Deleted Objects,…` with the show-deleted control and
/// emits one `(external_id, external_dn)` per tombstoned entry. Caller
/// flips the local row to `enabled=false`.
///
/// v0.1 implementation note: the show-deleted control is signaled
/// implicitly by scoping the base DN inside the deleted-objects
/// container; full LDAP_SERVER_SHOW_DELETED_OID control marshalling
/// lands with the upcoming `ldap3` control-options API.
pub async fn detect_tombstones(
    pool: &LdapPool,
    since: DateTime<Utc>,
) -> Result<Vec<TombstonedEntry>, LdapError> {
    let cfg = pool.config();
    let base = format!("CN=Deleted Objects,{}", cfg.base_dn);
    let since_gt = since.format("%Y%m%d%H%M%SZ").to_string();
    let filter = format!("(&(isDeleted=TRUE)(whenChanged>={since_gt}))");
    let attrs = vec![cfg.attribute_map.uid.clone(), "distinguishedName".into()];

    let mut conn = pool.acquire().await?;
    let result = tokio::time::timeout(
        cfg.search_timeout(),
        conn.ldap.search(&base, Scope::Subtree, &filter, attrs),
    )
    .await
    .map_err(|_| LdapError::Timeout {
        ms: cfg.search_timeout_ms,
    })?;
    // Tombstoned-objects containers don't exist on non-AD servers;
    // surface "not found" as an empty list, not an error.
    let (rs, _) = match result {
        Ok(r) => match r.success() {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "tombstone scan returned non-success");
                return Ok(Vec::new());
            }
        },
        Err(e) => {
            tracing::debug!(error = %e, "tombstone scan failed");
            return Ok(Vec::new());
        }
    };
    let mut out = Vec::new();
    for raw in rs {
        let entry = SearchEntry::construct(raw);
        let dn = entry.dn.clone();
        if let Some(uid) = entry
            .attrs
            .get(&cfg.attribute_map.uid)
            .and_then(|v| v.first())
            .cloned()
        {
            out.push(TombstonedEntry {
                external_id: uid,
                external_dn: dn,
            });
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TombstonedEntry {
    pub external_id: String,
    pub external_dn: String,
}

async fn paged_search(
    pool: &LdapPool,
    filter: &str,
    attrs: &[String],
    realm_id: RealmId,
) -> Result<Vec<SyncOutcome>, LdapError> {
    let cfg = pool.config();
    let mut conn = pool.acquire().await?;
    let (rs, _) = tokio::time::timeout(
        cfg.search_timeout(),
        conn.ldap
            .search(&cfg.base_dn, Scope::Subtree, filter, attrs.to_vec()),
    )
    .await
    .map_err(|_| LdapError::Timeout {
        ms: cfg.search_timeout_ms,
    })?
    .map_err(LdapError::from)?
    .success()
    .map_err(LdapError::from)?;

    let mut out = Vec::new();
    for raw in rs {
        let entry = SearchEntry::construct(raw);
        let dn = entry.dn.clone();
        let groups = match &cfg.group_sync {
            Some(gs) => entry
                .attrs
                .get(&gs.membership_attribute)
                .cloned()
                .unwrap_or_default(),
            None => Vec::new(),
        };
        let typed = EntryAttributes {
            dn: dn.clone(),
            values: entry.attrs.into_iter().collect::<BTreeMap<_, _>>(),
        };
        if let Some(user) = entry_to_user(realm_id, &cfg.alias, &cfg.attribute_map, &typed) {
            out.push(SyncOutcome { user, dn, groups });
        }
    }
    Ok(out)
}
