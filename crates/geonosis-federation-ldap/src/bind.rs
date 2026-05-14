//! Simple-bind credential validation for federated users.

use ldap3::Scope;

use crate::error::LdapError;
use crate::pool::LdapPool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindOutcome {
    /// User's DN was located and BIND with the supplied password succeeded.
    Success,
    /// DN exists; password rejected by the server.
    InvalidCredential,
    /// DN not found.
    NotFound,
}

/// Validate `username` + `password` against the federated source.
///
/// Two-phase: a service-account bind locates the user DN (per
/// `cfg.user_filter`), then a second connection issues a simple BIND
/// with the supplied password. We don't reuse the search connection
/// because re-binding the same connection invalidates the original
/// authentication on most LDAP servers.
pub async fn bind_as_user(
    pool: &LdapPool,
    username: &str,
    password: &str,
) -> Result<BindOutcome, LdapError> {
    let cfg = pool.config();
    let filter = cfg.render_user_filter(username);

    // Phase 1: locate DN under service-account credentials.
    let mut probe = pool.acquire().await?;
    let timeout = cfg.search_timeout();
    let (rs, _res) = tokio::time::timeout(
        timeout,
        probe.ldap.search(&cfg.base_dn, Scope::Subtree, &filter, vec!["dn"]),
    )
    .await
    .map_err(|_| LdapError::Timeout {
        ms: cfg.search_timeout_ms,
    })?
    .map_err(LdapError::from)?
    .success()
    .map_err(LdapError::from)?;

    let dn = match rs.into_iter().next() {
        Some(e) => ldap3::SearchEntry::construct(e).dn,
        None => return Ok(BindOutcome::NotFound),
    };
    let _ = probe.ldap.unbind().await;
    drop(probe);

    // Phase 2: bind as that DN to verify the password.
    let mut user_conn = pool.acquire().await?;
    let bind_timeout = cfg.bind_timeout();
    let bind_res =
        tokio::time::timeout(bind_timeout, user_conn.ldap.simple_bind(&dn, password))
            .await
            .map_err(|_| LdapError::Timeout {
                ms: cfg.bind_timeout_ms,
            })?
            .map_err(LdapError::from)?;
    let _ = user_conn.ldap.unbind().await;

    match bind_res.rc {
        0 => Ok(BindOutcome::Success),
        // 49 = invalidCredentials per RFC 4511 §4.2.
        49 => Ok(BindOutcome::InvalidCredential),
        rc => Err(LdapError::Bind(format!("rc={rc} {}", bind_res.text))),
    }
}
