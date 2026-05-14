//! Runtime-side error type. The config-only surface uses
//! `thiserror` for its `From`/`Display` plumbing; the runtime adds
//! `ldap3`-specific arms.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum LdapError {
    #[error("connect: {0}")]
    Connect(String),
    #[error("tls: {0}")]
    Tls(String),
    #[error("bind: {0}")]
    Bind(String),
    #[error("search: {0}")]
    Search(String),
    #[error("timeout after {ms}ms")]
    Timeout { ms: u64 },
    #[error("circuit open")]
    CircuitOpen,
    #[error("not found")]
    NotFound,
    #[error("pool exhausted")]
    PoolExhausted,
    #[error("other: {0}")]
    Other(String),
}

impl From<ldap3::LdapError> for LdapError {
    fn from(e: ldap3::LdapError) -> Self {
        // ldap3's error enum is non-exhaustive across releases, so we
        // pattern-match on the variants we care about by `Display`
        // shape and fall back to `Other` rather than coupling tightly.
        let msg = e.to_string();
        if msg.to_ascii_lowercase().contains("timeout") {
            LdapError::Timeout { ms: 0 }
        } else if msg.to_ascii_lowercase().contains("invalid credentials")
            || msg.to_ascii_lowercase().contains("invalidcredentials")
        {
            LdapError::Bind(msg)
        } else {
            LdapError::Connect(msg)
        }
    }
}
