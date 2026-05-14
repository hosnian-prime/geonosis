//! OAuth scope names.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A single OAuth/OIDC scope name (RFC 6749 §3.3).
///
/// Permitted characters: `%x21 / %x23-5B / %x5D-7E` — but we apply a more
/// conservative subset matching what real-world IdPs accept.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScopeName(String);

#[derive(Debug, Error)]
#[error("invalid scope name: {0}")]
pub struct ScopeParseError(pub String);

impl ScopeName {
    pub fn new(s: impl Into<String>) -> Result<Self, ScopeParseError> {
        let s = s.into();
        if s.is_empty() || s.len() > 128 {
            return Err(ScopeParseError(s));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':' | '.' | '/' ))
        {
            return Err(ScopeParseError(s));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ScopeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ScopeName {
    type Err = ScopeParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// Parse a space-separated scope string into a deduplicated, ordered set.
pub fn parse_scope_string(s: &str) -> Result<Vec<ScopeName>, ScopeParseError> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    for tok in s.split_ascii_whitespace() {
        if seen.insert(tok.to_string()) {
            out.push(ScopeName::new(tok)?);
        }
    }
    Ok(out)
}

/// Render a scope vector as the space-separated form used by `scope=` params.
pub fn format_scope_string(scopes: &[ScopeName]) -> String {
    let mut out = String::new();
    for (i, s) in scopes.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(s.as_str());
    }
    out
}

/// A scope definition stored against a realm/client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub name: ScopeName,
    pub display_name: Option<String>,
    pub description: Option<String>,
    /// If true, the scope is offered as a "default" — granted without user
    /// consent prompt (system trust scope).
    pub default: bool,
    /// If true, prompted for consent if not in `default`.
    pub consent_required: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_format_roundtrip() {
        let s = "openid profile email";
        let scopes = parse_scope_string(s).unwrap();
        assert_eq!(scopes.len(), 3);
        assert_eq!(format_scope_string(&scopes), s);
    }

    #[test]
    fn dedupe_in_parse() {
        let scopes = parse_scope_string("openid openid profile").unwrap();
        assert_eq!(scopes.len(), 2);
    }

    #[test]
    fn invalid_chars_rejected() {
        assert!(ScopeName::new("a b").is_err());
        assert!(ScopeName::new("").is_err());
    }

    #[test]
    fn colon_and_slash_accepted_for_urn_like() {
        assert!(ScopeName::new("urn:agent:read").is_ok());
        assert!(ScopeName::new("api/read").is_ok());
    }
}
