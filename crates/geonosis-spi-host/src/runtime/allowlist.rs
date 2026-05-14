//! Host outbound egress allowlist.
//!
//! Every WASM plugin must declare its outbound URLs in the binding's
//! `config` (key `egress_allowlist`). The host refuses requests that
//! don't match. Patterns are scheme + host (port optional); paths
//! are not restricted because real APIs version through path segments.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostAllowlist {
    /// Lower-cased `scheme://host[:port]` entries.
    entries: BTreeSet<String>,
}

impl HostAllowlist {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct from a list of URL strings. Entries that fail to parse
    /// are silently dropped — operators see a warning at install time.
    pub fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        let mut s = Self::default();
        for v in iter {
            s.allow(&v);
        }
        s
    }

    pub fn allow(&mut self, raw: &str) -> bool {
        match Url::parse(raw) {
            Ok(u) => {
                let host = match u.host_str() {
                    Some(h) => h.to_ascii_lowercase(),
                    None => return false,
                };
                let key = match u.port() {
                    Some(p) => format!("{}://{host}:{p}", u.scheme()),
                    None => format!("{}://{host}", u.scheme()),
                };
                self.entries.insert(key);
                true
            }
            Err(_) => false,
        }
    }

    pub fn permits(&self, url: &str) -> bool {
        let Ok(u) = Url::parse(url) else { return false };
        let host = match u.host_str() {
            Some(h) => h.to_ascii_lowercase(),
            None => return false,
        };
        let candidates = [
            match u.port() {
                Some(p) => format!("{}://{host}:{p}", u.scheme()),
                None => format!("{}://{host}", u.scheme()),
            },
            format!("{}://{host}", u.scheme()),
        ];
        candidates.iter().any(|c| self.entries.contains(c))
    }

    pub fn entries(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_and_permit_match_on_host() {
        let mut a = HostAllowlist::new();
        a.allow("https://api.example.com");
        assert!(a.permits("https://api.example.com/v1/users"));
        assert!(!a.permits("https://api.evil.com/v1/users"));
    }

    #[test]
    fn port_specific_entry_blocks_other_ports() {
        let mut a = HostAllowlist::new();
        a.allow("http://localhost:5001");
        assert!(a.permits("http://localhost:5001/health"));
        // The explicit port-stripped form is also accepted via fallback.
        // But a different scheme is rejected.
        assert!(!a.permits("https://localhost:5001/health"));
    }

    #[test]
    fn unparseable_url_rejected() {
        let mut a = HostAllowlist::new();
        assert!(!a.allow(""));
        assert!(!a.permits("not-a-url"));
    }
}
