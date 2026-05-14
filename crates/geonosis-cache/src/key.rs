//! Cache key composition.
//!
//! All keys are tenanted by `RealmId`. The `CacheClass` discriminator keeps
//! distinct entity classes from colliding without verbose prefixes.

use std::fmt::{self, Write as _};

use serde::{Deserialize, Serialize};

use geonosis_core::id::RealmId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CacheClass {
    Realm,
    Client,
    Flow,
    Theme,
    Spi,
    Jwks,
    Idp,
    Federation,
    User,
    UserProfile,
    Organization,
    SamlMetadata,
    ScimTarget,
    Agent,
    Negative,
}

impl CacheClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Realm => "realm",
            Self::Client => "client",
            Self::Flow => "flow",
            Self::Theme => "theme",
            Self::Spi => "spi",
            Self::Jwks => "jwks",
            Self::Idp => "idp",
            Self::Federation => "federation",
            Self::User => "user",
            Self::UserProfile => "user-profile",
            Self::Organization => "organization",
            Self::SamlMetadata => "saml-metadata",
            Self::ScimTarget => "scim-target",
            Self::Agent => "agent",
            Self::Negative => "neg",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CacheKey {
    pub realm: RealmId,
    pub class: CacheClass,
    pub id: String,
}

impl CacheKey {
    pub fn new(realm: RealmId, class: CacheClass, id: impl Into<String>) -> Self {
        Self {
            realm,
            class,
            id: id.into(),
        }
    }
}

impl fmt::Display for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("g:")?;
        fmt::Display::fmt(&self.realm, f)?;
        f.write_char(':')?;
        f.write_str(self.class.as_str())?;
        f.write_char(':')?;
        f.write_str(&self.id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKeyPrefix {
    pub realm: RealmId,
    pub class: CacheClass,
}

impl CacheKeyPrefix {
    pub fn new(realm: RealmId, class: CacheClass) -> Self {
        Self { realm, class }
    }

    pub fn matches(&self, key: &CacheKey) -> bool {
        key.realm == self.realm && key.class == self.class
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_renders_with_class() {
        let realm = RealmId::new();
        let k = CacheKey::new(realm, CacheClass::Client, "abc");
        let s = k.to_string();
        assert!(s.starts_with("g:"));
        assert!(s.contains(":client:abc"));
    }

    #[test]
    fn prefix_matches() {
        let realm = RealmId::new();
        let prefix = CacheKeyPrefix::new(realm, CacheClass::User);
        assert!(prefix.matches(&CacheKey::new(realm, CacheClass::User, "alice")));
        assert!(!prefix.matches(&CacheKey::new(realm, CacheClass::Client, "alice")));
    }
}
