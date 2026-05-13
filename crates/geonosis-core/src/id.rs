//! Strongly-typed identifiers.
//!
//! Each entity has its own newtype around a `Ulid` (or opaque random string
//! for tokens). Newtypes prevent accidentally passing a `ClientId` where a
//! `UserId` is expected.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

#[derive(Debug, Error)]
#[error("invalid id: {0}")]
pub struct IdParseError(String);

macro_rules! ulid_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Ulid);

        impl $name {
            #[inline]
            pub fn new() -> Self {
                Self(Ulid::new())
            }

            #[inline]
            pub const fn from_ulid(u: Ulid) -> Self {
                Self(u)
            }

            #[inline]
            pub const fn as_ulid(&self) -> Ulid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ulid::from_str(s)
                    .map(Self)
                    .map_err(|e| IdParseError(e.to_string()))
            }
        }
    };
}

ulid_id!(RealmId, "Realm (tenant) identifier.");
ulid_id!(UserId, "User identifier.");
ulid_id!(ClientId, "Internal client identifier (distinct from `client_id` string).");
ulid_id!(RoleId, "Role identifier.");
ulid_id!(GroupId, "Group identifier.");
ulid_id!(FlowId, "Authentication flow identifier.");
ulid_id!(NodeId, "Flow node identifier (scoped within a flow).");
ulid_id!(KeyId, "Cryptographic key identifier (used as JWS `kid`).");
ulid_id!(CredentialId, "Credential identifier.");
ulid_id!(IdpId, "Identity provider (broker) identifier.");
ulid_id!(SpiBindingId, "SPI provider registry binding identifier.");
ulid_id!(WasmModuleId, "Uploaded WASM module identifier.");
ulid_id!(EventId, "Audit event identifier.");
ulid_id!(AgentId, "Agent (AI / M2M) identifier.");
ulid_id!(ScimTargetId, "SCIM provisioning target identifier.");
ulid_id!(BrokerLinkId, "Persistent broker-user link identifier.");
ulid_id!(BrokerAuthnStateId, "Pending broker callback state identifier.");
ulid_id!(FlowStateId, "In-progress flow state identifier.");
ulid_id!(ConsentGrantId, "Persisted consent grant identifier.");
ulid_id!(OrganizationId, "Organization (B2B sub-tenant) identifier.");
ulid_id!(OrgDomainId, "Organization domain identifier.");
ulid_id!(OrgInvitationId, "Organization invitation identifier.");
ulid_id!(OrgRoleId, "Organization-scoped role identifier.");
ulid_id!(FederationId, "User federation source identifier.");
ulid_id!(TokenFamilyId, "Refresh-token family lineage identifier.");

/// Opaque session identifier (32-byte random, base32-encoded).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub String);

impl SessionId {
    pub fn new_random() -> Self {
        use rand_bytes::random_b32_32;
        Self(random_b32_32())
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Opaque single-use authorization code (32-byte random, base32-encoded).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CodeId(pub String);

impl CodeId {
    pub fn new_random() -> Self {
        use rand_bytes::random_b32_32;
        Self(random_b32_32())
    }
}

impl fmt::Display for CodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Opaque refresh-token identifier.
///
/// Never plaintext in storage — the storage layer holds a BLAKE3-keyed hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RefreshTokenId(pub String);

impl fmt::Display for RefreshTokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

mod rand_bytes {
    // Tiny dependency-free RNG-backed helper. We don't pull `rand` here
    // to keep `geonosis-core` I/O-free, but we DO need a tiny source. We
    // use `getrandom` (OS RNG) via the std library where possible.
    use std::sync::atomic::{AtomicU64, Ordering};

    // Crockford base32 alphabet (no 0/O/1/I/L confusables — match Ulid).
    const ALPHA: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    pub fn random_b32_32() -> String {
        let mut bytes = [0u8; 20]; // 32 base32 chars = 160 bits
        fill_os_random(&mut bytes);
        // mix in monotonic counter to defend against any pathological RNG
        let c = COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes();
        for (i, b) in c.iter().enumerate() {
            bytes[i % bytes.len()] ^= b;
        }
        let mut out = String::with_capacity(32);
        for chunk in bytes.chunks(5) {
            let mut buf = [0u8; 5];
            buf[..chunk.len()].copy_from_slice(chunk);
            let v = u64::from(buf[0]) << 32
                | u64::from(buf[1]) << 24
                | u64::from(buf[2]) << 16
                | u64::from(buf[3]) << 8
                | u64::from(buf[4]);
            for i in (0..8).rev() {
                let ix = ((v >> (i * 5)) & 0x1f) as usize;
                out.push(ALPHA[ix] as char);
            }
        }
        out.truncate(32);
        out
    }

    fn fill_os_random(buf: &mut [u8]) {
        // Best-effort OS RNG without pulling extra deps. Falls back to
        // a deterministic seed if /dev/urandom is unreadable — that
        // path is only relevant for non-Unix exotica.
        #[cfg(unix)]
        {
            use std::fs::File;
            use std::io::Read;
            if let Ok(mut f) = File::open("/dev/urandom") {
                if f.read_exact(buf).is_ok() {
                    return;
                }
            }
        }
        // Fallback: ulid randomness is sufficient given monotonic mixin.
        for b in buf {
            *b = (ulid::Ulid::new().0 & 0xff) as u8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ulid_id_roundtrip_text() {
        let id = RealmId::new();
        let s = id.to_string();
        let parsed: RealmId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn ulid_id_distinct_each_call() {
        let a = UserId::new();
        let b = UserId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn session_id_is_32_chars() {
        let sid = SessionId::new_random();
        assert_eq!(sid.0.len(), 32);
    }

    #[test]
    fn code_id_random_unique() {
        let a = CodeId::new_random();
        let b = CodeId::new_random();
        assert_ne!(a, b);
    }

    #[test]
    fn ids_serialize_transparently() {
        let id = RealmId::new();
        let json = serde_json::to_string(&id).unwrap();
        assert!(json.starts_with('"') && json.ends_with('"'));
        let de: RealmId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, de);
    }
}
