//! LDAP / Active Directory user federation provider.
//!
//! Per `docs/04-federation-ldap.md`:
//! - Modes: pass-through bind, mirror-on-demand (default), mirror-sync
//! - URN: `builtin:user-storage:ldap:{alias}`
//! - AD `userAccountControl` ACCOUNTDISABLE bit handling, tombstone-as-disable
//!
//! The `config` module owns the strongly-typed configuration shape;
//! `mapper` translates an LDAP entry into a `geonosis_core::User`.
//! `pool`, `bind`, `search`, and `sync` are gated by the `ldap-runtime`
//! feature so the crate keeps compiling without the optional `ldap3`
//! dependency (e.g. when only the typed config is needed).

pub mod config;
pub mod mapper;

#[cfg(feature = "ldap-runtime")]
pub mod bind;
#[cfg(feature = "ldap-runtime")]
pub mod error;
#[cfg(feature = "ldap-runtime")]
pub mod pool;
#[cfg(feature = "ldap-runtime")]
pub mod search;
#[cfg(feature = "ldap-runtime")]
pub mod sync;

pub use config::{
    provider_urn, AttributeMap, LdapFederationConfig, ReferralPolicy, SyncPolicy, TlsPolicy,
    WritePolicy,
};
pub use mapper::{entry_to_user, EntryAttributes};

#[cfg(feature = "ldap-runtime")]
pub use bind::{bind_as_user, BindOutcome};
#[cfg(feature = "ldap-runtime")]
pub use error::LdapError;
#[cfg(feature = "ldap-runtime")]
pub use pool::{CircuitState, LdapPool};
#[cfg(feature = "ldap-runtime")]
pub use search::{find_user, search_groups, SearchedUser};
#[cfg(feature = "ldap-runtime")]
pub use sync::{
    detect_tombstones, run_full_sync, run_incremental_sync, SyncReport, TombstonedEntry,
};
