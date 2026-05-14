//! Cache abstraction for Geonosis.
//!
//! The `Cache` trait is the seam between the hot-path lookups (realm,
//! client, flow, key, idp, …) and the storage backend. v0.1 ships:
//!
//! - `LocalCache`: in-process Moka LRU + tokio broadcast invalidation
//! - `NoopCache`: always-miss; used by tests and read-mostly admin paths
//!
//! Redis-backed and Komino backends share the same trait — they live in
//! their own modules (`redis`, `komino`) feature-gated separately.

mod key;
mod local;
mod noop;
mod traits;

pub use key::{CacheClass, CacheKey, CacheKeyPrefix};
pub use local::{LocalCache, LocalCacheConfig};
pub use noop::NoopCache;
pub use traits::{Cache, CacheError, Cached};
