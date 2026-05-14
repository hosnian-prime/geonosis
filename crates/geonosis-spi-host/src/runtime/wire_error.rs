//! Shared `plugin-error` wire shape.
//!
//! `wit/types.wit` defines:
//!
//! ```wit
//! record plugin-error { kind: string, message: string, retryable: bool }
//! ```
//!
//! Every WIT export that returns `result<T, plugin-error>` uses this
//! struct on the host side. Extracted from `runtime/mapper.rs` so
//! the new authn / event / policy / etc. runtimes share one
//! component-model decoder instead of redefining it per file.

use wasmtime::component::{ComponentType, Lift, Lower};

#[derive(Debug, Clone, ComponentType, Lift, Lower)]
#[component(record)]
pub struct Wire {
    pub kind: String,
    pub message: String,
    pub retryable: bool,
}
