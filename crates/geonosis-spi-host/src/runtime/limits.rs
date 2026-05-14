//! Sandbox resource limits.
//!
//! v0.1 default budgets per `docs/07-spi-wasm.md` §"Sandbox & resource
//! limits":
//! - `authn`, `mapper`, `policy`: 50M fuel, 200 ms wall, 32 MiB memory
//! - `event`: 10M fuel, 100 ms wall, 16 MiB memory
//! - `broker-adapter`: 500M fuel, 5 s wall, 100 MiB memory
//! - `federation` (user-storage): 200M fuel, 2 s wall, 64 MiB memory

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub fuel: u64,
    pub memory_bytes: u64,
    pub wall_clock_ms: u64,
}

impl ResourceLimits {
    pub const fn authn() -> Self {
        Self {
            fuel: 50_000_000,
            memory_bytes: 32 * 1024 * 1024,
            wall_clock_ms: 200,
        }
    }

    pub const fn mapper() -> Self {
        Self::authn()
    }

    pub const fn policy() -> Self {
        Self::authn()
    }

    pub const fn event() -> Self {
        Self {
            fuel: 10_000_000,
            memory_bytes: 16 * 1024 * 1024,
            wall_clock_ms: 100,
        }
    }

    pub const fn broker_adapter() -> Self {
        Self {
            fuel: 500_000_000,
            memory_bytes: 100 * 1024 * 1024,
            wall_clock_ms: 5_000,
        }
    }

    pub const fn user_storage() -> Self {
        Self {
            fuel: 200_000_000,
            memory_bytes: 64 * 1024 * 1024,
            wall_clock_ms: 2_000,
        }
    }

    pub fn wall_clock(&self) -> Duration {
        Duration::from_millis(self.wall_clock_ms)
    }
}

/// Engine-level sandbox configuration. Set once at process boot.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Disk root for the `cwasm` cache. `None` disables persistence.
    pub cwasm_cache_root: Option<std::path::PathBuf>,
    /// Maximum in-memory `Component` cache size.
    pub component_cache_max: u64,
    /// Period of the wasmtime epoch ticker. 1 ms per doc §"open items".
    pub epoch_tick_ms: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            cwasm_cache_root: None,
            component_cache_max: 256,
            epoch_tick_ms: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_budgets_match_doc() {
        assert_eq!(ResourceLimits::authn().fuel, 50_000_000);
        assert_eq!(ResourceLimits::event().wall_clock_ms, 100);
        assert_eq!(ResourceLimits::broker_adapter().memory_bytes, 100 * 1024 * 1024);
    }
}
