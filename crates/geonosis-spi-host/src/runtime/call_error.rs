//! Shared `wasmtime::Trap` / call-error classification.
//!
//! Maps the raw `anyhow::Error` returned from a typed function call
//! into a structured `RuntimeError` variant by sniffing the error
//! message. Extracted from `runtime/mapper.rs` so every per-WIT
//! runtime sees the same fuel / epoch-deadline / memory-growth
//! diagnostics.

use crate::runtime::engine::RuntimeError;
use crate::runtime::limits::ResourceLimits;

pub fn classify(e: anyhow::Error, limits: &ResourceLimits) -> RuntimeError {
    let msg = e.to_string();
    if msg.contains("all fuel consumed") || msg.contains("out of fuel") {
        RuntimeError::FuelExhausted
    } else if msg.contains("epoch deadline") {
        RuntimeError::Timeout {
            ms: limits.wall_clock_ms,
        }
    } else if msg.contains("memory growth failed")
        || msg.contains("exceeded memory limit")
        || msg.contains("memory size of")
    {
        RuntimeError::MemoryExceeded
    } else if e.downcast_ref::<wasmtime::Trap>().is_some() {
        RuntimeError::Trap(msg)
    } else {
        RuntimeError::Call(msg)
    }
}
