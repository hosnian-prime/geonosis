//! Authenticator-dispatch seam.
//!
//! The flow executor doesn't know how to RUN an authenticator — that
//! belongs to the SPI host layer (built-in registry + WASM runtime).
//! `AuthnDispatcher` is the trait the executor calls when it reaches
//! an `Authenticator` node; concrete impls live in
//! `geonosis-server::flow_runtime` and bridge to
//! `geonosis-authenticators::BuiltinAuthenticators`.
//!
//! Keeping the trait in `geonosis-flow` (rather than spreading the
//! dispatch across crates) avoids the audit's "three different
//! patterns for the same problem" anti-goal — the flow executor has
//! ONE dispatch hook, and every authenticator (built-in or WASM)
//! arrives through it.

use std::collections::BTreeMap;

use async_trait::async_trait;

use crate::executor::{FlowError, FlowFailure, RenderInstruction, StepInput};
use crate::state::FlowState;

/// Outcome of one authenticator step. Mirrors `AuthnOutput` in the
/// authenticators crate but uses flow-side types so the flow crate
/// stays dependency-free from authenticator runtimes.
#[derive(Debug, Clone)]
pub enum AuthnStepOutcome {
    /// Render this template; pause until the user submits.
    Render(RenderInstruction),
    /// Advance the flow via an `EdgeCondition::Success` edge.
    Success {
        /// AMR values the authenticator contributed (`pwd`, `otp`, …).
        amr: Vec<String>,
        /// `authn_level` bump (e.g. +1 for password, +1 for OTP).
        authn_level_delta: i32,
        /// Optionally resolves the user — populates `FlowContext.user_id`.
        user_id: Option<String>,
        /// Optional locals to merge into the flow context.
        locals: BTreeMap<String, serde_json::Value>,
    },
    /// Authenticator said "I don't handle this"; flow falls through
    /// the `Otherwise` edge.
    Skip,
    /// Authenticator failed; flow takes the `Failure` edge.
    Failure(FlowFailure),
}

/// Trait the flow executor calls on every `Authenticator` node. The
/// caller owns `FlowContext` mutation — dispatcher impls return their
/// contribution and the executor merges it. Receives the full
/// `FlowState` so concrete impls can read the realm id + flow
/// snapshot version without threading them separately.
#[async_trait]
pub trait AuthnDispatcher: Send + Sync {
    async fn dispatch(
        &self,
        provider_urn: &str,
        state: &FlowState,
        input: &StepInput,
    ) -> Result<AuthnStepOutcome, FlowError>;
}

/// Default v0.1 dispatcher — returns a Render that names the expected
/// provider URN. Used by unit tests and by the executor when the
/// server hasn't injected a real dispatcher (graceful fallback during
/// boot). Matches the pre-B5 stub behavior so existing tests keep
/// their assertions.
pub struct NoopAuthnDispatcher;

#[async_trait]
impl AuthnDispatcher for NoopAuthnDispatcher {
    async fn dispatch(
        &self,
        provider_urn: &str,
        _state: &FlowState,
        _input: &StepInput,
    ) -> Result<AuthnStepOutcome, FlowError> {
        Ok(AuthnStepOutcome::Render(RenderInstruction {
            template: format!("authenticate::{provider_urn}"),
            locals: BTreeMap::new(),
        }))
    }
}
