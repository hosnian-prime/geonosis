//! The `Authenticator` trait and shared input/output types.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use geonosis_core::{Amr, CredentialKind};

use crate::context::AuthnContext;

#[derive(Debug, Error)]
pub enum AuthnError {
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("internal: {0}")]
    Internal(String),
    #[error("storage: {0}")]
    Storage(String),
    #[error("crypto: {0}")]
    Crypto(String),
}

/// Input handed to an authenticator on each step. Mirrors the WASM
/// `geonosis:authn@0.1.0` interface so built-in + plugin authenticators
/// are interchangeable.
#[derive(Debug, Clone)]
pub enum AuthnInput {
    /// First entry into the authenticator node.
    Init,
    /// A form submission carrying the named fields (e.g. `username`+`password`).
    Submit(BTreeMap<String, String>),
    /// Re-evaluation without user input (e.g. after a redirect-back).
    Resume,
}

impl AuthnInput {
    pub fn field(&self, name: &str) -> Option<&str> {
        match self {
            Self::Submit(m) => m.get(name).map(String::as_str),
            _ => None,
        }
    }
}

/// Outcome of a single authenticator invocation. Per `docs/06`:
/// `Success` advances the flow; `Continue` stays on the same node;
/// `Skip` says "this node didn't apply"; `Failure` is terminal for the
/// node (flow may still continue if the requirement allows).
#[derive(Debug, Clone)]
pub enum AuthnOutput {
    Success {
        credentials_satisfied: Vec<CredentialKind>,
        amr: Vec<Amr>,
    },
    Continue {
        render: RenderInstruction,
    },
    Skip,
    Failure(FailureKind),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderInstruction {
    pub template: String,
    pub locals: BTreeMap<String, serde_json::Value>,
}

impl RenderInstruction {
    pub fn new(template: impl Into<String>) -> Self {
        Self {
            template: template.into(),
            locals: BTreeMap::new(),
        }
    }

    pub fn with(mut self, k: impl Into<String>, v: serde_json::Value) -> Self {
        self.locals.insert(k.into(), v);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureKind {
    InvalidCredential,
    UserDisabled,
    UserNotFound,
    ConsentDenied,
    Locked,
    BrokerError(String),
    RequiresEnrollment,
    /// Risk-score-driven block.
    HighRisk,
    Other(String),
}

/// The trait every built-in + WASM authenticator satisfies.
#[async_trait]
pub trait Authenticator: Send + Sync {
    /// Stable identifier. Built-ins return `"builtin:authn:<name>"`.
    fn provider_id(&self) -> &'static str;

    /// Step the authenticator. Mutating `ctx` is how the authenticator
    /// stores intermediate state (e.g. "username resolved").
    async fn process(
        &self,
        ctx: &mut AuthnContext,
        input: AuthnInput,
    ) -> Result<AuthnOutput, AuthnError>;
}
