//! Authentication flow DSL + executor.
//!
//! Per `docs/06-auth-flows.md`:
//! - A flow is a directed graph of `FlowNode`s with typed edges.
//! - Built-in nodes: Start, Render, Authenticator, Broker, Switch,
//!   SubFlow, Action, Success, Failure.
//! - Each flow is per-version-snapshotted; old in-flight states resolve
//!   against the version they were started on.
//! - Per-step requirement: Required, Optional, Alternative, Disabled.

pub mod authenticator;
pub mod builtin;
pub mod compile;
pub mod dsl;
pub mod executor;
pub mod guard;
pub mod state;

pub use authenticator::{AuthnDispatcher, AuthnStepOutcome, NoopAuthnDispatcher};
pub use compile::{compile, CompileError, CompiledFlow};
pub use dsl::{
    Edge, EdgeCondition, FlowDefinition, FlowNode, NodeKind, NodeLayout, Requirement, StartNode,
    SuccessNode,
};
pub use executor::{FlowError, FlowExecutor, StepInput, StepOutput};
pub use guard::eval_guard;
pub use state::{CsrfToken, FlowContext, FlowHistoryEntry, FlowState};
