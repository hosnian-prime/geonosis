//! Flow executor — the engine that walks the graph.

use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::Utc;
use thiserror::Error;
use url::Url;

use geonosis_core::Subject;

use crate::compile::CompiledFlow;
use crate::dsl::{EdgeCondition, NodeKind, Requirement};
use crate::state::{FlowHistoryEntry, FlowState};

#[derive(Debug, Error)]
pub enum FlowError {
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("graph has no outgoing edge from {0}")]
    DeadEnd(String),
    #[error("expired")]
    Expired,
    #[error("internal: {0}")]
    Internal(String),
}

/// What the executor receives from the HTTP layer for each step.
#[derive(Debug, Clone)]
pub enum StepInput {
    /// First call into the flow.
    Start,
    /// Form post from a `Render` page.
    Submit(FormBody),
    /// External IdP callback returned to us.
    IdpCallback(RawCallback),
    /// "Re-evaluate without input" — used after Action nodes.
    Resume,
}

pub type FormBody = BTreeMap<String, String>;

#[derive(Debug, Clone)]
pub struct RawCallback {
    pub query: BTreeMap<String, String>,
    pub body: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub enum StepOutput {
    Render(RenderInstruction),
    Redirect(Url),
    Done(Subject),
    Failed(FlowFailure),
}

#[derive(Debug, Clone)]
pub struct RenderInstruction {
    pub template: String,
    pub locals: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone)]
pub enum FlowFailure {
    InvalidCredential,
    UserDisabled,
    UserNotFound,
    ConsentDenied,
    BrokerError(String),
    SpiError(String),
    Other(String),
}

/// The contract — `step()` advances `state` by one node.
#[async_trait]
pub trait FlowExecutor: Send + Sync {
    async fn step(
        &self,
        flow: &CompiledFlow,
        state: &mut FlowState,
        input: StepInput,
    ) -> Result<StepOutput, FlowError>;
}

/// Default executor — knows how to walk Start/Render/Success/Failure
/// nodes. Authenticator nodes delegate to an injected
/// `AuthnDispatcher`; the noop default keeps the pre-B5 stub-render
/// behavior so existing tests and the server boot path stay valid
/// until the real dispatcher lands at runtime.
pub struct DefaultExecutor {
    authn: std::sync::Arc<dyn crate::authenticator::AuthnDispatcher>,
}

impl Default for DefaultExecutor {
    fn default() -> Self {
        Self::with_noop_authenticator()
    }
}

impl DefaultExecutor {
    /// Construct an executor with a concrete `AuthnDispatcher`. The
    /// server bootstrap calls this with the
    /// `BuiltinAuthenticators`-backed dispatcher; tests call
    /// `with_noop_authenticator()`.
    pub fn new(
        authn: std::sync::Arc<dyn crate::authenticator::AuthnDispatcher>,
    ) -> Self {
        Self { authn }
    }

    /// Convenience for tests + flow-only code paths.
    pub fn with_noop_authenticator() -> Self {
        Self {
            authn: std::sync::Arc::new(crate::authenticator::NoopAuthnDispatcher),
        }
    }
}

#[async_trait]
impl FlowExecutor for DefaultExecutor {
    async fn step(
        &self,
        flow: &CompiledFlow,
        state: &mut FlowState,
        input: StepInput,
    ) -> Result<StepOutput, FlowError> {
        if state.expires_at < Utc::now() {
            return Err(FlowError::Expired);
        }
        state.last_activity_at = Utc::now();

        loop {
            let node = flow.node(state.current_node).clone();
            match (&node.kind, &input) {
                (NodeKind::Start(_), _) => {
                    state.history.push(FlowHistoryEntry {
                        node: node.id,
                        at: Utc::now(),
                        outcome: "advance".into(),
                    });
                    let next = flow
                        .next_with_guard(node.id, &EdgeCondition::Otherwise, &state.context)
                        .ok_or_else(|| FlowError::DeadEnd(node.id.to_string()))?;
                    state.current_node = next;
                    // Continue executing the next node in this same step
                    // unless it's a Render / Broker / Authenticator that
                    // needs user input.
                    continue;
                }
                (NodeKind::Render { template }, StepInput::Start | StepInput::Resume) => {
                    return Ok(StepOutput::Render(RenderInstruction {
                        template: template.clone(),
                        locals: state.context.locals.clone(),
                    }));
                }
                (NodeKind::Render { .. }, StepInput::Submit(_) | StepInput::IdpCallback(_)) => {
                    // The page was POSTed back; consider this step done and
                    // continue to the next node.
                    state.history.push(FlowHistoryEntry {
                        node: node.id,
                        at: Utc::now(),
                        outcome: "submit".into(),
                    });
                    let next = flow
                        .next_with_guard(node.id, &EdgeCondition::Success, &state.context)
                        .or_else(|| flow.next_with_guard(node.id, &EdgeCondition::Otherwise, &state.context))
                        .ok_or_else(|| FlowError::DeadEnd(node.id.to_string()))?;
                    state.current_node = next;
                    continue;
                }
                (NodeKind::Authenticator { provider_urn }, _) => {
                    let outcome = self
                        .authn
                        .dispatch(provider_urn, &state.context, &input)
                        .await?;
                    use crate::authenticator::AuthnStepOutcome::*;
                    match outcome {
                        Render(r) => {
                            return Ok(StepOutput::Render(r));
                        }
                        Success {
                            amr,
                            authn_level_delta,
                            user_id,
                            locals,
                        } => {
                            for a in amr {
                                if !state.context.amr.contains(&a) {
                                    state.context.amr.push(a);
                                }
                            }
                            state.context.authn_level += authn_level_delta;
                            if let Some(uid) = user_id {
                                state.context.user_id = Some(uid);
                            }
                            state.context.locals.extend(locals);
                            state.history.push(FlowHistoryEntry {
                                node: node.id,
                                at: Utc::now(),
                                outcome: "success".into(),
                            });
                            let next = flow
                                .next_with_guard(
                                    node.id,
                                    &EdgeCondition::Success,
                                    &state.context,
                                )
                                .or_else(|| {
                                    flow.next_with_guard(
                                        node.id,
                                        &EdgeCondition::Otherwise,
                                        &state.context,
                                    )
                                })
                                .ok_or_else(|| {
                                    FlowError::DeadEnd(node.id.to_string())
                                })?;
                            state.current_node = next;
                            continue;
                        }
                        Skip => {
                            state.history.push(FlowHistoryEntry {
                                node: node.id,
                                at: Utc::now(),
                                outcome: "skip".into(),
                            });
                            let next = flow
                                .next_with_guard(
                                    node.id,
                                    &EdgeCondition::Otherwise,
                                    &state.context,
                                )
                                .ok_or_else(|| {
                                    FlowError::DeadEnd(node.id.to_string())
                                })?;
                            state.current_node = next;
                            continue;
                        }
                        Failure(reason) => {
                            state.history.push(FlowHistoryEntry {
                                node: node.id,
                                at: Utc::now(),
                                outcome: "failure".into(),
                            });
                            let next = flow.next_with_guard(
                                node.id,
                                &EdgeCondition::Failure,
                                &state.context,
                            );
                            if let Some(n) = next {
                                state.current_node = n;
                                continue;
                            }
                            return Ok(StepOutput::Failed(reason));
                        }
                    }
                }
                (NodeKind::Broker { idp_alias }, _) => {
                    return Ok(StepOutput::Render(RenderInstruction {
                        template: format!("broker::{idp_alias}"),
                        locals: state.context.locals.clone(),
                    }));
                }
                (NodeKind::Switch { condition }, _) => {
                    // Switch nodes are pure routing; v0.1 supports literal
                    // condition labels which match `EdgeCondition::Status`.
                    let next = flow
                        .next_with_guard(
                            node.id,
                            &EdgeCondition::Status(condition.clone()),
                            &state.context,
                        )
                        .or_else(|| flow.next_with_guard(node.id, &EdgeCondition::Otherwise, &state.context))
                        .ok_or_else(|| FlowError::DeadEnd(node.id.to_string()))?;
                    state.current_node = next;
                    continue;
                }
                (NodeKind::Action { .. }, _) | (NodeKind::SubFlow { .. }, _) => {
                    // v0.1: Action / SubFlow advance via Otherwise edge.
                    let next = flow
                        .next_with_guard(node.id, &EdgeCondition::Otherwise, &state.context)
                        .ok_or_else(|| FlowError::DeadEnd(node.id.to_string()))?;
                    state.current_node = next;
                    continue;
                }
                (NodeKind::Success(_), _) => {
                    state.history.push(FlowHistoryEntry {
                        node: node.id,
                        at: Utc::now(),
                        outcome: "success".into(),
                    });
                    // The OAuth layer reads `state.context.user_id` to
                    // construct the real `Subject::Local`. Default executor
                    // just signals completion with a placeholder when no
                    // user resolved.
                    let user_id = state
                        .context
                        .user_id
                        .as_ref()
                        .and_then(|s| s.parse::<geonosis_core::UserId>().ok())
                        .unwrap_or_default();
                    return Ok(StepOutput::Done(Subject::Local { user_id }));
                }
                (NodeKind::Failure { reason }, _) => {
                    state.history.push(FlowHistoryEntry {
                        node: node.id,
                        at: Utc::now(),
                        outcome: "failure".into(),
                    });
                    return Ok(StepOutput::Failed(FlowFailure::Other(reason.clone())));
                }
            }
        }
    }
}

/// Quiet a "may be unused" warning until the SPI host wires up.
#[allow(dead_code)]
fn _touch_requirement(_r: Requirement) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::compile;
    use crate::dsl::{Edge, EdgeCondition, FlowDefinition, FlowNode, NodeKind, Requirement, StartNode, SuccessNode};
    use crate::state::FlowState;
    use geonosis_core::id::{FlowId, NodeId, RealmId};
    use std::time::Duration;

    fn node(kind: NodeKind) -> FlowNode {
        FlowNode {
            id: NodeId::new(),
            display_name: String::new(),
            kind,
            requirement: Requirement::Required,
            config: serde_json::Value::Null,
        }
    }

    #[tokio::test]
    async fn start_to_success_runs_to_done() {
        let start = node(NodeKind::Start(StartNode::default()));
        let success = node(NodeKind::Success(SuccessNode::default()));
        let def = FlowDefinition {
            realm_id: geonosis_core::id::RealmId::new(),
            id: FlowId::new(),
            alias: "x".into(),
            display_name: "X".into(),
            version: 1,
            start: start.id,
            edges: vec![Edge {
                from: start.id,
                to: success.id,
                on: EdgeCondition::Otherwise,
                guard: Default::default(),
            }],
            nodes: vec![start.clone(), success],
        };
        let compiled = compile(def).unwrap();
        let mut state = FlowState::fresh(
            RealmId::new(),
            compiled.definition.id,
            1,
            start.id,
            Duration::from_secs(300),
        );
        let out = DefaultExecutor::default().step(&compiled, &mut state, StepInput::Start).await.unwrap();
        assert!(matches!(out, StepOutput::Done(_)));
    }

    #[tokio::test]
    async fn render_node_pauses_for_form_submit() {
        let start = node(NodeKind::Start(StartNode::default()));
        let render = node(NodeKind::Render {
            template: "login".into(),
        });
        let success = node(NodeKind::Success(SuccessNode::default()));
        let def = FlowDefinition {
            realm_id: geonosis_core::id::RealmId::new(),
            id: FlowId::new(),
            alias: "x".into(),
            display_name: "X".into(),
            version: 1,
            start: start.id,
            edges: vec![
                Edge {
                    from: start.id,
                    to: render.id,
                    on: EdgeCondition::Otherwise,
                    guard: Default::default(),
                },
                Edge {
                    from: render.id,
                    to: success.id,
                    on: EdgeCondition::Success,
                    guard: Default::default(),
                },
            ],
            nodes: vec![start.clone(), render.clone(), success],
        };
        let compiled = compile(def).unwrap();
        let mut state = FlowState::fresh(
            RealmId::new(),
            compiled.definition.id,
            1,
            start.id,
            Duration::from_secs(300),
        );
        let out = DefaultExecutor::default().step(&compiled, &mut state, StepInput::Start).await.unwrap();
        match out {
            StepOutput::Render(r) => assert_eq!(r.template, "login"),
            other => panic!("expected render, got {other:?}"),
        }
        // After submit, we proceed to success.
        let out = DefaultExecutor::default()
            .step(&compiled, &mut state, StepInput::Submit(Default::default()))
            .await
            .unwrap();
        assert!(matches!(out, StepOutput::Done(_)));
    }

    #[tokio::test]
    async fn expired_state_rejects() {
        let start = node(NodeKind::Start(StartNode::default()));
        let success = node(NodeKind::Success(SuccessNode::default()));
        let def = FlowDefinition {
            realm_id: geonosis_core::id::RealmId::new(),
            id: FlowId::new(),
            alias: "x".into(),
            display_name: "X".into(),
            version: 1,
            start: start.id,
            edges: vec![Edge {
                from: start.id,
                to: success.id,
                on: EdgeCondition::Otherwise,
                guard: Default::default(),
            }],
            nodes: vec![start.clone(), success],
        };
        let compiled = compile(def).unwrap();
        let mut state = FlowState::fresh(
            RealmId::new(),
            compiled.definition.id,
            1,
            start.id,
            Duration::from_secs(300),
        );
        // Force expiry.
        state.expires_at = Utc::now() - chrono::Duration::seconds(1);
        let err = DefaultExecutor::default()
            .step(&compiled, &mut state, StepInput::Start)
            .await
            .unwrap_err();
        assert!(matches!(err, FlowError::Expired));
    }
}
