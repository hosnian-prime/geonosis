//! Server-side `AuthnDispatcher` bridge.
//!
//! Connects `geonosis-flow::DefaultExecutor` to the v0.1 authenticator
//! population — built-in trait implementations AND WASM plugins.
//! Dispatch order:
//!
//! 1. Look up the URN in the `ProviderRegistry` (per realm). If a
//!    binding exists with `ProviderOrigin::Wasm`, load the module
//!    bytecode from storage and dispatch through
//!    [`geonosis_spi_host::WasmAuthnRuntime`].
//! 2. Otherwise fall through to `BuiltinAuthenticators.dispatch(urn)`
//!    which calls into the in-tree `dyn Authenticator` registered
//!    under that URN.
//!
//! The single `AuthnDispatcher` trait covers BOTH paths — built-in
//! and WASM authenticators are interchangeable from the flow
//! executor's perspective. That is the v0.1 promise of doc 07
//! §"Built-ins-as-plugins".

use std::sync::Arc;

use async_trait::async_trait;

use geonosis_authenticators::{AuthnContext, AuthnInput, AuthnOutput, FailureKind};
use geonosis_core::Amr;
use geonosis_flow::authenticator::{AuthnDispatcher, AuthnStepOutcome};
use geonosis_flow::executor::{FlowError, FlowFailure, RenderInstruction, StepInput};
use geonosis_flow::state::FlowState;
use geonosis_spi_host::registry::{ProviderBinding, ProviderOrigin};
use geonosis_spi_host::runtime::{HostState, ResourceLimits, WasmAuthnRuntime, WasmEngine};
use geonosis_spi_host::{ProviderRegistry, WitInterfaceName};
use geonosis_storage::Storage;

use crate::authenticators::BuiltinAuthenticators;

pub struct BuiltinAuthnDispatcher {
    authenticators: Arc<BuiltinAuthenticators>,
    storage: Arc<dyn Storage>,
    realm_hash_key: [u8; 32],
    /// `ProviderRegistry` we consult to see if the URN resolves to a
    /// WASM plugin instead of the in-tree built-in.
    providers: Arc<ProviderRegistry>,
    /// Shared wasmtime engine. Cheap to clone (Arc); per-call store
    /// instances handle the per-realm sandboxing.
    wasm_engine: Arc<WasmEngine>,
}

impl BuiltinAuthnDispatcher {
    pub fn new(
        authenticators: Arc<BuiltinAuthenticators>,
        storage: Arc<dyn Storage>,
        realm_hash_key: [u8; 32],
        providers: Arc<ProviderRegistry>,
        wasm_engine: Arc<WasmEngine>,
    ) -> Self {
        Self {
            authenticators,
            storage,
            realm_hash_key,
            providers,
            wasm_engine,
        }
    }

    async fn build_context(&self, state: &FlowState) -> Result<AuthnContext, FlowError> {
        let realm = self
            .storage
            .get_realm(state.realm_id)
            .await
            .map_err(|e| FlowError::Internal(format!("get_realm: {e}")))?;

        // Client lookup. FlowContext.client_id is a String form of
        // the Client.client_id (NOT the ULID id). Look up via
        // get_client_by_client_id.
        let client_id_str = state
            .context
            .client_id
            .as_deref()
            .ok_or_else(|| FlowError::Internal(
                "FlowContext.client_id missing — OAuth /authorize must populate it"
                    .into(),
            ))?;
        let client = self
            .storage
            .get_client_by_client_id(state.realm_id, client_id_str)
            .await
            .map_err(|e| FlowError::Internal(format!("get_client: {e}")))?;

        let user_id = state
            .context
            .user_id
            .as_deref()
            .and_then(|s| s.parse::<geonosis_core::UserId>().ok());
        let amr: Vec<Amr> = state
            .context
            .amr
            .iter()
            .map(|s| {
                serde_json::from_value::<Amr>(serde_json::Value::String(s.clone()))
                    .unwrap_or(Amr::Custom(s.clone()))
            })
            .collect();

        Ok(AuthnContext {
            realm_id: state.realm_id,
            client: Arc::new(client),
            storage: self.storage.clone(),
            realm_hash_key: self.realm_hash_key,
            user_id,
            session_id: None,
            amr,
            locals: state.context.locals.clone(),
            now: chrono::Utc::now(),
            brute_force: realm.brute_force,
        })
    }

    /// Consult `ProviderRegistry` for a binding matching the URN. The
    /// caller decides what to do with the binding (built-in vs Wasm
    /// dispatch). Returns `None` if no binding exists — the dispatcher
    /// then assumes a built-in URN that lives directly in
    /// `BuiltinAuthenticators`.
    fn wasm_binding(&self, realm: geonosis_core::RealmId, urn: &str) -> Option<ProviderBinding> {
        let iface = WitInterfaceName(WitInterfaceName::AUTHN.into());
        let bindings = self.providers.list(realm, &iface);
        bindings
            .into_iter()
            .find(|b| b.provider_urn == urn && b.enabled && matches!(b.origin, ProviderOrigin::Wasm { .. }))
    }

    async fn dispatch_wasm(
        &self,
        binding: ProviderBinding,
        state: &FlowState,
        input: &StepInput,
    ) -> Result<AuthnStepOutcome, FlowError> {
        let ProviderOrigin::Wasm { alias, .. } = &binding.origin else {
            return Err(FlowError::Internal("non-wasm binding in wasm dispatch".into()));
        };
        let module = self
            .storage
            .get_wasm_module(state.realm_id, alias)
            .await
            .map_err(|e| FlowError::Internal(format!("get_wasm_module: {e}")))?;
        let runtime = WasmAuthnRuntime::compile(
            self.wasm_engine.clone(),
            &module.bytecode,
            ResourceLimits::authn(),
        )
        .map_err(|e| FlowError::Internal(format!("wasm compile: {e}")))?;

        // Serialize FlowContext + form into JSON for the plugin's wire
        // input. JSON keeps the host struct-agnostic (per doc 07).
        let ctx_json = serde_json::to_vec(&state.context)
            .map_err(|e| FlowError::Internal(format!("ctx json: {e}")))?;
        let form_json = match input {
            StepInput::Submit(m) => serde_json::to_vec(m),
            StepInput::IdpCallback(cb) => {
                let mut merged = cb.query.clone();
                for (k, v) in &cb.body {
                    merged.insert(k.clone(), v.clone());
                }
                serde_json::to_vec(&merged)
            }
            StepInput::Start | StepInput::Resume => Ok(b"{}".to_vec()),
        }
        .map_err(|e| FlowError::Internal(format!("form json: {e}")))?;
        let config_bytes = serde_json::to_vec(&binding.config)
            .map_err(|e| FlowError::Internal(format!("config json: {e}")))?;

        let host_state = HostState::builder(binding.provider_urn.clone()).build();
        let realm_str = state.realm_id.to_string();
        let step_output = runtime
            .process(host_state, &realm_str, &ctx_json, &form_json, &config_bytes)
            .await
            .map_err(|e| FlowError::Internal(format!("wasm process: {e}")))?;

        use geonosis_spi_host::runtime::authn::wire::StepOutput;
        match step_output {
            StepOutput::Success(payload) => Ok(AuthnStepOutcome::Success {
                amr: payload.amr,
                authn_level_delta: 1,
                user_id: state.context.user_id.clone(),
                locals: state.context.locals.clone(),
            }),
            StepOutput::Challenge(payload) => {
                let locals: std::collections::BTreeMap<String, serde_json::Value> =
                    serde_json::from_slice(&payload.locals).unwrap_or_default();
                Ok(AuthnStepOutcome::Render(RenderInstruction {
                    template: payload.template,
                    locals,
                }))
            }
            StepOutput::Failure(msg) => Ok(AuthnStepOutcome::Failure(FlowFailure::Other(msg))),
            StepOutput::Skip => Ok(AuthnStepOutcome::Skip),
        }
    }
}

#[async_trait]
impl AuthnDispatcher for BuiltinAuthnDispatcher {
    async fn dispatch(
        &self,
        provider_urn: &str,
        state: &FlowState,
        input: &StepInput,
    ) -> Result<AuthnStepOutcome, FlowError> {
        // 1. WASM path: registry-resolved binding wins over built-ins.
        if let Some(binding) = self.wasm_binding(state.realm_id, provider_urn) {
            return self.dispatch_wasm(binding, state, input).await;
        }

        // 2. Built-in path (the v0.0 behavior).
        let mut ctx = self.build_context(state).await?;
        let authn_input = match input {
            StepInput::Start => AuthnInput::Init,
            StepInput::Resume => AuthnInput::Resume,
            StepInput::Submit(form) => AuthnInput::Submit(form.clone()),
            StepInput::IdpCallback(cb) => {
                let mut m = cb.query.clone();
                for (k, v) in &cb.body {
                    m.insert(k.clone(), v.clone());
                }
                AuthnInput::Submit(m)
            }
        };

        match self
            .authenticators
            .dispatch(provider_urn, &mut ctx, authn_input)
            .await
        {
            Ok(AuthnOutput::Success {
                credentials_satisfied: _,
                amr,
            }) => Ok(AuthnStepOutcome::Success {
                amr: amr.iter().map(|a| a.as_token_value()).collect(),
                authn_level_delta: 1,
                user_id: ctx.user_id.map(|u| u.to_string()),
                locals: ctx.locals,
            }),
            Ok(AuthnOutput::Continue { render }) => {
                Ok(AuthnStepOutcome::Render(RenderInstruction {
                    template: render.template,
                    locals: render.locals,
                }))
            }
            Ok(AuthnOutput::Skip) => Ok(AuthnStepOutcome::Skip),
            Ok(AuthnOutput::Failure(kind)) => {
                Ok(AuthnStepOutcome::Failure(map_failure(kind)))
            }
            Err(e) => Err(FlowError::Internal(format!(
                "authenticator {provider_urn} failed: {e}"
            ))),
        }
    }
}

fn map_failure(kind: FailureKind) -> FlowFailure {
    use FailureKind::*;
    match kind {
        InvalidCredential => FlowFailure::InvalidCredential,
        UserDisabled => FlowFailure::UserDisabled,
        UserNotFound => FlowFailure::UserNotFound,
        ConsentDenied => FlowFailure::ConsentDenied,
        Locked => FlowFailure::Other("locked".into()),
        BrokerError(m) => FlowFailure::BrokerError(m),
        RequiresEnrollment => FlowFailure::Other("requires-enrollment".into()),
        HighRisk => FlowFailure::Other("high-risk".into()),
        Other(m) => FlowFailure::Other(m),
    }
}
