//! Server-side `AuthnDispatcher` bridge.
//!
//! Connects `geonosis-flow::DefaultExecutor` to the
//! `BuiltinAuthenticators` registry. The bridge:
//! 1. Resolves the realm + client from storage.
//! 2. Constructs an `AuthnContext` from the `FlowState` snapshot.
//! 3. Maps `StepInput` ↔ `AuthnInput` and `AuthnOutput` ↔
//!    `AuthnStepOutcome`.
//! 4. Runs `BuiltinAuthenticators.dispatch(urn, ctx, input)`.
//!
//! WASM-backed authenticators land here in B4 — the same bridge will
//! delegate to a `WasmAuthnRuntime` when the URN's
//! `ProviderBinding.origin` is `ProviderOrigin::Wasm`.

use std::sync::Arc;

use async_trait::async_trait;

use geonosis_authenticators::{AuthnContext, AuthnInput, AuthnOutput, FailureKind};
use geonosis_core::Amr;
use geonosis_flow::authenticator::{AuthnDispatcher, AuthnStepOutcome};
use geonosis_flow::executor::{FlowError, FlowFailure, RenderInstruction, StepInput};
use geonosis_flow::state::FlowState;
use geonosis_storage::Storage;

use crate::authenticators::BuiltinAuthenticators;

pub struct BuiltinAuthnDispatcher {
    authenticators: Arc<BuiltinAuthenticators>,
    storage: Arc<dyn Storage>,
    realm_hash_key: [u8; 32],
}

impl BuiltinAuthnDispatcher {
    pub fn new(
        authenticators: Arc<BuiltinAuthenticators>,
        storage: Arc<dyn Storage>,
        realm_hash_key: [u8; 32],
    ) -> Self {
        Self {
            authenticators,
            storage,
            realm_hash_key,
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
}

#[async_trait]
impl AuthnDispatcher for BuiltinAuthnDispatcher {
    async fn dispatch(
        &self,
        provider_urn: &str,
        state: &FlowState,
        input: &StepInput,
    ) -> Result<AuthnStepOutcome, FlowError> {
        let mut ctx = self.build_context(state).await?;
        let authn_input = match input {
            StepInput::Start => AuthnInput::Init,
            StepInput::Resume => AuthnInput::Resume,
            StepInput::Submit(form) => AuthnInput::Submit(form.clone()),
            StepInput::IdpCallback(cb) => {
                // Flatten the IdP callback's query + body into a single
                // form-shaped map. The idp-redirect authenticator reads
                // `code`/`state`/`error` keys; the rest are kept for
                // future broker-callback authenticators.
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
