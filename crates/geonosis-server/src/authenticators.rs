//! Server-side wiring for the built-in authenticator runtimes.
//!
//! **Layer**: registry. Holds the singleton `Arc<dyn Authenticator>`
//! instances keyed by URN. The convenience `dispatch(urn, ctx, input)`
//! method composes `lookup() + Authenticator::process()` for callers
//! that already own a built `AuthnContext`.
//!
//! **Not the canonical entry point.** Flow-level code goes through
//! [`crate::flow_runtime::BuiltinAuthnDispatcher`] (which implements
//! [`geonosis_flow::AuthnDispatcher`]) — that's where flow-world
//! types (`FlowState`, `StepInput`) translate into authenticator-world
//! types (`AuthnContext`, `AuthnInput`) before reaching this registry.
//! See `flow_runtime.rs` for the bridge.
//!
//! **Why two `dispatch` methods exist** (intentional layering, not
//! duplication):
//! - `BuiltinAuthenticators::dispatch` — registry layer, takes an
//!   already-built `AuthnContext`.
//! - `BuiltinAuthnDispatcher::dispatch` — flow layer, builds the
//!   `AuthnContext` from `FlowState` + storage + realm hash key,
//!   then calls into the registry layer.
//!
//! Runtime instances are shared across realms — they hold no
//! per-realm state. Per-realm config flows through `AuthnContext` /
//! `OtpConfig::from_policy(&realm.otp_policy)`.
//!
//! ## Pattern note
//!
//! This registry's shape — URN → single-method trait → `.process()` —
//! differs intentionally from:
//! - `geonosis_broker::BuiltinAdapters` — multi-hook trait (each
//!   adapter exposes 4 distinct lifecycle methods, not a single
//!   `process`).
//! - `geonosis_broker::mapper` — config-driven enum (no URN
//!   dispatch; mapper bindings are configuration, not pluggable
//!   runtimes in the same sense).
//!
//! Each shape matches the domain need. The three registries are not
//! a fourth pattern waiting to be unified — they are three appropriate
//! patterns for three different dispatch problems.

use std::collections::HashMap;
use std::sync::Arc;

use geonosis_authenticators::{
    Authenticator, AuthnContext, AuthnError, AuthnInput, AuthnOutput, BuiltinUrn,
    ConsentAuthenticator, CookieAuthenticator, IdpRedirectAuthenticator, OtpAuthenticator,
    PasswordAuthenticator, RecoveryCodeAuthenticator, RequireActionAuthenticator,
    RiskScoreAuthenticator, WebauthnAuthenticator,
};

/// Shared registry of built-in authenticator runtimes. Constructed at
/// boot and held inside `AppState`.
pub struct BuiltinAuthenticators {
    by_urn: HashMap<&'static str, Arc<dyn Authenticator>>,
}

impl Default for BuiltinAuthenticators {
    fn default() -> Self {
        let mut by_urn: HashMap<&'static str, Arc<dyn Authenticator>> = HashMap::new();
        by_urn.insert(BuiltinUrn::PASSWORD, Arc::new(PasswordAuthenticator));
        by_urn.insert(
            BuiltinUrn::OTP,
            Arc::new(OtpAuthenticator::new(Default::default())),
        );
        by_urn.insert(
            BuiltinUrn::RECOVERY_CODE,
            Arc::new(RecoveryCodeAuthenticator),
        );
        by_urn.insert(BuiltinUrn::CONSENT, Arc::new(ConsentAuthenticator));
        by_urn.insert(BuiltinUrn::COOKIE, Arc::new(CookieAuthenticator));
        by_urn.insert(
            BuiltinUrn::REQUIRE_ACTION,
            Arc::new(RequireActionAuthenticator),
        );
        by_urn.insert(
            BuiltinUrn::RISK_SCORE,
            Arc::new(RiskScoreAuthenticator::new()),
        );
        by_urn.insert(BuiltinUrn::WEBAUTHN, Arc::new(WebauthnAuthenticator));
        // Note: `idp-redirect`, `magic-link`, `phone-otp` need per-binding
        // config (idp alias / SMTP sender / SMS sender) so they aren't
        // registered as singletons here. The executor instantiates them
        // from the flow-node config at dispatch time.
        let _ = IdpRedirectAuthenticator::new(""); // type-touch for unused-warn

        Self { by_urn }
    }
}

impl BuiltinAuthenticators {
    pub fn lookup(&self, urn: &str) -> Option<Arc<dyn Authenticator>> {
        self.by_urn.get(urn).cloned()
    }

    pub async fn dispatch(
        &self,
        urn: &str,
        ctx: &mut AuthnContext,
        input: AuthnInput,
    ) -> Result<AuthnOutput, AuthnError> {
        let a = self
            .lookup(urn)
            .ok_or_else(|| AuthnError::Internal(format!("unknown authenticator urn: {urn}")))?;
        a.process(ctx, input).await
    }
}
