//! `/admin/v1/realms/:slug/flows/:alias/dry-run` — synthetic-context
//! flow walker.
//!
//! Per `docs/06-auth-flows.md` §"Visual flow editor" the admin UI must
//! offer dry-run with synthetic context so operators can validate a
//! flow change before letting it touch real users. This handler is the
//! REST entry point; the heavy lifting lives in
//! [`geonosis_flow::dry_run`] which is pure (no I/O, no audit, no
//! WASM SPI invocation).
//!
//! Design notes:
//! - **GET / PUT for the flow definition stays in legacy
//!   `handlers.rs::api_flow_*`.** Adding the dry-run sub-resource
//!   here keeps the handlers_v1 surface focused on the new endpoint
//!   without conflicting with the existing route registrations.
//! - **No audit emission.** Dry-run is a read-only operator inspection
//!   action; emitting an audit event for every "did this branch fire?"
//!   click would drown the audit feed in noise. Once admin auth lands
//!   and we have a real principal, a single coarse-grained
//!   `flow.dry_run_invoked` event becomes feasible.
//! - **String-keyed `expected_outcomes`.** The request body keys are
//!   node-id ULID strings rather than typed `NodeId` to keep the JSON
//!   round-trip robust against future ID-type changes; the handler
//!   parses them through `FromStr` and skips entries that fail to
//!   parse (a flow may be edited between dry-run invocations).

use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;

use geonosis_core::id::NodeId;
use geonosis_flow::{dry_run, DryRunReport, ExpectedOutcome, FlowContext};

use crate::handlers_v1::extractors::realm_by_slug;
use crate::state::{AdminError, AdminState};

/// Operator-supplied synthetic context. Every field is optional so
/// the request body can be as small as `{}` — the handler maps any
/// unset field to its `FlowContext` default. This is a separate type
/// from `FlowContext` (which is owned by the executor and has stricter
/// invariants on field presence) so that loosening the wire shape
/// here never relaxes invariants on the in-flight executor state.
#[derive(Debug, Deserialize, Default)]
pub struct SyntheticContext {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default)]
    pub authn_level: i32,
    #[serde(default)]
    pub locals: BTreeMap<String, serde_json::Value>,
}

impl From<SyntheticContext> for FlowContext {
    fn from(s: SyntheticContext) -> Self {
        FlowContext {
            username: s.username,
            user_id: s.user_id,
            client_id: s.client_id,
            amr: s.amr,
            authn_level: s.authn_level,
            requested_acr: None,
            session_id: None,
            locals: s.locals,
        }
    }
}

/// Request body for the dry-run endpoint.
///
/// `context` is the synthetic context the walker uses for guard
/// evaluation. `expected_outcomes` lets the operator pin per-node
/// behavior (e.g. *"assume the password authenticator returns
/// Failure"*) so the report shows the failure branch instead of the
/// default success path.
#[derive(Debug, Deserialize, Default)]
pub struct DryRunRequest {
    #[serde(default)]
    pub context: SyntheticContext,
    /// Map of `node_id (ULID string) -> expected outcome`.
    /// Unknown / unparseable node IDs are silently ignored — a flow
    /// may be edited between dry-run invocations.
    #[serde(default)]
    pub expected_outcomes: HashMap<String, ExpectedOutcome>,
}

/// `POST /admin/v1/realms/:slug/flows/:alias/dry-run`
pub async fn dry_run_post(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
    Json(req): Json<DryRunRequest>,
) -> Result<Json<DryRunReport>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let flow = state
        .storage
        .get_auth_flow_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;

    // Parse the string-keyed map into the typed map the pure walker
    // expects. Entries with unparseable keys are dropped silently —
    // they refer to nodes that no longer exist, which is benign here.
    let expected: HashMap<NodeId, ExpectedOutcome> = req
        .expected_outcomes
        .into_iter()
        .filter_map(|(k, v)| NodeId::from_str(&k).ok().map(|nid| (nid, v)))
        .collect();

    let context: FlowContext = req.context.into();
    // The only ways this can fail are (a) the persisted flow itself
    // is uncompilable (bad data — surfaces as 400 InvalidInput so the
    // operator sees the cause) or (b) future expansion. No storage
    // writes, no audit emit, no authenticator dispatch.
    let report = dry_run(&flow, &context, &expected)
        .map_err(|e| AdminError::InvalidInput(format!("flow `{alias}` failed to compile: {e}")))?;
    Ok(Json(report))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chrono::Utc;
    use tower::ServiceExt;

    use geonosis_core::{
        AcrPolicy, BruteForcePolicy, EventConfig, LocalizationPolicy, LoginSettings, OtpPolicy,
        PasswordPolicy, Realm, RealmId, RegistrationPolicy, SenderConstraint, SessionPolicy,
        SslRequirement, ThemeBinding, TokenPolicy, WebauthnPolicy,
    };
    use geonosis_storage::{seed_default_flows, MemoryStorage, Storage};

    use crate::AdminState;

    async fn fixture_state() -> (Arc<AdminState>, RealmId) {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let realm = Realm {
            id: RealmId::new(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            frontend_url: None,
            admin_frontend_url: None,
            enabled: true,
            ssl_required: SslRequirement::None,
            login: LoginSettings::default(),
            registration: RegistrationPolicy::default(),
            session_policy: SessionPolicy::default(),
            token_policy: TokenPolicy::default(),
            brute_force: BruteForcePolicy::default(),
            password_policy: PasswordPolicy::default(),
            otp_policy: OtpPolicy::default(),
            webauthn_policy: WebauthnPolicy::default(),
            acr_policy: AcrPolicy::default(),
            sender_constraint_default: SenderConstraint::None,
            theme_binding: ThemeBinding::default(),
            localization: LocalizationPolicy::default(),
            events: EventConfig::default(),
            default_groups: vec![],
            default_roles: Default::default(),
            organizations_enabled: true,
            organization_policy: Default::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let realm_id = realm.id;
        storage.create_realm(realm).await.unwrap();
        seed_default_flows(storage.as_ref(), realm_id)
            .await
            .unwrap();
        let admin = AdminState::new(storage).unwrap();
        (Arc::new(admin), realm_id)
    }

    /// POST a synthetic empty context against the `direct-grant`
    /// built-in flow and assert the JSON shape matches the
    /// admin-contract surface.
    #[tokio::test]
    async fn dry_run_direct_grant_returns_success_terminal() {
        let (state, _realm_id) = fixture_state().await;
        let router = crate::handlers_v1::router(state);

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/v1/realms/acme/flows/direct-grant/dry-run")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Required keys per the admin contract.
        assert!(json.get("steps").is_some(), "missing `steps`");
        assert!(json.get("terminal").is_some(), "missing `terminal`");
        // Default authenticator outcome is Success → reaches the
        // success terminal.
        assert_eq!(json["terminal"], serde_json::json!("success"));
        let steps = json["steps"].as_array().expect("steps array");
        assert!(!steps.is_empty(), "steps should not be empty");
        for step in steps {
            assert!(step["node_id"].is_string());
            assert!(step["kind"].is_string());
            assert!(step["decision"].is_string());
        }
    }

    #[tokio::test]
    async fn dry_run_unknown_flow_returns_404() {
        let (state, _realm_id) = fixture_state().await;
        let router = crate::handlers_v1::router(state);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/v1/realms/acme/flows/does-not-exist/dry-run")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn dry_run_unknown_realm_returns_404() {
        let (state, _realm_id) = fixture_state().await;
        let router = crate::handlers_v1::router(state);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/v1/realms/missing/flows/browser/dry-run")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Pin the password authenticator to Failure → terminal must
    /// flip to `failure` because the `direct-grant` flow routes
    /// `Failure` → failure terminal.
    #[tokio::test]
    async fn dry_run_honors_expected_outcomes_in_request() {
        let (state, realm_id) = fixture_state().await;
        // Discover the password node id from the persisted flow so we
        // can address it in the request body.
        let flow = state
            .storage
            .get_auth_flow_by_alias(realm_id, "direct-grant")
            .await
            .unwrap();
        let pw_id = flow
            .nodes
            .iter()
            .find_map(|n| match &n.kind {
                geonosis_flow::NodeKind::Authenticator { provider_urn }
                    if provider_urn == "builtin:authn:password" =>
                {
                    Some(n.id)
                }
                _ => None,
            })
            .expect("password node present in direct-grant");

        let router = crate::handlers_v1::router(state);
        let body = serde_json::json!({
            "context": {},
            "expected_outcomes": { pw_id.to_string(): "failure" },
        });
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/v1/realms/acme/flows/direct-grant/dry-run")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["terminal"], serde_json::json!("failure"));
    }
}
