//! Built-in flow definitions per `docs/06-auth-flows.md` §"Built-in
//! authentication flows".
//!
//! v0.1 ships seven flows: every realm gets them seeded automatically
//! on creation so a fresh tenant can authenticate before an operator
//! touches the admin UI. Each definition is intentionally minimal —
//! just enough to walk a happy-path login. Operators clone + customize
//! by saving a new version under the same alias.
//!
//! Author convention: the FIRST authenticator URN in every flow comes
//! from `geonosis-authenticators::registry` so the executor can resolve
//! it without a custom URN map. New URNs land in that crate, never
//! ad-hoc here.

use std::collections::BTreeMap;

use geonosis_core::id::{FlowId, NodeId, RealmId};

use crate::dsl::{
    Edge, EdgeCondition, FlowDefinition, FlowNode, NodeKind, Requirement, StartNode, SuccessNode,
};

/// Stable URNs the executor / flow seeder reference. These mirror the
/// constants in `geonosis-authenticators::registry::BuiltinUrn`; we
/// duplicate the strings here (not import the crate) to keep
/// geonosis-flow dependency-free from authenticators. The
/// `consistent_urns_with_authenticators_crate` test pins them against
/// drift.
mod urn {
    pub const PASSWORD: &str = "builtin:authn:password";
    pub const OTP: &str = "builtin:authn:otp";
    pub const COOKIE: &str = "builtin:authn:cookie";
    pub const MAGIC_LINK: &str = "builtin:authn:magic-link";
    pub const IDP_REDIRECT: &str = "builtin:authn:idp-redirect";
    pub const CLIENT_AUTH: &str = "builtin:authn:client-authentication";
    pub const REQUIRE_ACTION: &str = "builtin:authn:require-action";
}

/// Stable aliases the v0.1 protocol layer expects. The OAuth /authorize
/// handler picks `browser` by default, `direct-grant` for the
/// password grant, `registration` for /registrations, etc.
pub mod alias {
    pub const BROWSER: &str = "browser";
    pub const DIRECT_GRANT: &str = "direct-grant";
    pub const REGISTRATION: &str = "registration";
    pub const RESET_CREDENTIALS: &str = "reset-credentials";
    pub const FIRST_BROKER_LOGIN: &str = "first-broker-login";
    pub const CLIENT_AUTHENTICATION: &str = "client-authentication";
    pub const STEP_UP: &str = "step-up";
}

/// Build every v0.1 built-in flow for a realm. Returns the
/// fully-populated `FlowDefinition` values ready for `save_auth_flow`.
pub fn v0_1_flows(realm: RealmId) -> Vec<FlowDefinition> {
    vec![
        browser(realm),
        direct_grant(realm),
        registration(realm),
        reset_credentials(realm),
        first_broker_login(realm),
        client_authentication(realm),
        step_up(realm),
    ]
}

/// `browser` — interactive login: cookie-first, then password, then
/// optional required-actions, then success.
pub fn browser(realm: RealmId) -> FlowDefinition {
    let start = node_start();
    let cookie = node_authn("cookie SSO", urn::COOKIE, Requirement::Optional);
    let render_form = node_render("login form", "login");
    let password = node_authn("password", urn::PASSWORD, Requirement::Required);
    let require_action = node_authn(
        "required actions",
        urn::REQUIRE_ACTION,
        Requirement::Optional,
    );
    let success = node_success();
    let failure = node_failure("authentication failed");
    let edges = vec![
        edge(start.id, cookie.id, EdgeCondition::Otherwise),
        edge(cookie.id, success.id, EdgeCondition::Success),
        edge(cookie.id, render_form.id, EdgeCondition::Otherwise),
        edge(render_form.id, password.id, EdgeCondition::Success),
        edge(password.id, require_action.id, EdgeCondition::Success),
        edge(password.id, failure.id, EdgeCondition::Failure),
        edge(require_action.id, success.id, EdgeCondition::Otherwise),
    ];
    let start_id = start.id;
    flow(
        realm,
        alias::BROWSER,
        "Browser flow",
        start_id,
        edges,
        vec![
            start,
            cookie,
            render_form,
            password,
            require_action,
            success,
            failure,
        ],
    )
}

/// `direct-grant` — programmatic password grant (RFC 6749 §4.3).
pub fn direct_grant(realm: RealmId) -> FlowDefinition {
    let start = node_start();
    let password = node_authn("password", urn::PASSWORD, Requirement::Required);
    let success = node_success();
    let failure = node_failure("invalid credentials");
    let edges = vec![
        edge(start.id, password.id, EdgeCondition::Otherwise),
        edge(password.id, success.id, EdgeCondition::Success),
        edge(password.id, failure.id, EdgeCondition::Failure),
    ];
    let start_id = start.id;
    flow(
        realm,
        alias::DIRECT_GRANT,
        "Direct grant",
        start_id,
        edges,
        vec![start, password, success, failure],
    )
}

/// `registration` — self-service signup. Render form → password set →
/// optional required-actions → success.
pub fn registration(realm: RealmId) -> FlowDefinition {
    let start = node_start();
    let render_form = node_render("registration form", "register");
    let password = node_authn("set password", urn::PASSWORD, Requirement::Required);
    let success = node_success();
    let failure = node_failure("registration failed");
    let edges = vec![
        edge(start.id, render_form.id, EdgeCondition::Otherwise),
        edge(render_form.id, password.id, EdgeCondition::Success),
        edge(password.id, success.id, EdgeCondition::Success),
        edge(password.id, failure.id, EdgeCondition::Failure),
    ];
    let start_id = start.id;
    flow(
        realm,
        alias::REGISTRATION,
        "Registration",
        start_id,
        edges,
        vec![start, render_form, password, success, failure],
    )
}

/// `reset-credentials` — magic-link email + new password entry.
pub fn reset_credentials(realm: RealmId) -> FlowDefinition {
    let start = node_start();
    let render_form = node_render("email entry", "reset-credentials/email");
    let magic = node_authn("magic-link verify", urn::MAGIC_LINK, Requirement::Required);
    let render_new = node_render("new password", "reset-credentials/new-password");
    let password = node_authn("set new password", urn::PASSWORD, Requirement::Required);
    let success = node_success();
    let failure = node_failure("reset failed");
    let edges = vec![
        edge(start.id, render_form.id, EdgeCondition::Otherwise),
        edge(render_form.id, magic.id, EdgeCondition::Success),
        edge(magic.id, render_new.id, EdgeCondition::Success),
        edge(magic.id, failure.id, EdgeCondition::Failure),
        edge(render_new.id, password.id, EdgeCondition::Success),
        edge(password.id, success.id, EdgeCondition::Success),
        edge(password.id, failure.id, EdgeCondition::Failure),
    ];
    let start_id = start.id;
    flow(
        realm,
        alias::RESET_CREDENTIALS,
        "Reset credentials",
        start_id,
        edges,
        vec![
            start,
            render_form,
            magic,
            render_new,
            password,
            success,
            failure,
        ],
    )
}

/// `first-broker-login` — first sign-in via an external IdP. IdP
/// redirect produces broker assertion → user provisioned → success.
pub fn first_broker_login(realm: RealmId) -> FlowDefinition {
    let start = node_start();
    let idp = node_authn("idp redirect", urn::IDP_REDIRECT, Requirement::Required);
    let success = node_success();
    let failure = node_failure("broker login failed");
    let edges = vec![
        edge(start.id, idp.id, EdgeCondition::Otherwise),
        edge(idp.id, success.id, EdgeCondition::Success),
        edge(idp.id, failure.id, EdgeCondition::Failure),
    ];
    let start_id = start.id;
    flow(
        realm,
        alias::FIRST_BROKER_LOGIN,
        "First broker login",
        start_id,
        edges,
        vec![start, idp, success, failure],
    )
}

/// `client-authentication` — token endpoint client authentication
/// (alternative to the built-in `client_secret_basic` path; flows
/// here are how a deployment opts into private-key-jwt or
/// client-secret-jwt schemes at the admin level).
pub fn client_authentication(realm: RealmId) -> FlowDefinition {
    let start = node_start();
    let auth = node_authn(
        "client authentication",
        urn::CLIENT_AUTH,
        Requirement::Required,
    );
    let success = node_success();
    let failure = node_failure("client authentication failed");
    let edges = vec![
        edge(start.id, auth.id, EdgeCondition::Otherwise),
        edge(auth.id, success.id, EdgeCondition::Success),
        edge(auth.id, failure.id, EdgeCondition::Failure),
    ];
    let start_id = start.id;
    flow(
        realm,
        alias::CLIENT_AUTHENTICATION,
        "Client authentication",
        start_id,
        edges,
        vec![start, auth, success, failure],
    )
}

/// `step-up` — additional factor on top of an existing session. Used
/// when an authorize request carries `acr_values` higher than the
/// session's current `authn_level`. The OTP step has a guarded edge
/// that goes to Success only when the bumped authn_level satisfies the
/// request — guarding is wired in v0.1.x once the OAuth layer threads
/// the requested ACR into FlowContext.
pub fn step_up(realm: RealmId) -> FlowDefinition {
    let start = node_start();
    let otp = node_authn("otp", urn::OTP, Requirement::Required);
    let success = node_success();
    let failure = node_failure("step-up failed");
    let edges = vec![
        edge(start.id, otp.id, EdgeCondition::Otherwise),
        edge(otp.id, success.id, EdgeCondition::Success),
        edge(otp.id, failure.id, EdgeCondition::Failure),
    ];
    let start_id = start.id;
    flow(
        realm,
        alias::STEP_UP,
        "Step-up",
        start_id,
        edges,
        vec![start, otp, success, failure],
    )
}

// ---- Helpers ----

fn node_start() -> FlowNode {
    FlowNode {
        id: NodeId::new(),
        display_name: "Start".into(),
        kind: NodeKind::Start(StartNode::default()),
        requirement: Requirement::Required,
        config: serde_json::Value::Null,
        layout: None,
    }
}

fn node_success() -> FlowNode {
    FlowNode {
        id: NodeId::new(),
        display_name: "Success".into(),
        kind: NodeKind::Success(SuccessNode::default()),
        requirement: Requirement::Required,
        config: serde_json::Value::Null,
        layout: None,
    }
}

fn node_failure(reason: &str) -> FlowNode {
    FlowNode {
        id: NodeId::new(),
        display_name: "Failure".into(),
        kind: NodeKind::Failure {
            reason: reason.into(),
        },
        requirement: Requirement::Required,
        config: serde_json::Value::Null,
        layout: None,
    }
}

fn node_render(display: &str, template: &str) -> FlowNode {
    FlowNode {
        id: NodeId::new(),
        display_name: display.into(),
        kind: NodeKind::Render {
            template: template.into(),
        },
        requirement: Requirement::Required,
        config: serde_json::Value::Null,
        layout: None,
    }
}

fn node_authn(display: &str, urn: &str, req: Requirement) -> FlowNode {
    FlowNode {
        id: NodeId::new(),
        display_name: display.into(),
        kind: NodeKind::Authenticator {
            provider_urn: urn.into(),
        },
        requirement: req,
        config: serde_json::Value::Null,
        layout: None,
    }
}

fn edge(from: NodeId, to: NodeId, on: EdgeCondition) -> Edge {
    Edge {
        from,
        to,
        on,
        guard: BTreeMap::new(),
    }
}

fn flow(
    realm: RealmId,
    alias: &str,
    display_name: &str,
    start_id: NodeId,
    edges: Vec<Edge>,
    nodes: Vec<FlowNode>,
) -> FlowDefinition {
    FlowDefinition {
        id: FlowId::new(),
        realm_id: realm,
        alias: alias.into(),
        display_name: display_name.into(),
        version: 1,
        start: start_id,
        nodes,
        edges,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile;

    #[test]
    fn v0_1_flows_returns_seven_flows() {
        let realm = RealmId::new();
        let flows = v0_1_flows(realm);
        assert_eq!(flows.len(), 7);
        let aliases: Vec<&str> = flows.iter().map(|f| f.alias.as_str()).collect();
        assert!(aliases.contains(&alias::BROWSER));
        assert!(aliases.contains(&alias::DIRECT_GRANT));
        assert!(aliases.contains(&alias::REGISTRATION));
        assert!(aliases.contains(&alias::RESET_CREDENTIALS));
        assert!(aliases.contains(&alias::FIRST_BROKER_LOGIN));
        assert!(aliases.contains(&alias::CLIENT_AUTHENTICATION));
        assert!(aliases.contains(&alias::STEP_UP));
    }

    #[test]
    fn every_built_in_flow_compiles() {
        let realm = RealmId::new();
        for flow in v0_1_flows(realm) {
            let alias = flow.alias.clone();
            compile(flow)
                .unwrap_or_else(|e| panic!("built-in flow {alias} failed to compile: {e}"));
        }
    }

    #[test]
    fn every_flow_has_distinct_id_and_realm_bound() {
        let realm = RealmId::new();
        let flows = v0_1_flows(realm);
        let mut ids: Vec<_> = flows.iter().map(|f| f.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 7);
        for f in &flows {
            assert_eq!(f.realm_id, realm);
            assert_eq!(f.version, 1);
        }
    }
}
