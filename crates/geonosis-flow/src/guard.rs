//! Edge-guard evaluation.
//!
//! Per `docs/06-auth-flows.md` §"Conditional execution": each edge
//! carries an optional `guard` map that filters whether the edge is
//! eligible during `flow.next()` lookup. v0.1 ships the simplest
//! workable semantics: **map-matcher** — every `(path, value)` entry
//! in the guard must equal the corresponding dot-path lookup against
//! the flow context. An empty guard is always taken (preserves the
//! existing "no-guard" behavior).
//!
//! The full expression DSL (boolean operators, comparisons, function
//! calls) lands in v0.1.x via a reserved `"expr"` key. Keeping the
//! v0.1 surface intentionally tiny lets flow authors write the 90%
//! case today without committing to a parser we'll need to maintain
//! forever.
//!
//! Design choices that pin this to v0.1:
//! - Guards are **pure**: no I/O, no clocks. The evaluator can be
//!   called from anywhere (executor hot path, admin dry-run, tests).
//! - Guards are **stateless**: no mutation. Either the edge is taken
//!   or it isn't.
//! - Guards live OUTSIDE the executor's match. The executor calls
//!   `eval_guard(&edge.guard, &context)` only when more than one
//!   edge could match `on`. Single-edge case keeps zero overhead.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::state::FlowContext;

/// Evaluate a guard map against a flow context. Empty guard returns
/// `true` so unguarded edges stay free.
pub fn eval_guard(guard: &BTreeMap<String, Value>, ctx: &FlowContext) -> bool {
    if guard.is_empty() {
        return true;
    }
    let ctx_value = context_as_json(ctx);
    guard
        .iter()
        .all(|(path, expected)| match resolve_path(&ctx_value, path) {
            Some(actual) => json_equals(&actual, expected),
            None => false,
        })
}

/// Project a `FlowContext` to a JSON object so we can dot-path into
/// it consistently. Keeping this projection local avoids requiring
/// every consumer to know the struct shape.
fn context_as_json(ctx: &FlowContext) -> Value {
    serde_json::json!({
        "context": {
            "username": ctx.username,
            "user_id": ctx.user_id,
            "amr": ctx.amr,
            "authn_level": ctx.authn_level,
            "locals": ctx.locals,
        }
    })
}

/// Walk a dot-separated path against a JSON value. `context.user.id`
/// returns the value of `obj["context"]["user"]["id"]` or `None` at
/// the first missing segment.
fn resolve_path(value: &Value, path: &str) -> Option<Value> {
    let mut cursor = value;
    for segment in path.split('.') {
        cursor = cursor.get(segment)?;
    }
    Some(cursor.clone())
}

/// JSON equality with two-direction string ↔ number coercion so flow
/// authors can write `guard: {context.authn_level: 2}` even though
/// `authn_level` is an integer in serde-land.
fn json_equals(actual: &Value, expected: &Value) -> bool {
    if actual == expected {
        return true;
    }
    match (actual, expected) {
        (Value::Number(a), Value::String(b)) | (Value::String(b), Value::Number(a)) => {
            a.to_string() == *b
        }
        (Value::Bool(a), Value::String(b)) | (Value::String(b), Value::Bool(a)) => {
            (*a && b == "true") || (!*a && b == "false")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> FlowContext {
        let mut locals = BTreeMap::new();
        locals.insert("otp_required".into(), Value::Bool(true));
        FlowContext {
            username: Some("padme".into()),
            user_id: Some("01H...".into()),
            amr: vec!["pwd".into()],
            authn_level: 2,
            locals,
        }
    }

    #[test]
    fn empty_guard_is_always_true() {
        assert!(eval_guard(&BTreeMap::new(), &ctx()));
    }

    #[test]
    fn single_field_equality() {
        let mut g = BTreeMap::new();
        g.insert("context.username".into(), Value::String("padme".into()));
        assert!(eval_guard(&g, &ctx()));
    }

    #[test]
    fn missing_path_fails_closed() {
        // Unknown segments must yield false, not silently pass.
        let mut g = BTreeMap::new();
        g.insert("context.nope".into(), Value::String("anything".into()));
        assert!(!eval_guard(&g, &ctx()));
    }

    #[test]
    fn nested_path_into_locals() {
        let mut g = BTreeMap::new();
        g.insert("context.locals.otp_required".into(), Value::Bool(true));
        assert!(eval_guard(&g, &ctx()));
    }

    #[test]
    fn number_string_coercion_both_directions() {
        // Flow authors commonly write numbers as strings in YAML.
        let mut g = BTreeMap::new();
        g.insert("context.authn_level".into(), Value::String("2".into()));
        assert!(eval_guard(&g, &ctx()));

        // And the reverse — number literal against stringified number.
        let mut g2 = BTreeMap::new();
        g2.insert(
            "context.authn_level".into(),
            Value::Number(serde_json::Number::from(2)),
        );
        assert!(eval_guard(&g2, &ctx()));
    }

    #[test]
    fn all_entries_must_pass() {
        let mut g = BTreeMap::new();
        g.insert("context.username".into(), Value::String("padme".into()));
        g.insert("context.user_id".into(), Value::String("WRONG".into()));
        assert!(!eval_guard(&g, &ctx()));
    }

    #[test]
    fn bool_string_coercion() {
        let mut g = BTreeMap::new();
        g.insert(
            "context.locals.otp_required".into(),
            Value::String("true".into()),
        );
        assert!(eval_guard(&g, &ctx()));
    }
}
