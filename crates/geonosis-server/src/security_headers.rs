//! Default security response headers — CSP, X-Content-Type-Options,
//! Referrer-Policy, X-Frame-Options. Per `docs/08-admin-ui.md` §"Theme
//! sandbox threat model": every Geonosis-served page emits a strict
//! CSP, themes declare extras via `csp_extra`, and the host audits
//! those at install time. v0.1 ships the doc-default CSP; the theme
//! audit + per-request nonce live behind the `geonosis:ui-component`
//! WIT contract that lands together with the WASM-backed `Surface`
//! renderer.
//!
//! API surface: a single `axum::middleware::from_fn` factory the
//! router wraps around every response. Static assets keep the same
//! headers — `style-src 'self'` covers the embedded admin.css and
//! `script-src 'self'` covers the flow-editor island.
//!
//! Why hand-roll instead of pulling `tower-helmet`: the doc lists
//! the exact directives, the policy is realm-wide, and a 25-line
//! middleware keeps the dependency footprint flat. When themes
//! start declaring `csp_extra`, this module grows a merger; the
//! contract — "emit secure defaults from the server" — stays here.

use axum::extract::Request;
use axum::http::header::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

/// The default Content-Security-Policy. Matches the doc:
/// - `default-src 'self'` — every fetch defaults to same-origin.
/// - `script-src 'self'` — the flow-editor island ships as
///   `/static/flow-editor.js`; no inline scripts permitted.
/// - `style-src 'self'` — design tokens come from `/static/admin.css`.
/// - `img-src 'self' data:` — `data:` covers favicons + small SVGs
///   the admin UI inlines.
/// - `connect-src 'self'` — REST stays same-origin in v0.1.
/// - `frame-ancestors 'none'` — Geonosis is never embedded.
/// - `base-uri 'self'` + `form-action 'self'` — defeat dangling-base
///   and form-hijacking attacks.
/// - `object-src 'none'` — no plugins, no Flash, ever.
const DEFAULT_CSP: &str = concat!(
    "default-src 'self'; ",
    "script-src 'self'; ",
    "style-src 'self'; ",
    "img-src 'self' data:; ",
    "font-src 'self' data:; ",
    "connect-src 'self'; ",
    "frame-ancestors 'none'; ",
    "base-uri 'self'; ",
    "form-action 'self'; ",
    "object-src 'none'",
);

/// Apply the standard set of security headers to every response.
/// Idempotent: if a handler already set one of these headers, the
/// existing value wins (handlers know more than this middleware).
pub async fn apply(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    set_if_absent(headers, "content-security-policy", DEFAULT_CSP);
    set_if_absent(headers, "x-content-type-options", "nosniff");
    set_if_absent(headers, "referrer-policy", "no-referrer");
    set_if_absent(headers, "x-frame-options", "DENY");
    set_if_absent(headers, "cross-origin-opener-policy", "same-origin");
    response
}

fn set_if_absent(
    headers: &mut axum::http::HeaderMap,
    name: &'static str,
    value: &'static str,
) {
    let name = HeaderName::from_static(name);
    if headers.contains_key(&name) {
        return;
    }
    headers.insert(name, HeaderValue::from_static(value));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_csp_contains_doc_required_directives() {
        // Per docs/08-admin-ui.md the theme threat model demands these.
        for needle in [
            "default-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "object-src 'none'",
        ] {
            assert!(DEFAULT_CSP.contains(needle), "missing directive: {needle}");
        }
    }
}
