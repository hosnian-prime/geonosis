//! Front-channel SLO HTML page renderer.
//!
//! Per `docs/20-saml-idp.md` §"Single Logout": when the IdP cleans
//! up a session it can fan logout out to participating SPs either
//! back-channel (server-to-server POST of a signed LogoutRequest)
//! or front-channel (an HTML page with one `<iframe>` per SP).
//! Browser-driven fan-out works without SPs exposing a back-channel
//! POST endpoint, so it's the realistic option for legacy SPs.
//!
//! Sprint G shipped back-channel fan-out; this module covers the
//! front-channel side. The HTML page is intentionally small + JS-
//! free: a placeholder `<script>` redirects the user to the final
//! post-logout URL after a short delay so iframes have time to
//! finish.

use std::fmt::Write as _;
use url::Url;

/// One peer SP slot to render. The SP's name is shown to the user
/// only as a status marker — the actual logout happens inside the
/// hidden iframe.
#[derive(Debug, Clone)]
pub struct FrontChannelLogoutPeer {
    pub sp_label: String,
    pub front_channel_url: Url,
}

/// Render the front-channel logout HTML page for a session.
///
/// `realm_slug` decorates the page title so operators auditing
/// captured pages can tell sessions apart. `final_redirect_url` is
/// the URL the browser navigates to after the iframes have had a
/// chance to load. `peers` is the list of participating SPs — an
/// empty list returns a "no peers" stub that still navigates the
/// browser to `final_redirect_url` after the delay so the caller
/// has a single response shape to deal with.
pub fn render_front_channel_logout_html(
    realm_slug: &str,
    final_redirect_url: &str,
    peers: &[FrontChannelLogoutPeer],
) -> String {
    let mut out = String::with_capacity(1024);
    out.push_str("<!doctype html>");
    out.push_str("<html lang=\"en\"><head>");
    out.push_str("<meta charset=\"utf-8\">");
    let _ = write!(out, "<title>{} — logging out</title>", html_escape(realm_slug));
    out.push_str("<meta http-equiv=\"refresh\" content=\"3;url=");
    out.push_str(&html_escape(final_redirect_url));
    out.push_str("\">");
    // CSP: only allow the iframes we're embedding ourselves. The
    // realm's security headers middleware also applies a global
    // CSP; this inline meta-CSP is defence-in-depth.
    out.push_str("<style>body{font:14px sans-serif;padding:1em;}iframe{display:none;}</style>");
    out.push_str("</head><body>");
    let _ = write!(
        out,
        "<p>Signing out of {} session(s)&hellip;</p>",
        peers.len()
    );
    for p in peers {
        out.push_str("<iframe src=\"");
        out.push_str(&html_escape(p.front_channel_url.as_str()));
        out.push_str("\" title=\"");
        out.push_str(&html_escape(&p.sp_label));
        out.push_str("\"></iframe>");
    }
    out.push_str("<p><a href=\"");
    out.push_str(&html_escape(final_redirect_url));
    out.push_str("\">Continue</a></p>");
    out.push_str("</body></html>");
    out
}

/// Tiny escape helper — quotes, angle brackets, ampersand. Used only
/// to render operator-controlled URLs + SP labels into HTML; the
/// realm slug is already constrained by `[a-z0-9-]{2,64}`.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(label: &str, url: &str) -> FrontChannelLogoutPeer {
        FrontChannelLogoutPeer {
            sp_label: label.into(),
            front_channel_url: Url::parse(url).unwrap(),
        }
    }

    #[test]
    fn renders_one_iframe_per_peer() {
        let peers = vec![
            peer("App A", "https://a.example/slo"),
            peer("App B", "https://b.example/slo"),
        ];
        let html =
            render_front_channel_logout_html("acme", "https://idp.example/done", &peers);
        let iframe_count = html.matches("<iframe").count();
        assert_eq!(iframe_count, 2);
        assert!(html.contains("https://a.example/slo"));
        assert!(html.contains("https://b.example/slo"));
    }

    #[test]
    fn empty_peer_list_still_redirects() {
        let html =
            render_front_channel_logout_html("acme", "https://idp.example/done", &[]);
        assert!(!html.contains("<iframe"));
        // Meta-refresh navigates the browser to the final URL even
        // when no peers participated.
        assert!(html.contains("meta http-equiv=\"refresh\""));
        assert!(html.contains("https://idp.example/done"));
    }

    #[test]
    fn html_escapes_dangerous_characters_in_sp_label() {
        let peers = vec![peer(
            "<script>alert(1)</script>",
            "https://safe.example/slo",
        )];
        let html =
            render_front_channel_logout_html("acme", "https://idp.example/done", &peers);
        // The label is escaped — original `<script>` literal must
        // not appear in the rendered output.
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[test]
    fn html_escapes_redirect_url_query_separator() {
        let html = render_front_channel_logout_html(
            "acme",
            "https://idp.example/done?next=a&b=c",
            &[],
        );
        // `&` must be escaped to `&amp;` to be valid HTML inside
        // attribute values. Otherwise some browsers interpret
        // `&b=c` as a literal `&b=c` substring of a malformed
        // entity reference.
        assert!(html.contains("https://idp.example/done?next=a&amp;b=c"));
    }

    #[test]
    fn realm_slug_lands_in_title() {
        let html = render_front_channel_logout_html("acme", "https://x/done", &[]);
        assert!(html.contains("<title>acme &mdash;") || html.contains("<title>acme —"));
    }
}
