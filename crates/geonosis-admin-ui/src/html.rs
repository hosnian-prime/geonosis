//! Server-side HTML rendering helpers.

use maud::{html, Markup, PreEscaped};

use geonosis_core::Realm;
use geonosis_i18n::{writing_direction, I18n};
use geonosis_ui_kit::layout::page as ui_page;
use unic_langid::LanguageIdentifier;

pub struct PageCtx<'a> {
    pub lang: LanguageIdentifier,
    pub i18n: &'a I18n,
    pub active: &'a str,
    pub realm_slug: Option<&'a str>,
}

impl<'a> PageCtx<'a> {
    pub fn t(&self, key: &str) -> String {
        self.i18n
            .message(&self.lang, key, None)
            .unwrap_or_else(|_| key.to_string())
    }
}

pub fn page(ctx: &PageCtx, title: &str, body: Markup) -> Markup {
    let _dir = writing_direction(&ctx.lang);
    let lang = ctx.lang.to_string();
    ui_page(title, &lang, ctx.active, ctx.realm_slug, body)
}

pub fn realms_table(ctx: &PageCtx, realms: &[Realm]) -> Markup {
    if realms.is_empty() {
        return html! { p { (ctx.t("admin-realms-empty")) } };
    }
    html! {
        table class="gn-table" {
            thead {
                tr {
                    th { (ctx.t("admin-realm-slug")) }
                    th { (ctx.t("admin-realm-display-name")) }
                    th { (ctx.t("admin-realm-enabled")) }
                    th { (ctx.t("admin-realm-created")) }
                }
            }
            tbody {
                @for r in realms {
                    tr {
                        td { a href=(format!("/admin/realms/{}", r.slug)) { (r.slug) } }
                        td { (r.display_name) }
                        td { @if r.enabled { "yes" } @else { "no" } }
                        td { (r.created_at.to_rfc3339()) }
                    }
                }
            }
        }
    }
}

pub fn empty_section(ctx: &PageCtx, heading: &str, message: &str) -> Markup {
    html! {
        h1 { (ctx.t(heading)) }
        p { (ctx.t(message)) }
    }
}

pub fn flow_editor_mount(realm_slug: &str, alias: &str) -> Markup {
    html! {
        div id="gn-flow-canvas" data-realm=(realm_slug) data-alias=(alias)
            style="background: var(--gn-color-bg-alt); border-radius: var(--gn-radius-md); padding: var(--gn-space-3);" {
            "Loading flow…"
        }
        // Inline script tag is acceptable because the page template owns the
        // CSP nonce; the asset path is content-hashed by the embedder.
        (PreEscaped("<script src=\"/static/flow-editor.js\" defer></script>"))
    }
}
