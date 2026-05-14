//! Legacy Maud helpers.
//!
//! The admin pages migrated to Leptos in v0.1.x; this module retains
//! only the `PageCtx` struct used by the `handlers_v1` module for
//! locale negotiation. The `realms_table`, `flow_editor_mount`, and
//! `page` helpers retired alongside the legacy Maud HTML routes.

use geonosis_i18n::I18n;
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
