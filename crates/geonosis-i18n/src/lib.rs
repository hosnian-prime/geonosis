//! Project Fluent (FTL) i18n bundle loader.
//!
//! Per `docs/08-admin-ui.md` §"Internationalization":
//! - All user-facing strings are FTL keys.
//! - Translation bundles ship with this crate; themes may declare an
//!   overlay bundle.
//! - Language negotiation: explicit user pref > realm default >
//!   `Accept-Language` > English.
//!
//! v0.1 ships English + Turkish + German + Arabic (the last as the
//! right-to-left sanity check per the doc's day-one RTL requirement).

use std::collections::HashMap;

use fluent::{bundle::FluentBundle, FluentArgs, FluentResource};
use intl_memoizer::concurrent::IntlLangMemoizer;
use parking_lot::RwLock;
use rust_embed::RustEmbed;
use thiserror::Error;
use unic_langid::LanguageIdentifier;

type ConcurrentBundle = FluentBundle<FluentResource, IntlLangMemoizer>;

#[derive(RustEmbed)]
#[folder = "bundles/"]
struct Bundles;

#[derive(Debug, Error)]
pub enum I18nError {
    #[error("language tag: {0}")]
    Lang(String),
    #[error("parse: {0}")]
    Parse(String),
    #[error("bundle: {0}")]
    Bundle(String),
    #[error("missing key: {0}")]
    Missing(String),
}

pub struct I18n {
    bundles: RwLock<HashMap<LanguageIdentifier, ConcurrentBundle>>,
    fallback: LanguageIdentifier,
}

impl I18n {
    /// Load every bundled FTL file at construction time.
    pub fn load_embedded() -> Result<Self, I18nError> {
        let fallback: LanguageIdentifier = "en"
            .parse()
            .map_err(|e: unic_langid::LanguageIdentifierError| I18nError::Lang(e.to_string()))?;
        let me = Self {
            bundles: RwLock::new(HashMap::new()),
            fallback,
        };

        let mut by_lang: HashMap<String, Vec<(String, String)>> = HashMap::new();
        for file in Bundles::iter() {
            let path = file.to_string();
            let mut parts = path.splitn(2, '/');
            let Some(lang) = parts.next() else { continue };
            let Some(_rest) = parts.next() else { continue };
            let data = Bundles::get(&path).ok_or_else(|| I18nError::Bundle(path.clone()))?;
            let text = String::from_utf8(data.data.into_owned())
                .map_err(|e| I18nError::Parse(e.to_string()))?;
            by_lang.entry(lang.into()).or_default().push((path, text));
        }

        for (lang, files) in by_lang {
            let lid: LanguageIdentifier =
                lang.parse()
                    .map_err(|e: unic_langid::LanguageIdentifierError| {
                        I18nError::Lang(e.to_string())
                    })?;
            let mut bundle = ConcurrentBundle::new_concurrent(vec![lid.clone()]);
            for (path, body) in files {
                let res = FluentResource::try_new(body)
                    .map_err(|(_, errs)| I18nError::Parse(format!("{path}: {errs:?}")))?;
                bundle
                    .add_resource(res)
                    .map_err(|e| I18nError::Bundle(format!("{path}: {e:?}")))?;
            }
            me.bundles.write().insert(lid, bundle);
        }
        Ok(me)
    }

    pub fn supported(&self) -> Vec<LanguageIdentifier> {
        self.bundles.read().keys().cloned().collect()
    }

    /// Negotiate the closest supported language for an `Accept-Language`
    /// header value. Falls back to English when no match is found.
    pub fn negotiate_from_header(&self, header: &str) -> LanguageIdentifier {
        for token in header.split(',') {
            let raw = token.trim().split(';').next().unwrap_or("").trim();
            if raw.is_empty() {
                continue;
            }
            if let Ok(lid) = raw.parse::<LanguageIdentifier>() {
                let bundles = self.bundles.read();
                if bundles.contains_key(&lid) {
                    return lid;
                }
                // Language-only match (`en-GB` → `en`).
                let stripped = LanguageIdentifier::from_parts(lid.language, None, None, &[]);
                if bundles.contains_key(&stripped) {
                    return stripped;
                }
            }
        }
        self.fallback.clone()
    }

    /// Render a message with optional Fluent arguments.
    pub fn message(
        &self,
        lang: &LanguageIdentifier,
        key: &str,
        args: Option<&FluentArgs>,
    ) -> Result<String, I18nError> {
        let bundles = self.bundles.read();
        let bundle = bundles
            .get(lang)
            .or_else(|| bundles.get(&self.fallback))
            .ok_or_else(|| I18nError::Missing(key.into()))?;
        let msg = bundle
            .get_message(key)
            .ok_or_else(|| I18nError::Missing(key.into()))?;
        let pattern = msg.value().ok_or_else(|| I18nError::Missing(key.into()))?;
        let mut errors = Vec::new();
        let out = bundle.format_pattern(pattern, args, &mut errors);
        if !errors.is_empty() {
            tracing::warn!(?errors, key, "fluent format errors");
        }
        Ok(out.into_owned())
    }
}

/// Map an `LanguageIdentifier` to the recommended `dir` attribute
/// (`ltr` / `rtl`). Used by the admin layout to set `<html dir>`.
pub fn writing_direction(lang: &LanguageIdentifier) -> &'static str {
    matches!(lang.language.as_str(), "ar" | "he" | "fa" | "ur")
        .then_some("rtl")
        .unwrap_or("ltr")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_bundled_languages() {
        let i = I18n::load_embedded().expect("load");
        let supported = i.supported();
        assert!(supported.iter().any(|l| l.language.as_str() == "en"));
        assert!(supported.iter().any(|l| l.language.as_str() == "tr"));
        assert!(supported.iter().any(|l| l.language.as_str() == "ar"));
    }

    #[test]
    fn renders_english_default() {
        let i = I18n::load_embedded().unwrap();
        let s = i
            .message(&"en".parse().unwrap(), "admin-realms-heading", None)
            .unwrap();
        assert_eq!(s, "Realms");
    }

    #[test]
    fn renders_turkish_translation() {
        let i = I18n::load_embedded().unwrap();
        let s = i
            .message(&"tr".parse().unwrap(), "admin-realms-heading", None)
            .unwrap();
        assert_eq!(s, "Alanlar");
    }

    #[test]
    fn arabic_is_rtl() {
        assert_eq!(writing_direction(&"ar".parse().unwrap()), "rtl");
        assert_eq!(writing_direction(&"en".parse().unwrap()), "ltr");
    }

    #[test]
    fn accept_language_negotiation() {
        let i = I18n::load_embedded().unwrap();
        let lid = i.negotiate_from_header("fr-FR,en-GB;q=0.9");
        // No French bundle → falls through to `en` (matched via en-GB→en).
        assert_eq!(lid.language.as_str(), "en");

        let lid = i.negotiate_from_header("tr,en;q=0.5");
        assert_eq!(lid.language.as_str(), "tr");
    }
}
