//! Theme overlay engine.
//!
//! Per `docs/08-admin-ui.md` §"Component overrides (themes)":
//! - A `Theme` is a directory with `theme.toml`, plus `login/`,
//!   `email/` etc. subdirectories.
//! - Template lookups fall through `theme → parent_theme → builtin`.
//! - Templates are HTML fragments named by their slot
//!   (`login/login.html`, `login/otp.html`, …).
//!
//! v0.1 ships the read-side: `Theme::load_dir`, `TemplateOverlay::find`.
//! Hot-reload via `notify` + file-watcher lands when the admin UI
//! consumes the overlay (next minor release).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ThemeError {
    #[error("io: {0}")]
    Io(String),
    #[error("toml: {0}")]
    Toml(String),
    #[error("invalid theme: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemeMeta {
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub parent: Option<String>,
    /// Additional CSP entries the theme needs — audited at install
    /// time. Servers reject themes that ask for `default-src 'unsafe-inline'`
    /// or third-party origins beyond an explicit allowlist.
    #[serde(default)]
    pub csp_extra: Vec<String>,
    #[serde(default)]
    pub locales: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Theme {
    pub meta: ThemeMeta,
    pub root: PathBuf,
}

impl Theme {
    /// Load a theme from disk. The directory must contain a
    /// `theme.toml`. Subdirectories (`login/`, `email/`, …) are
    /// optional and discovered lazily.
    pub fn load_dir(root: impl AsRef<Path>) -> Result<Self, ThemeError> {
        let root = root.as_ref().to_path_buf();
        let toml_path = root.join("theme.toml");
        let bytes = std::fs::read(&toml_path).map_err(|e| ThemeError::Io(e.to_string()))?;
        let meta: ThemeMeta = toml::from_str(
            std::str::from_utf8(&bytes).map_err(|e| ThemeError::Toml(e.to_string()))?,
        )
        .map_err(|e| ThemeError::Toml(e.to_string()))?;
        if meta.name.is_empty() {
            return Err(ThemeError::Invalid("name is empty".into()));
        }
        Ok(Self { meta, root })
    }

    /// Locate a template relative to the theme root. Returns `None` if
    /// the file does not exist (caller falls through to parent or
    /// builtin).
    pub fn template_path(&self, slot: &str) -> Option<PathBuf> {
        let p = self.root.join(slot);
        p.is_file().then_some(p)
    }

    pub fn read_template(&self, slot: &str) -> Result<Option<String>, ThemeError> {
        match self.template_path(slot) {
            Some(p) => {
                let bytes = std::fs::read(&p).map_err(|e| ThemeError::Io(e.to_string()))?;
                Ok(Some(
                    String::from_utf8(bytes).map_err(|e| ThemeError::Invalid(e.to_string()))?,
                ))
            }
            None => Ok(None),
        }
    }
}

/// Overlay registry — keyed by theme name, with a built-in fallback.
#[derive(Default)]
pub struct TemplateOverlay {
    themes: RwLock<HashMap<String, Theme>>,
    builtin: RwLock<HashMap<String, String>>,
}

impl TemplateOverlay {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_builtin(&self, slot: &str, body: &str) {
        self.builtin
            .write()
            .insert(slot.to_string(), body.to_string());
    }

    pub fn register_theme(&self, theme: Theme) {
        self.themes.write().insert(theme.meta.name.clone(), theme);
    }

    /// Resolve a slot following the theme → parent → builtin chain.
    pub fn find(
        &self,
        active_theme: Option<&str>,
        slot: &str,
    ) -> Result<Option<String>, ThemeError> {
        if let Some(name) = active_theme {
            let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
            let mut next = Some(name.to_string());
            while let Some(t) = next {
                if !visited.insert(t.clone()) {
                    // Cycle — bail.
                    return Err(ThemeError::Invalid(format!("parent cycle through {t}")));
                }
                let themes = self.themes.read();
                let Some(theme) = themes.get(&t) else {
                    break;
                };
                if let Some(s) = theme.read_template(slot)? {
                    return Ok(Some(s));
                }
                next = theme.meta.parent.clone();
            }
        }
        Ok(self.builtin.read().get(slot).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn loads_theme_meta_from_dir() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("theme.toml"),
            r#"name = "acme"
display_name = "Acme"
"#,
        )
        .unwrap();
        let t = Theme::load_dir(dir.path()).unwrap();
        assert_eq!(t.meta.name, "acme");
        assert_eq!(t.meta.display_name.as_deref(), Some("Acme"));
    }

    #[test]
    fn overlay_falls_through_to_builtin() {
        let overlay = TemplateOverlay::new();
        overlay.register_builtin("login/login.html", "<p>builtin</p>");
        let got = overlay.find(None, "login/login.html").unwrap();
        assert_eq!(got.as_deref(), Some("<p>builtin</p>"));
    }

    #[test]
    fn overlay_uses_theme_when_present() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("theme.toml"), "name = \"acme\"\n").unwrap();
        fs::create_dir(dir.path().join("login")).unwrap();
        fs::write(dir.path().join("login/login.html"), "<p>themed</p>").unwrap();
        let overlay = TemplateOverlay::new();
        overlay.register_builtin("login/login.html", "<p>builtin</p>");
        overlay.register_theme(Theme::load_dir(dir.path()).unwrap());
        let got = overlay.find(Some("acme"), "login/login.html").unwrap();
        assert_eq!(got.as_deref(), Some("<p>themed</p>"));
    }

    #[test]
    fn parent_chain_resolves() {
        let parent_dir = tempdir().unwrap();
        fs::write(parent_dir.path().join("theme.toml"), "name = \"base\"\n").unwrap();
        fs::create_dir(parent_dir.path().join("login")).unwrap();
        fs::write(
            parent_dir.path().join("login/login.html"),
            "<p>from base</p>",
        )
        .unwrap();
        let child_dir = tempdir().unwrap();
        fs::write(
            child_dir.path().join("theme.toml"),
            "name = \"child\"\nparent = \"base\"\n",
        )
        .unwrap();
        let overlay = TemplateOverlay::new();
        overlay.register_theme(Theme::load_dir(parent_dir.path()).unwrap());
        overlay.register_theme(Theme::load_dir(child_dir.path()).unwrap());
        let got = overlay.find(Some("child"), "login/login.html").unwrap();
        assert_eq!(got.as_deref(), Some("<p>from base</p>"));
    }
}
