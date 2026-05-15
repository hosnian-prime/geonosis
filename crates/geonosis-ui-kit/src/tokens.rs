//! Design tokens + base stylesheet served from `/static/admin.css`.
//!
//! The token layer is the single source of truth for color, spacing,
//! type, radius, and shadow values across the admin console and
//! tenant-facing login pages. Per `docs/08-admin-ui.md` §1.4:
//!
//! - **Two themes** — dark (`:root`) and light (`:root[data-theme="light"]`).
//! - **Every color** is defined exactly once per theme via CSS custom
//!   properties. Components reference `var(--gn-color-*)` only; no
//!   hardcoded color values outside the `:root` blocks.
//! - **Theme is applied** by setting `data-theme="light"|"dark"` on
//!   `<html>` (the inline boot script in `layout.rs` reads the
//!   user's persisted choice from `localStorage` and falls back to
//!   `prefers-color-scheme`).
//! - **Typography tokens** match spec §1.5 — base 15 px with a clear
//!   scale up to 36 px for marketing-style stat numbers.
//! - **Responsive** breakpoints at 1024 px (tablet) and 768 px
//!   (mobile) — sidebar collapses behind a hamburger on mobile, the
//!   tables fall back to card layout, and tab bars scroll horizontally.
//!
//! Themes ship their own stylesheet with higher specificity to override
//! any of these values per-realm.

pub const TOKENS_CSS: &str = include_str!("tokens.css");
