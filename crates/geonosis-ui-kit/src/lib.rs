//! Maud-based component primitives + design tokens.
//!
//! Per `docs/08-admin-ui.md` §"Layered architecture": the ui-kit is the
//! lowest layer (buttons, fields, cards). It exposes Maud component
//! functions that any higher-level surface (admin UI, login pages,
//! themes) composes into.
//!
//! Design-token decisions:
//! - Colors / spacing / type live in `tokens.css`, exposed as CSS
//!   custom properties so themes can override per-realm.
//! - Every component uses **CSS logical properties**
//!   (`margin-inline-start`, `border-block-end`, etc.) so right-to-left
//!   rendering works without per-component changes.

pub mod button;
pub mod card;
pub mod field;
pub mod layout;
pub mod tokens;

pub use button::{button, ButtonKind};
pub use card::card;
pub use field::{field, text_input, FieldKind};
pub use layout::{nav_link, page};
pub use tokens::TOKENS_CSS;
