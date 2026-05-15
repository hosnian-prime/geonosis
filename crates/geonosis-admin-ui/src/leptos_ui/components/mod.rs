//! Reusable presentation primitives for the admin console.
//!
//! Each module owns one design-system primitive (a piece of chrome,
//! a form widget, a layout wrapper) and is the only place the
//! corresponding markup lives — pages compose these instead of
//! repeating tag soup. This is the DRY discipline the spec calls out
//! in §1.4: every component uses CSS-custom-property tokens, so a
//! palette change in `tokens.css` ripples through automatically.

pub mod breadcrumb;
pub mod chrome;
pub mod flow_canvas;
pub mod form;
pub mod layout;
pub mod list_table;
pub mod nav;
pub mod page_header;
pub mod tabs;
pub mod widgets;
