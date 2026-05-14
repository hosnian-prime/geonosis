//! Embedded static assets — design tokens + the small bit of JS the
//! flow editor needs. v0.1 keeps the asset payload tiny so the admin
//! page loads under 50 KB on first paint.

use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "assets/"]
pub struct AdminAssets;
