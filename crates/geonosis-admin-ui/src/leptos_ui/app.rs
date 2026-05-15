//! Top-level Leptos `App` shell wrapper.
//!
//! Wraps individual page components in the persistent admin chrome
//! (header + sidebar + main slot) and threads page metadata (title,
//! breadcrumb, active section, profile, realm options) through to
//! the layout.

use leptos::prelude::*;

use crate::leptos_ui::components::breadcrumb::{Breadcrumb, Crumb};
use crate::leptos_ui::components::chrome::{ProfileContext, RealmChoice};
use crate::leptos_ui::components::layout::AdminLayout;

#[derive(Clone, Debug, Default)]
pub struct PageContext {
    pub title: String,
    pub active_section: &'static str,
    pub realm_slug: Option<String>,
    /// All realms — populates the header dropdown.
    pub realms: Vec<RealmChoice>,
    /// Authenticated user metadata for the profile avatar.
    pub profile: ProfileContext,
    /// Breadcrumb trail. The page is responsible for terminating it
    /// with a `Crumb::Current` entry.
    pub crumbs: Vec<Crumb>,
}

impl PageContext {
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    pub fn with_section(mut self, section: &'static str) -> Self {
        self.active_section = section;
        self
    }

    pub fn with_realm(mut self, slug: impl Into<String>) -> Self {
        self.realm_slug = Some(slug.into());
        self
    }

    pub fn with_crumbs(mut self, crumbs: Vec<Crumb>) -> Self {
        self.crumbs = crumbs;
        self
    }

    pub fn with_realms(mut self, realms: Vec<RealmChoice>) -> Self {
        self.realms = realms;
        self
    }

    pub fn with_profile(mut self, profile: ProfileContext) -> Self {
        self.profile = profile;
        self
    }
}

#[component]
pub fn Page(context: PageContext, children: Children) -> impl IntoView {
    let realm_slug = context.realm_slug.clone().unwrap_or_default();
    view! {
        <AdminLayout
            title=context.title.clone()
            active_section=context.active_section
            realm_slug=realm_slug
            realms=context.realms
            profile=context.profile
        >
            <Breadcrumb crumbs=context.crumbs/>
            {children()}
        </AdminLayout>
    }
}
