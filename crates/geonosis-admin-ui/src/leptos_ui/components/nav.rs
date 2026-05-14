//! Sidebar navigation shared by every admin page.

use leptos::prelude::*;

#[component]
pub fn SidebarNav(active: &'static str, #[prop(default = String::new())] realm_slug: String) -> impl IntoView {
    let item = |section: &'static str, label: &'static str, href: String| {
        let class = if section == active {
            "gn-nav__item is-active"
        } else {
            "gn-nav__item"
        };
        view! {
            <a class=class href=href>{label}</a>
        }
    };
    let base = if realm_slug.is_empty() {
        None
    } else {
        Some(format!("/admin-next/realms/{realm_slug}"))
    };
    view! {
        <nav class="gn-nav" aria-label="Admin sections">
            {item("realms", "Realms", "/admin-next/realms".to_string())}
            {base.as_ref().map(|b| view! {
                {item("clients", "Clients", format!("{b}/clients"))}
                {item("users", "Users", format!("{b}/users"))}
                {item("roles", "Roles", format!("{b}/roles"))}
                {item("groups", "Groups", format!("{b}/groups"))}
                {item("orgs", "Organizations", format!("{b}/orgs"))}
                {item("agents", "Agents", format!("{b}/agents"))}
                {item("flows", "Flows", format!("{b}/flows"))}
                {item("idps", "Identity providers", format!("{b}/idps"))}
                {item("spi", "SPI plugins", format!("{b}/spi"))}
                {item("sessions", "Sessions", format!("{b}/sessions"))}
                {item("events", "Audit events", format!("{b}/events"))}
            })}
        </nav>
    }
}
