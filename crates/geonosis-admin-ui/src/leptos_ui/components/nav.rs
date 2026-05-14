//! Sidebar navigation shared by every admin page.

use leptos::prelude::*;

#[component]
pub fn SidebarNav(active: &'static str) -> impl IntoView {
    let item = |slug: &'static str, label: &'static str, href: String| {
        let class = if slug == active {
            "gn-nav__item is-active"
        } else {
            "gn-nav__item"
        };
        view! {
            <a class=class href=href>{label}</a>
        }
    };
    view! {
        <nav class="gn-nav" aria-label="Admin sections">
            {item("realms", "Realms", "/admin-next/realms".to_string())}
            {item("clients", "Clients", "/admin-next/clients".to_string())}
            {item("users", "Users", "/admin-next/users".to_string())}
            {item("roles", "Roles", "/admin-next/roles".to_string())}
            {item("groups", "Groups", "/admin-next/groups".to_string())}
            {item("orgs", "Organizations", "/admin-next/orgs".to_string())}
            {item("agents", "Agents", "/admin-next/agents".to_string())}
            {item("flows", "Flows", "/admin-next/flows".to_string())}
            {item("idps", "Identity providers", "/admin-next/idps".to_string())}
            {item("spi", "SPI plugins", "/admin-next/spi".to_string())}
            {item("events", "Audit events", "/admin-next/events".to_string())}
        </nav>
    }
}
