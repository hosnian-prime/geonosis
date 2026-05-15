//! Grouped sidebar nav — per `docs/08-admin-ui.md` §1.2.

use leptos::prelude::*;

#[component]
pub fn SidebarNav(
    active: &'static str,
    #[prop(default = String::new())] realm_slug: String,
) -> impl IntoView {
    let in_realm = !realm_slug.is_empty();
    let in_realm_view = in_realm.then(|| {
        let b = format!("/admin/realms/{realm_slug}");
        // Pre-compute each href so the view! macro doesn't re-borrow
        // the same `base` capture across nested closures.
        let users = format!("{b}/users");
        let groups = format!("{b}/groups");
        let orgs = format!("{b}/orgs");
        let agents = format!("{b}/agents");
        let sessions = format!("{b}/sessions");
        let clients = format!("{b}/clients");
        let roles = format!("{b}/roles");
        let flows = format!("{b}/flows");
        let idps = format!("{b}/idps");
        let federation = format!("{b}/federation");
        let keys = format!("{b}/keys");
        let spi = format!("{b}/spi");
        let events = format!("{b}/events");
        let settings = format!("{b}/settings");
        view! {
            <Group title="Manage">
                <NavItem section="users" active=active label="Users" href=users icon=NavIcon::Users/>
                <NavItem section="groups" active=active label="Groups" href=groups icon=NavIcon::Groups/>
                <NavItem section="orgs" active=active label="Organizations" href=orgs icon=NavIcon::Orgs/>
                <NavItem section="agents" active=active label="Agents" href=agents icon=NavIcon::Agents/>
                <NavItem section="sessions" active=active label="Sessions" href=sessions icon=NavIcon::Sessions/>
            </Group>
            <Group title="Configure">
                <NavItem section="clients" active=active label="Clients" href=clients icon=NavIcon::Clients/>
                <NavItem section="roles" active=active label="Roles" href=roles icon=NavIcon::Roles/>
                <NavItem section="flows" active=active label="Flows" href=flows icon=NavIcon::Flows/>
                <NavItem section="idps" active=active label="Identity providers" href=idps icon=NavIcon::Idps/>
                <NavItem section="federation" active=active label="Federation" href=federation icon=NavIcon::Federation/>
                <NavItem section="keys" active=active label="Keys" href=keys icon=NavIcon::Keys/>
            </Group>
            <Group title="Extensions">
                <NavItem section="spi" active=active label="SPI plugins" href=spi icon=NavIcon::Spi/>
            </Group>
            <Group title="Monitor">
                <NavItem section="events" active=active label="Audit events" href=events icon=NavIcon::Events/>
            </Group>
            <hr style="border:0;border-top:1px solid var(--gn-color-border);margin:12px 8px;"/>
            <NavItem section="settings" active=active label="Settings" href=settings icon=NavIcon::Settings/>
        }
    });
    view! {
        <nav class="gn-nav" aria-label="Admin sections">
            <NavItem
                section="realms"
                active=active
                label="Realms"
                href="/admin/realms".to_string()
                icon=NavIcon::Realms
            />
            {in_realm_view}
        </nav>
    }
}

#[component]
fn Group(title: &'static str, children: Children) -> impl IntoView {
    view! {
        <div class="gn-nav-group">
            <div class="gn-nav-group__header">{title}</div>
            {children()}
        </div>
    }
}

#[component]
fn NavItem(
    section: &'static str,
    active: &'static str,
    label: &'static str,
    href: String,
    icon: NavIcon,
) -> impl IntoView {
    let class = if section == active {
        "gn-nav-item is-active"
    } else {
        "gn-nav-item"
    };
    let aria_current = if section == active { "page" } else { "" };
    view! {
        <a class=class href=href aria-current=aria_current>
            <span class="gn-nav-item__icon">{icon_svg(icon)}</span>
            <span>{label}</span>
        </a>
    }
}

#[derive(Clone, Copy)]
pub enum NavIcon {
    Realms,
    Users,
    Groups,
    Orgs,
    Agents,
    Sessions,
    Clients,
    Roles,
    Flows,
    Idps,
    Federation,
    Keys,
    Spi,
    Events,
    Settings,
}

fn icon_svg(icon: NavIcon) -> impl IntoView {
    let path: &'static str = match icon {
        NavIcon::Realms => "M3 7l9-4 9 4-9 4-9-4zm0 6l9 4 9-4M3 17l9 4 9-4",
        NavIcon::Users => "M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zm14 10v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75",
        NavIcon::Groups => "M22 11v8a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2",
        NavIcon::Orgs => "M3 21h18M5 21V7l8-4v18M19 21V11l-6-4M9 9v.01M9 13v.01M9 17v.01",
        NavIcon::Agents => "M12 8V4H8M5 8h14a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2zM2 14h2M20 14h2M15 13v2M9 13v2",
        NavIcon::Sessions => "M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 5v5l4 2",
        NavIcon::Clients => "M3 3h7v7H3V3zm11 0h7v7h-7V3zM3 14h7v7H3v-7zm11 0h7v7h-7v-7z",
        NavIcon::Roles => "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
        NavIcon::Flows => "M6 3v4M6 7a3 3 0 0 0 3 3h6a3 3 0 0 1 3 3v4M18 21v-4M6 21h12",
        NavIcon::Idps => "M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zM2 12h20M12 2a15 15 0 0 1 4 10 15 15 0 0 1-4 10 15 15 0 0 1-4-10 15 15 0 0 1 4-10z",
        NavIcon::Federation => "M9 7V3M15 7V3M5 12h14M5 12a4 4 0 0 0 4 4h6a4 4 0 0 0 4-4v-2H5v2zM10 16v3a2 2 0 0 0 2 2 2 2 0 0 0 2-2v-3",
        NavIcon::Keys => "M21 2l-2 2-9 9a5 5 0 1 0 4 4l9-9-2-2-3 3-3-3 3-3z",
        NavIcon::Spi => "M19.4 11h-1.4a2 2 0 0 1-2-2v-1.4A2.6 2.6 0 0 0 13.4 5h-2.8A2.6 2.6 0 0 0 8 7.6V9a2 2 0 0 1-2 2H4.6A2.6 2.6 0 0 0 2 13.6v2.8A2.6 2.6 0 0 0 4.6 19H6a2 2 0 0 1 2 2v.4",
        NavIcon::Events => "M3 12h4l3-9 4 18 3-9h4",
        NavIcon::Settings => "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm7 .5a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09a1.65 1.65 0 0 0-1.07-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9.4a1.65 1.65 0 0 0-.33-1.82L4.21 7.52a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z",
    };
    view! {
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
            stroke-linecap="round" stroke-linejoin="round" inner_html=wrap_svg_paths(path)></svg>
    }
}

fn wrap_svg_paths(d: &str) -> String {
    format!(r#"<path d="{d}"/>"#)
}
