//! `/admin/realms/{slug}` — realm overview dashboard. Per
//! `docs/08-admin-ui.md` §2.1 this page shows quick stats and
//! deep-links into the sub-sections (Clients, Users, Roles, ...) so
//! operators can land here, glance at the realm state, and jump.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::breadcrumb::Crumb;
use crate::leptos_ui::components::page_header::PageHeader;
use crate::leptos_ui::components::widgets::{LinkButton, LinkCard, StatCard, StateBadge};

#[derive(Clone, Debug, Default)]
pub struct RealmDetailData {
    pub slug: String,
    pub display_name: String,
    pub enabled: bool,
    pub organizations_enabled: bool,
    pub frontend_url: Option<String>,
    pub user_count: usize,
    pub client_count: usize,
    pub session_count: usize,
    pub role_count: usize,
    pub group_count: usize,
    pub org_count: usize,
    pub agent_count: usize,
    pub idp_count: usize,
    pub flow_count: usize,
}

#[component]
pub fn RealmDetailPage(data: RealmDetailData, ctx: PageContext) -> impl IntoView {
    let slug = data.slug.clone();
    let display = data.display_name.clone();
    let ctx = ctx
        .with_title(display.clone())
        .with_section("realms")
        .with_realm(slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::current(display.clone()),
        ]);
    let settings = format!("/admin/realms/{slug}/settings");
    let edit_actions = Some(
        view! {
            <LinkButton href=settings label="Settings".to_string()/>
        }
        .into_any(),
    );

    let card = move |path: &'static str, title: &'static str, desc: &'static str, count: usize| {
        let href = format!("/admin/realms/{slug}/{path}");
        view! {
            <LinkCard
                href=href
                title=title.into()
                description=desc.into()
                count=Some(count.to_string())
            />
        }
    };

    view! {
        <Page context=ctx>
            <PageHeader
                title=display
                subtitle=Some(format!("Slug: {}", data.slug.clone()))
                actions=edit_actions
            />

            <section class="gn-section">
                <div class="gn-card-grid">
                    <StatCard label="Users".into() value=data.user_count.to_string()
                        hint=Some("registered identities".into())/>
                    <StatCard label="Clients".into() value=data.client_count.to_string()
                        hint=Some("OAuth + SAML apps".into())/>
                    <StatCard label="Active sessions".into() value=data.session_count.to_string()
                        hint=Some("logged-in right now".into())/>
                </div>
            </section>

            <section class="gn-section">
                <h2>"Status"</h2>
                <dl class="gn-defs">
                    <dt>"Realm"</dt>
                    <dd><StateBadge enabled=data.enabled/></dd>
                    <dt>"Organizations"</dt>
                    <dd><StateBadge enabled=data.organizations_enabled/></dd>
                    {data.frontend_url.clone().map(|u| view! {
                        <dt>"Frontend URL"</dt>
                        <dd><code>{u}</code></dd>
                    })}
                </dl>
            </section>

            <section class="gn-section">
                <h2>"Browse"</h2>
                <div class="gn-card-grid">
                    {card("users", "Users", "People who sign in to apps.", data.user_count)}
                    {card("groups", "Groups", "Hierarchical user collections.", data.group_count)}
                    {card("orgs", "Organizations", "Tenant boundaries within the realm.", data.org_count)}
                    {card("agents", "Agents", "Non-human / AI identities.", data.agent_count)}
                    {card("clients", "Clients", "OAuth and SAML applications.", data.client_count)}
                    {card("roles", "Roles", "Authorisation grants.", data.role_count)}
                    {card("flows", "Flows", "Authentication step graphs.", data.flow_count)}
                    {card("idps", "Identity providers", "Brokered OIDC / SAML logins.", data.idp_count)}
                    {card("sessions", "Sessions", "Live SSO state.", data.session_count)}
                </div>
            </section>

            <section class="gn-section">
                <div class="gn-card">
                    <div class="gn-card__title">"Danger zone"</div>
                    <p class="gn-card__subtitle">
                        "Disabling a realm denies all logins immediately. Deletion drops every user, client and session in this realm."
                    </p>
                    <div class="gn-btn-row">
                        <form method="post" action=format!("/admin/realms/{}/disable", data.slug.clone())
                            data-gn-confirm=format!("Disable realm {} for all users?", data.slug.clone())>
                            <button type="submit" class="gn-btn">"Disable realm"</button>
                        </form>
                        {if data.slug != geonosis_core::MASTER_REALM_SLUG {
                            Some(view! {
                                <form method="post" action=format!("/admin/realms/{}/delete", data.slug.clone())
                                    data-gn-confirm=format!("Delete realm {} permanently? This cannot be undone.", data.slug.clone())>
                                    <button type="submit" class="gn-btn gn-btn--danger">"Delete realm"</button>
                                </form>
                            })
                        } else {
                            None
                        }}
                    </div>
                </div>
            </section>
        </Page>
    }
}
