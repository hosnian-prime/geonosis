//! `/admin/realms/{slug}/federation` — LDAP source list + per-source detail.

use leptos::prelude::*;

use geonosis_federation_ldap::config::{LdapFederationConfig, TlsPolicy};

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::breadcrumb::Crumb;
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;
use crate::leptos_ui::components::tabs::{TabBar, TabItem};
use crate::leptos_ui::components::widgets::{
    Alert, AlertKind, Badge, BadgeKind, EmptyState, StateBadge,
};

#[derive(Clone, Debug)]
pub struct LdapRow {
    pub alias: String,
    pub server: String,
    pub base_dn: String,
    pub priority: i32,
    pub enabled: bool,
}

#[component]
pub fn FederationPage(realm_slug: String, rows: Vec<LdapRow>, ctx: PageContext) -> impl IntoView {
    let ctx = ctx
        .with_title("Federation")
        .with_section("federation")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::current("Federation"),
        ]);
    let is_empty = rows.is_empty();
    view! {
        <Page context=ctx>
            <PageHeader
                title="LDAP federation".into()
                subtitle=Some("External user directories synchronized into the realm.".into())
            />
            {if is_empty {
                view! {
                    <EmptyState title="No federated sources".into()
                        description="Configure an LDAP federation via the admin API to import users from an external directory.".into()/>
                }.into_any()
            } else {
                view! {
                    <ListTable headers=vec!["Alias", "Server", "Base DN", "Priority", "State"]>
                        {rows.into_iter().map(|r| {
                            let href = format!("/admin/realms/{realm_slug}/federation/{}", r.alias);
                            view! {
                                <tr>
                                    <td data-label="Alias"><a href=href.clone()><code>{r.alias}</code></a></td>
                                    <td data-label="Server"><code class="gn-truncate">{r.server}</code></td>
                                    <td data-label="Base DN"><code class="gn-truncate">{r.base_dn}</code></td>
                                    <td data-label="Priority">{r.priority.to_string()}</td>
                                    <td data-label="State"><StateBadge enabled=r.enabled/></td>
                                </tr>
                            }
                        }).collect_view()}
                    </ListTable>
                }.into_any()
            }}
        </Page>
    }
}

pub const LDAP_TABS: &[(&str, &str)] = &[
    ("connection", "Connection"),
    ("mapping", "Attribute mapping"),
    ("sync", "Sync"),
];

#[component]
pub fn LdapDetailPage(
    realm_slug: String,
    cfg: LdapFederationConfig,
    active_tab: String,
    ctx: PageContext,
) -> impl IntoView {
    let alias = cfg.alias.clone();
    let ctx = ctx
        .with_title(format!("LDAP · {alias}"))
        .with_section("federation")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::link(
                "Federation",
                format!("/admin/realms/{realm_slug}/federation"),
            ),
            Crumb::current(alias.clone()),
        ]);
    let tab_items = LDAP_TABS
        .iter()
        .map(|(k, l)| {
            TabItem::new(
                *k,
                *l,
                format!("/admin/realms/{realm_slug}/federation/{alias}?tab={k}"),
            )
        })
        .collect::<Vec<_>>();
    let panel = match active_tab.as_str() {
        "connection" => render_connection(cfg.clone()).into_any(),
        "mapping" => render_mapping(cfg.clone()).into_any(),
        "sync" => render_sync(cfg.clone()).into_any(),
        _ => view! { <Alert message="Unknown tab.".into() kind=AlertKind::Warning/> }.into_any(),
    };
    let tls = match cfg.tls {
        TlsPolicy::None => "no TLS",
        TlsPolicy::StartTls => "StartTLS",
        TlsPolicy::Ldaps => "LDAPS",
    };
    view! {
        <Page context=ctx>
            <PageHeader
                title=alias.clone()
                subtitle=Some(format!("{} · {tls}", cfg.urls.first().cloned().unwrap_or_default()))
            />
            <TabBar active=active_tab.clone() items=tab_items/>
            {panel}
        </Page>
    }
}

fn render_connection(c: LdapFederationConfig) -> impl IntoView {
    let urls = c.urls.join(", ");
    let bind_dn = c.bind_dn.clone().unwrap_or_default();
    view! {
        <dl class="gn-defs">
            <dt>"Server URLs"</dt><dd><code>{urls}</code></dd>
            <dt>"Base DN"</dt><dd><code>{c.base_dn.clone()}</code></dd>
            <dt>"Bind DN"</dt><dd><code>{bind_dn}</code></dd>
            <dt>"User filter"</dt><dd><code>{c.user_filter.clone()}</code></dd>
            <dt>"Page size"</dt><dd>{c.page_size.to_string()}</dd>
            <dt>"Pool size"</dt><dd>{c.pool_size.to_string()}</dd>
            <dt>"Bind timeout"</dt><dd>{format!("{}ms", c.bind_timeout_ms)}</dd>
            <dt>"Search timeout"</dt><dd>{format!("{}ms", c.search_timeout_ms)}</dd>
        </dl>
    }
}

fn render_mapping(c: LdapFederationConfig) -> impl IntoView {
    let m = c.attribute_map;
    let custom = m
        .extras
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect::<Vec<_>>();
    let custom_section = if custom.is_empty() {
        view! { <p class="gn-text-muted">"No custom mappings."</p> }.into_any()
    } else {
        view! {
            <ListTable headers=vec!["LDAP attribute", "Geonosis key"]>
                {custom.into_iter().map(|(k, v)| view! {
                    <tr>
                        <td data-label="LDAP"><code>{k}</code></td>
                        <td data-label="Geonosis"><code>{v}</code></td>
                    </tr>
                }).collect_view()}
            </ListTable>
        }
        .into_any()
    };
    view! {
        <div class="gn-stack">
            <ListTable headers=vec!["LDAP attribute", "Geonosis field"]>
                <tr><td data-label="LDAP"><code>{m.username.clone()}</code></td><td data-label="Field"><code>"username"</code></td></tr>
                {m.email.clone().map(|v| view! { <tr><td data-label="LDAP"><code>{v}</code></td><td data-label="Field"><code>"email"</code></td></tr> })}
                {m.first_name.clone().map(|v| view! { <tr><td data-label="LDAP"><code>{v}</code></td><td data-label="Field"><code>"first_name"</code></td></tr> })}
                {m.last_name.clone().map(|v| view! { <tr><td data-label="LDAP"><code>{v}</code></td><td data-label="Field"><code>"last_name"</code></td></tr> })}
            </ListTable>
            <h2>"Custom attributes"</h2>
            {custom_section}
        </div>
    }
}

fn render_sync(c: LdapFederationConfig) -> impl IntoView {
    let group_sync_state = if c.group_sync.is_some() {
        view! { <Badge label="enabled".into() kind=BadgeKind::Success/> }.into_any()
    } else {
        view! { <Badge label="disabled".into() kind=BadgeKind::Neutral/> }.into_any()
    };
    let policy = serde_json::to_string_pretty(&c.sync_policy).unwrap_or_default();
    view! {
        <div class="gn-stack">
            <dl class="gn-defs">
                <dt>"Group sync"</dt><dd>{group_sync_state}</dd>
                <dt>"Write policy"</dt><dd><code>{format!("{:?}", c.write_policy)}</code></dd>
            </dl>
            <h2>"Sync policy"</h2>
            <pre class="gn-json">{policy}</pre>
        </div>
    }
}
