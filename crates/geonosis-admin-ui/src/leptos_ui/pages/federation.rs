//! `/admin/realms/{slug}/federation` — LDAP source list + per-source detail.

use leptos::prelude::*;

use geonosis_federation_ldap::config::{LdapFederationConfig, TlsPolicy};

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::breadcrumb::Crumb;
use crate::leptos_ui::components::form::{
    ActionBar, Field, Select, SelectOption, TextInput, Textarea, Toggle,
};
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;
use crate::leptos_ui::components::tabs::{TabBar, TabItem};
use crate::leptos_ui::components::widgets::{
    Alert, AlertKind, EmptyState, LinkButton, StateBadge,
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
        "connection" => render_connection(realm_slug.clone(), cfg.clone()).into_any(),
        "mapping" => render_mapping(realm_slug.clone(), cfg.clone()).into_any(),
        "sync" => render_sync(realm_slug.clone(), cfg.clone()).into_any(),
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

fn form_post(realm_slug: &str, alias: &str, tab: &str) -> String {
    format!("/admin/realms/{realm_slug}/federation/{alias}/{tab}")
}

fn render_connection(realm_slug: String, c: LdapFederationConfig) -> impl IntoView {
    let action = form_post(&realm_slug, &c.alias, "connection");
    let urls = c.urls.join("\n");
    let bind_dn = c.bind_dn.clone().unwrap_or_default();
    let tls_value = match c.tls {
        TlsPolicy::None => "none",
        TlsPolicy::StartTls => "starttls",
        TlsPolicy::Ldaps => "ldaps",
    };
    let cancel = format!("/admin/realms/{realm_slug}/federation");
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Server URLs".into() name="urls".into() required=true
                hint=Some("One URL per line (ldap:// or ldaps://).".into())>
                <Textarea name="urls".into() value=urls rows=3/>
            </Field>
            <Field label="Base DN".into() name="base_dn".into() required=true>
                <TextInput name="base_dn".into() value=c.base_dn.clone() required=true/>
            </Field>
            <Field label="Bind DN".into() name="bind_dn".into()>
                <TextInput name="bind_dn".into() value=bind_dn/>
            </Field>
            <Field label="Bind password".into() name="bind_password".into()
                hint=Some("Leave empty to keep existing password unchanged.".into())>
                <TextInput name="bind_password".into() input_type="password".into()/>
            </Field>
            <Field label="User filter".into() name="user_filter".into()
                hint=Some("LDAP filter with {username} placeholder.".into())>
                <TextInput name="user_filter".into() value=c.user_filter.clone()/>
            </Field>
            <Field label="TLS policy".into() name="tls".into()>
                <Select name="tls".into() value=tls_value.into() options=vec![
                    SelectOption::new("none", "None"),
                    SelectOption::new("starttls", "StartTLS"),
                    SelectOption::new("ldaps", "LDAPS"),
                ]/>
            </Field>
            <Field label="Page size".into() name="page_size".into()>
                <TextInput name="page_size".into() input_type="number".into() value=c.page_size.to_string()/>
            </Field>
            <Field label="Pool size".into() name="pool_size".into()>
                <TextInput name="pool_size".into() input_type="number".into() value=c.pool_size.to_string()/>
            </Field>
            <Field label="Bind timeout (ms)".into() name="bind_timeout_ms".into()>
                <TextInput name="bind_timeout_ms".into() input_type="number".into() value=c.bind_timeout_ms.to_string()/>
            </Field>
            <Field label="Search timeout (ms)".into() name="search_timeout_ms".into()>
                <TextInput name="search_timeout_ms".into() input_type="number".into() value=c.search_timeout_ms.to_string()/>
            </Field>
            <Toggle name="enabled".into() label="Enabled".into() checked=c.enabled/>
            <ActionBar>
                <LinkButton href=cancel label="Cancel".to_string()/>
                <button type="submit" class="gn-btn gn-btn--primary">"Save connection"</button>
            </ActionBar>
        </form>
    }
}

fn render_mapping(realm_slug: String, c: LdapFederationConfig) -> impl IntoView {
    let action = form_post(&realm_slug, &c.alias, "mapping");
    let m = c.attribute_map.clone();
    let extras_text = m
        .extras
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\n");
    let cancel = format!("/admin/realms/{realm_slug}/federation");
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Username attribute".into() name="username".into() required=true
                hint=Some("LDAP attribute for the username (e.g. sAMAccountName, uid).".into())>
                <TextInput name="username".into() value=m.username.clone() required=true/>
            </Field>
            <Field label="Email attribute".into() name="email".into()>
                <TextInput name="email".into() value=m.email.clone().unwrap_or_default() placeholder="mail".into()/>
            </Field>
            <Field label="First name attribute".into() name="first_name".into()>
                <TextInput name="first_name".into() value=m.first_name.clone().unwrap_or_default() placeholder="givenName".into()/>
            </Field>
            <Field label="Last name attribute".into() name="last_name".into()>
                <TextInput name="last_name".into() value=m.last_name.clone().unwrap_or_default() placeholder="sn".into()/>
            </Field>
            <Field label="UID attribute".into() name="uid".into() required=true
                hint=Some("Immutable unique ID attribute (entryUUID, objectGUID).".into())>
                <TextInput name="uid".into() value=m.uid.clone() required=true/>
            </Field>
            <Field label="Custom mappings".into() name="extras".into()
                hint=Some("One mapping per line as ldap_attr=geonosis_key.".into())>
                <Textarea name="extras".into() value=extras_text rows=4/>
            </Field>
            <ActionBar>
                <LinkButton href=cancel label="Cancel".to_string()/>
                <button type="submit" class="gn-btn gn-btn--primary">"Save mapping"</button>
            </ActionBar>
        </form>
    }
}

fn render_sync(realm_slug: String, c: LdapFederationConfig) -> impl IntoView {
    let action = form_post(&realm_slug, &c.alias, "sync");
    let write_value = match c.write_policy {
        geonosis_federation_ldap::config::WritePolicy::ReadOnly => "read-only",
        geonosis_federation_ldap::config::WritePolicy::Writable => "writable",
    };
    let policy_json = serde_json::to_string_pretty(&c.sync_policy).unwrap_or_default();
    let has_group_sync = c.group_sync.is_some();
    let cancel = format!("/admin/realms/{realm_slug}/federation");
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Write policy".into() name="write_policy".into()>
                <Select name="write_policy".into() value=write_value.into() options=vec![
                    SelectOption::new("read-only", "Read-only"),
                    SelectOption::new("writable", "Writable"),
                ]/>
            </Field>
            <Toggle name="group_sync_enabled".into() label="Group sync enabled".into() checked=has_group_sync/>
            <Field label="Sync policy (JSON)".into() name="sync_policy_json".into()
                hint=Some("Sync schedule configuration. Modes: on-demand, periodic, changed-based.".into())>
                <Textarea name="sync_policy_json".into() value=policy_json rows=8 code=true/>
            </Field>
            <ActionBar>
                <LinkButton href=cancel label="Cancel".to_string()/>
                <button type="submit" class="gn-btn gn-btn--primary">"Save sync settings"</button>
            </ActionBar>
        </form>
    }
}
