//! `/admin/realms/{slug}/idps` — list + tabbed detail.

use leptos::prelude::*;

use geonosis_broker::types::{IdentityProvider, IdpConfig, IdpKind};

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::breadcrumb::Crumb;
use crate::leptos_ui::components::form::{ActionBar, Field, TextInput, Toggle};
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;
use crate::leptos_ui::components::tabs::{TabBar, TabItem};
use crate::leptos_ui::components::widgets::{
    Alert, AlertKind, Badge, BadgeKind, ButtonKind, EmptyState, LinkButton, StateBadge,
};

#[derive(Clone, Debug)]
pub struct IdpRow {
    pub alias: String,
    pub display_name: String,
    pub kind: String,
    pub enabled: bool,
}

#[component]
pub fn IdpsPage(realm_slug: String, rows: Vec<IdpRow>, ctx: PageContext) -> impl IntoView {
    let ctx = ctx
        .with_title("Identity providers")
        .with_section("idps")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::current("Identity providers"),
        ]);
    let create_href = format!("/admin/realms/{realm_slug}/idps/new");
    let is_empty = rows.is_empty();
    view! {
        <Page context=ctx>
            <PageHeader
                title="Identity providers".into()
                subtitle=Some("Brokered logins via OIDC or SAML.".into())
                actions=Some(view! {
                    <LinkButton href=create_href.clone() label="+ Add IdP".to_string() kind=ButtonKind::Primary/>
                }.into_any())
            />
            {if is_empty {
                view! {
                    <EmptyState title="No identity providers".into()
                        description="Add an OIDC or SAML provider to enable social or enterprise SSO.".into()/>
                }.into_any()
            } else {
                view! {
                    <ListTable headers=vec!["Alias", "Display name", "Kind", "State"]>
                        {rows.into_iter().map(|r| {
                            let href = format!("/admin/realms/{realm_slug}/idps/{}", r.alias);
                            view! {
                                <tr>
                                    <td data-label="Alias"><a href=href.clone()><code>{r.alias}</code></a></td>
                                    <td data-label="Display name">{r.display_name}</td>
                                    <td data-label="Kind"><Badge label=r.kind.to_uppercase() kind=BadgeKind::Info/></td>
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

#[component]
pub fn IdpCreatePage(
    realm_slug: String,
    ctx: PageContext,
    #[prop(default = None)] error: Option<String>,
) -> impl IntoView {
    let ctx = ctx
        .with_title("Add identity provider")
        .with_section("idps")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::link(
                "Identity providers",
                format!("/admin/realms/{realm_slug}/idps"),
            ),
            Crumb::current("Add"),
        ]);
    let action = format!("/admin/realms/{realm_slug}/idps");
    let cancel = format!("/admin/realms/{realm_slug}/idps");
    view! {
        <Page context=ctx>
            <PageHeader title="Add identity provider".into()/>
            {error.map(|e| view! { <Alert message=e kind=AlertKind::Danger/> })}
            <form method="post" action=action class="gn-form">
                <Field label="Alias".into() name="alias".into() required=true>
                    <TextInput name="alias".into() required=true placeholder="google".into()/>
                </Field>
                <Field label="Display name".into() name="display_name".into() required=true>
                    <TextInput name="display_name".into() required=true placeholder="Google".into()/>
                </Field>
                <Field label="Kind".into() name="kind".into() required=true>
                    <select class="gn-select" id="kind" name="kind">
                        <option value="oidc" selected=true>"OIDC"</option>
                        <option value="saml">"SAML"</option>
                    </select>
                </Field>
                <ActionBar>
                    <LinkButton href=cancel label="Cancel".to_string()/>
                    <button type="submit" class="gn-btn gn-btn--primary">"Continue"</button>
                </ActionBar>
            </form>
        </Page>
    }
}

pub const IDP_TABS: &[(&str, &str)] = &[
    ("general", "General"),
    ("config", "Configuration"),
    ("mappers", "Mappers"),
];

#[component]
pub fn IdpDetailPage(
    realm_slug: String,
    idp: IdentityProvider,
    active_tab: String,
    ctx: PageContext,
) -> impl IntoView {
    let alias = idp.alias.clone();
    let display = idp.display_name.clone();
    let kind = match idp.kind {
        IdpKind::Oidc => "OIDC",
        IdpKind::Saml => "SAML",
    };
    let ctx = ctx
        .with_title(format!("IdP · {alias}"))
        .with_section("idps")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::link(
                "Identity providers",
                format!("/admin/realms/{realm_slug}/idps"),
            ),
            Crumb::current(alias.clone()),
        ]);
    let tab_items = IDP_TABS
        .iter()
        .map(|(k, l)| {
            TabItem::new(
                *k,
                *l,
                format!("/admin/realms/{realm_slug}/idps/{alias}?tab={k}"),
            )
        })
        .collect::<Vec<_>>();
    let panel = match active_tab.as_str() {
        "general" => render_general(realm_slug.clone(), idp.clone()).into_any(),
        "config" => render_config(idp.clone()).into_any(),
        "mappers" => view! {
            <EmptyState title="No mappers configured".into()
                description="Attribute mappers transform external claims into Geonosis user attributes.".into()/>
        }.into_any(),
        _ => view! { <Alert message="Unknown tab.".into() kind=AlertKind::Warning/> }.into_any(),
    };
    view! {
        <Page context=ctx>
            <PageHeader title=display subtitle=Some(format!("{kind} · alias {alias}"))/>
            <TabBar active=active_tab.clone() items=tab_items/>
            {panel}
        </Page>
    }
}

fn render_general(realm_slug: String, i: IdentityProvider) -> impl IntoView {
    let action = format!("/admin/realms/{realm_slug}/idps/{}/general", i.alias);
    let adapter = i.adapter_urn.clone().unwrap_or_default();
    let post_login = i.post_login_flow_alias.clone().unwrap_or_default();
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Alias".into() name="alias".into()>
                <TextInput name="alias".into() value=i.alias.clone() read_only=true/>
            </Field>
            <Field label="Display name".into() name="display_name".into()>
                <TextInput name="display_name".into() value=i.display_name.clone()/>
            </Field>
            <Toggle name="enabled".into() label="Enabled".into() checked=i.enabled/>
            <Toggle name="link_only".into() label="Link only (no login)".into() checked=i.link_only/>
            <Field label="First-login flow alias".into() name="first_login_flow_alias".into()>
                <TextInput name="first_login_flow_alias".into() value=i.first_login_flow_alias.clone()/>
            </Field>
            <Field label="Post-login flow alias".into() name="post_login_flow_alias".into()>
                <TextInput name="post_login_flow_alias".into() value=post_login/>
            </Field>
            <Field label="Adapter URN (optional)".into() name="adapter_urn".into()>
                <TextInput name="adapter_urn".into() value=adapter/>
            </Field>
            <ActionBar>
                <button type="submit" class="gn-btn gn-btn--primary">"Save"</button>
            </ActionBar>
        </form>
    }
}

fn render_config(i: IdentityProvider) -> impl IntoView {
    match &i.config {
        IdpConfig::Oidc(c) => {
            let body = serde_json::to_string_pretty(c).unwrap_or_default();
            view! {
                <div class="gn-stack">
                    <p class="gn-text-muted gn-text-sm">
                        "OIDC configuration. Inline form lands in v0.2; edit via the admin API for now."
                    </p>
                    <pre class="gn-json">{body}</pre>
                </div>
            }.into_any()
        }
        IdpConfig::Saml(c) => {
            let body = serde_json::to_string_pretty(c).unwrap_or_default();
            view! {
                <div class="gn-stack">
                    <p class="gn-text-muted gn-text-sm">
                        "SAML configuration. Edit via the admin API."
                    </p>
                    <pre class="gn-json">{body}</pre>
                </div>
            }
            .into_any()
        }
    }
}
