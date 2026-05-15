//! `/admin/realms/{slug}/agents` — list + tabbed detail.

use leptos::prelude::*;

use geonosis_core::agent::{Agent, AgentAuthMethod, AgentKind};

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::breadcrumb::Crumb;
use crate::leptos_ui::components::form::{
    ActionBar, Field, Select, SelectOption, TextInput, Toggle,
};
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;
use crate::leptos_ui::components::tabs::{TabBar, TabItem};
use crate::leptos_ui::components::widgets::{
    Alert, AlertKind, Badge, BadgeKind, EmptyState, StateBadge,
};

#[derive(Clone, Debug)]
pub struct AgentRow {
    pub alias: String,
    pub display_name: String,
    pub kind: String,
    pub vendor: Option<String>,
    pub model_hint: Option<String>,
    pub enabled: bool,
}

#[component]
pub fn AgentsPage(realm_slug: String, rows: Vec<AgentRow>, ctx: PageContext) -> impl IntoView {
    let ctx = ctx
        .with_title("Agents")
        .with_section("agents")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::current("Agents"),
        ]);
    let is_empty = rows.is_empty();
    view! {
        <Page context=ctx>
            <PageHeader
                title="Agents".into()
                subtitle=Some("AI / M2M delegated identities. Capabilities + rate limits per agent.".into())
            />
            {if is_empty {
                view! {
                    <EmptyState title="No agents yet".into()
                        description="Register agents via the admin API or CLI; in-UI creation lands in v0.2.".into()/>
                }.into_any()
            } else {
                view! {
                    <ListTable headers=vec!["Alias", "Display name", "Kind", "Vendor", "Model", "State"]>
                        {rows.into_iter().map(|r| {
                            let href = format!("/admin/realms/{realm_slug}/agents/{}", r.alias);
                            view! {
                                <tr>
                                    <td data-label="Alias"><a href=href.clone()><code>{r.alias}</code></a></td>
                                    <td data-label="Display name">{r.display_name}</td>
                                    <td data-label="Kind"><Badge label=r.kind kind=BadgeKind::Info/></td>
                                    <td data-label="Vendor">{r.vendor.unwrap_or_else(|| "—".into())}</td>
                                    <td data-label="Model">{r.model_hint.unwrap_or_else(|| "—".into())}</td>
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

pub const AGENT_TABS: &[(&str, &str)] = &[
    ("general", "General"),
    ("capabilities", "Capabilities"),
    ("scopes", "Scopes & audiences"),
    ("rate-limits", "Rate limits"),
    ("public-key", "Public key"),
];

#[component]
pub fn AgentDetailPage(
    realm_slug: String,
    agent: Agent,
    active_tab: String,
    ctx: PageContext,
) -> impl IntoView {
    let alias = agent.alias.clone();
    let display = agent.display_name.clone();
    let ctx = ctx
        .with_title(format!("Agent · {alias}"))
        .with_section("agents")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::link("Agents", format!("/admin/realms/{realm_slug}/agents")),
            Crumb::current(alias.clone()),
        ]);
    let tab_items = AGENT_TABS
        .iter()
        .map(|(k, l)| {
            TabItem::new(
                *k,
                *l,
                format!("/admin/realms/{realm_slug}/agents/{alias}?tab={k}"),
            )
        })
        .collect::<Vec<_>>();
    let panel = match active_tab.as_str() {
        "general" => render_general(realm_slug.clone(), agent.clone()).into_any(),
        "capabilities" => render_capabilities(agent.clone()).into_any(),
        "scopes" => render_scopes(agent.clone()).into_any(),
        "rate-limits" => render_rate_limits(realm_slug.clone(), agent.clone()).into_any(),
        "public-key" => render_public_key(agent.clone()).into_any(),
        _ => view! { <Alert message="Unknown tab.".into() kind=AlertKind::Warning/> }.into_any(),
    };
    view! {
        <Page context=ctx>
            <PageHeader title=display subtitle=Some(format!("Alias: {alias}"))/>
            <TabBar active=active_tab.clone() items=tab_items/>
            {panel}
        </Page>
    }
}

fn render_general(realm_slug: String, a: Agent) -> impl IntoView {
    let action = format!("/admin/realms/{realm_slug}/agents/{}/general", a.alias);
    let kind = agent_kind_value(a.kind.clone());
    let auth = agent_auth_value(a.auth_method);
    let model = a.model_hint.clone().unwrap_or_default();
    let vendor = a.vendor.clone().unwrap_or_default();
    let version = a.version.clone().unwrap_or_default();
    let parent = format!("{:?}", a.parent_subject);
    let expires = a.expires_at.map(|t| t.to_rfc3339()).unwrap_or_default();
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Alias".into() name="alias".into()>
                <TextInput name="alias".into() value=a.alias.clone() read_only=true/>
            </Field>
            <Field label="Display name".into() name="display_name".into()>
                <TextInput name="display_name".into() value=a.display_name.clone()/>
            </Field>
            <Field label="Kind".into() name="kind".into()>
                <Select name="kind".into() value=kind options=vec![
                    SelectOption::new("assistant", "Assistant"),
                    SelectOption::new("scraper", "Scraper"),
                    SelectOption::new("webhook", "Webhook"),
                    SelectOption::new("batch", "Batch"),
                ]/>
            </Field>
            <Field label="Model hint".into() name="model_hint".into()>
                <TextInput name="model_hint".into() value=model placeholder="claude-opus-4".into()/>
            </Field>
            <Field label="Vendor".into() name="vendor".into()>
                <TextInput name="vendor".into() value=vendor placeholder="anthropic".into()/>
            </Field>
            <Field label="Version".into() name="version".into()>
                <TextInput name="version".into() value=version/>
            </Field>
            <Field label="Parent subject".into() name="parent_subject".into()>
                <TextInput name="parent_subject".into() value=parent read_only=true/>
            </Field>
            <Field label="Auth method".into() name="auth_method".into()>
                <Select name="auth_method".into() value=auth options=vec![
                    SelectOption::new("private-key-jwt", "private_key_jwt"),
                    SelectOption::new("dpop-bound-key", "dpop_bound_key"),
                    SelectOption::new("token-exchange-only", "token_exchange_only"),
                ]/>
            </Field>
            <Toggle name="enabled".into() label="Enabled".into() checked=a.enabled/>
            <Field label="Expires at".into() name="expires_at".into()
                hint=Some("Leave empty for no expiry. RFC 3339 format.".into())>
                <TextInput name="expires_at".into() value=expires
                    placeholder="2026-12-31T00:00:00Z".into()/>
            </Field>
            <ActionBar>
                <button type="submit" class="gn-btn gn-btn--primary">"Save"</button>
            </ActionBar>
        </form>
    }
}

fn render_capabilities(a: Agent) -> impl IntoView {
    if a.capabilities.is_empty() {
        view! {
            <EmptyState title="No capabilities".into()
                description="Capabilities are URN-keyed permissions like tool:read-files or model:gpt-4o.".into()/>
        }.into_any()
    } else {
        view! {
            <ListTable headers=vec!["URN", "Config"]>
                {a.capabilities.iter().map(|c| {
                    let cfg = serde_json::to_string(&c.config).unwrap_or_default();
                    view! {
                        <tr>
                            <td data-label="URN"><code>{c.urn.clone()}</code></td>
                            <td data-label="Config"><code class="gn-mono">{cfg}</code></td>
                        </tr>
                    }
                }).collect_view()}
            </ListTable>
        }
        .into_any()
    }
}

fn render_scopes(a: Agent) -> impl IntoView {
    let scopes = a
        .allowed_scopes
        .iter()
        .map(|s| s.as_str().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let auds = a.allowed_audiences.join(", ");
    view! {
        <div class="gn-stack">
            <div>
                <h3>"Allowed scopes"</h3>
                <p class="gn-text-muted gn-text-sm">{scopes}</p>
            </div>
            <div>
                <h3>"Allowed audiences"</h3>
                <p class="gn-text-muted gn-text-sm">{auds}</p>
            </div>
        </div>
    }
}

fn render_rate_limits(realm_slug: String, a: Agent) -> impl IntoView {
    let action = format!("/admin/realms/{realm_slug}/agents/{}/rate-limits", a.alias);
    let tpd = a
        .rate_limit
        .tokens_per_day
        .map(|n| n.to_string())
        .unwrap_or_default();
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Requests per minute".into() name="requests_per_minute".into()>
                <TextInput name="requests_per_minute".into() input_type="number".into()
                    value=a.rate_limit.requests_per_minute.to_string()/>
            </Field>
            <Field label="Tokens per day".into() name="tokens_per_day".into()
                hint=Some("Leave empty for no limit.".into())>
                <TextInput name="tokens_per_day".into() input_type="number".into() value=tpd/>
            </Field>
            <ActionBar>
                <button type="submit" class="gn-btn gn-btn--primary">"Save limits"</button>
            </ActionBar>
        </form>
    }
}

fn render_public_key(a: Agent) -> impl IntoView {
    if let Some(jwk) = &a.public_jwk {
        let pretty = serde_json::to_string_pretty(jwk).unwrap_or_default();
        view! { <pre class="gn-json">{pretty}</pre> }.into_any()
    } else {
        view! {
            <EmptyState title="No public key registered".into()
                description="Upload a JWK to enable private_key_jwt or DPoP.".into()/>
        }
        .into_any()
    }
}

fn agent_kind_value(k: AgentKind) -> String {
    match k {
        AgentKind::Assistant => "assistant".into(),
        AgentKind::Scraper => "scraper".into(),
        AgentKind::Webhook => "webhook".into(),
        AgentKind::Batch => "batch".into(),
        AgentKind::Custom(s) => s.clone(),
    }
}

fn agent_auth_value(m: AgentAuthMethod) -> String {
    match m {
        AgentAuthMethod::PrivateKeyJwt => "private-key-jwt".into(),
        AgentAuthMethod::DpopBoundKey => "dpop-bound-key".into(),
        AgentAuthMethod::TokenExchangeOnly => "token-exchange-only".into(),
    }
}
