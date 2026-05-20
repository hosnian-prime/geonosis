//! `/admin/realms/{slug}/idps` — list + tabbed detail.

use leptos::prelude::*;

use geonosis_broker::types::{IdentityProvider, IdpConfig, IdpKind};

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::breadcrumb::Crumb;
use crate::leptos_ui::components::form::{
    ActionBar, Field, Select, SelectOption, TextInput, Textarea, Toggle,
};
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
        "config" => render_config(realm_slug.clone(), idp.clone()).into_any(),
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

fn render_config(realm_slug: String, i: IdentityProvider) -> impl IntoView {
    let action = format!("/admin/realms/{realm_slug}/idps/{}/config", i.alias);
    match i.config.clone() {
        IdpConfig::Oidc(c) => {
            let scopes_csv = c.scopes.join(", ");
            let auth_value = match c.client_auth {
                geonosis_broker::types::ClientAuthMethod::Basic => "basic",
                geonosis_broker::types::ClientAuthMethod::Jwt => "jwt",
                geonosis_broker::types::ClientAuthMethod::None => "none",
            };
            let discovery = c.discovery_url.clone().unwrap_or_default();
            let authz_ep = c.authorization_endpoint.clone().unwrap_or_default();
            let token_ep = c.token_endpoint.clone().unwrap_or_default();
            let userinfo_ep = c.userinfo_endpoint.clone().unwrap_or_default();
            let jwks = c.jwks_uri.clone().unwrap_or_default();
            let prompt = c.prompt.clone().unwrap_or_default();
            let response_mode = c.response_mode.clone().unwrap_or_default();
            view! {
                <form method="post" action=action class="gn-form">
                    <Field label="Issuer".into() name="issuer".into() required=true
                        hint=Some("OIDC issuer URL (e.g. https://accounts.google.com).".into())>
                        <TextInput name="issuer".into() input_type="url".into() value=c.issuer.clone() required=true/>
                    </Field>
                    <Field label="Discovery URL".into() name="discovery_url".into()
                        hint=Some("Override .well-known URL. Leave empty to derive from issuer.".into())>
                        <TextInput name="discovery_url".into() input_type="url".into() value=discovery/>
                    </Field>
                    <Field label="Client ID".into() name="client_id".into() required=true>
                        <TextInput name="client_id".into() value=c.client_id.clone() required=true/>
                    </Field>
                    <Field label="Client secret".into() name="client_secret".into()
                        hint=Some("Leave empty to keep existing secret unchanged.".into())>
                        <TextInput name="client_secret".into() input_type="password".into()/>
                    </Field>
                    <Field label="Client auth method".into() name="client_auth".into()>
                        <Select name="client_auth".into() value=auth_value.into() options=vec![
                            SelectOption::new("basic", "Basic (client_secret_basic)"),
                            SelectOption::new("jwt", "JWT (client_secret_jwt)"),
                            SelectOption::new("none", "None (public client)"),
                        ]/>
                    </Field>
                    <Field label="Scopes".into() name="scopes".into()
                        hint=Some("Comma-separated (e.g. openid, profile, email).".into())>
                        <TextInput name="scopes".into() value=scopes_csv/>
                    </Field>
                    <Toggle name="pkce".into() label="Use PKCE".into() checked=c.pkce/>
                    <Toggle name="accept_unsigned_userinfo".into()
                        label="Accept unsigned userinfo".into() checked=c.accept_unsigned_userinfo/>
                    <Field label="Authorization endpoint".into() name="authorization_endpoint".into()
                        hint=Some("Override. Leave empty to use discovery.".into())>
                        <TextInput name="authorization_endpoint".into() input_type="url".into() value=authz_ep/>
                    </Field>
                    <Field label="Token endpoint".into() name="token_endpoint".into()>
                        <TextInput name="token_endpoint".into() input_type="url".into() value=token_ep/>
                    </Field>
                    <Field label="Userinfo endpoint".into() name="userinfo_endpoint".into()>
                        <TextInput name="userinfo_endpoint".into() input_type="url".into() value=userinfo_ep/>
                    </Field>
                    <Field label="JWKS URI".into() name="jwks_uri".into()>
                        <TextInput name="jwks_uri".into() input_type="url".into() value=jwks/>
                    </Field>
                    <Field label="Prompt".into() name="prompt".into()
                        hint=Some("OIDC prompt parameter (login, consent, none).".into())>
                        <TextInput name="prompt".into() value=prompt/>
                    </Field>
                    <Field label="Response mode".into() name="response_mode".into()>
                        <TextInput name="response_mode".into() value=response_mode/>
                    </Field>
                    <ActionBar>
                        <button type="submit" class="gn-btn gn-btn--primary">"Save configuration"</button>
                    </ActionBar>
                </form>
            }.into_any()
        }
        IdpConfig::Saml(c) => {
            let slo = c.slo_url.clone().unwrap_or_default();
            let certs = c.signing_cert_pems.join("\n---\n");
            let binding_out = saml_binding_value(&c.binding_outbound);
            let binding_in = saml_binding_value(&c.binding_inbound);
            let name_id = saml_nameid_value(&c.name_id_format);
            view! {
                <form method="post" action=action class="gn-form">
                    <Field label="Entity ID".into() name="entity_id".into() required=true>
                        <TextInput name="entity_id".into() value=c.entity_id.clone() required=true/>
                    </Field>
                    <Field label="SSO URL".into() name="sso_url".into() required=true>
                        <TextInput name="sso_url".into() input_type="url".into() value=c.sso_url.clone() required=true/>
                    </Field>
                    <Field label="SLO URL".into() name="slo_url".into()>
                        <TextInput name="slo_url".into() input_type="url".into() value=slo/>
                    </Field>
                    <Field label="Signing certificates (PEM)".into() name="signing_cert_pems".into()
                        hint=Some("One or more PEM-encoded certificates, separated by ---".into())>
                        <Textarea name="signing_cert_pems".into() value=certs rows=8 code=true/>
                    </Field>
                    <Field label="Outbound binding".into() name="binding_outbound".into()>
                        <Select name="binding_outbound".into() value=binding_out options=saml_binding_options()/>
                    </Field>
                    <Field label="Inbound binding".into() name="binding_inbound".into()>
                        <Select name="binding_inbound".into() value=binding_in options=saml_binding_options()/>
                    </Field>
                    <Field label="NameID format".into() name="name_id_format".into()>
                        <Select name="name_id_format".into() value=name_id options=vec![
                            SelectOption::new("unspecified", "Unspecified"),
                            SelectOption::new("email", "Email address"),
                            SelectOption::new("persistent", "Persistent"),
                            SelectOption::new("transient", "Transient"),
                            SelectOption::new("x509", "X.509 Subject Name"),
                        ]/>
                    </Field>
                    <Toggle name="want_assertions_signed".into()
                        label="Want assertions signed".into() checked=c.want_assertions_signed/>
                    <Toggle name="want_responses_signed".into()
                        label="Want responses signed".into() checked=c.want_responses_signed/>
                    <ActionBar>
                        <button type="submit" class="gn-btn gn-btn--primary">"Save configuration"</button>
                    </ActionBar>
                </form>
            }.into_any()
        }
    }
}

fn saml_binding_value(b: &geonosis_saml_types::SamlBinding) -> String {
    match b {
        geonosis_saml_types::SamlBinding::HttpRedirect => "redirect".into(),
        geonosis_saml_types::SamlBinding::HttpPost => "post".into(),
        geonosis_saml_types::SamlBinding::Artifact => "artifact".into(),
    }
}

fn saml_binding_options() -> Vec<SelectOption> {
    vec![
        SelectOption::new("redirect", "HTTP-Redirect"),
        SelectOption::new("post", "HTTP-POST"),
        SelectOption::new("artifact", "Artifact"),
    ]
}

fn saml_nameid_value(n: &geonosis_saml_types::NameIdFormat) -> String {
    match n {
        geonosis_saml_types::NameIdFormat::Unspecified => "unspecified".into(),
        geonosis_saml_types::NameIdFormat::EmailAddress => "email".into(),
        geonosis_saml_types::NameIdFormat::Persistent => "persistent".into(),
        geonosis_saml_types::NameIdFormat::Transient => "transient".into(),
        geonosis_saml_types::NameIdFormat::X509SubjectName => "x509".into(),
    }
}
