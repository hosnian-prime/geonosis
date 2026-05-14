//! `/admin/realms/{slug}/clients` — client list, create form, and
//! tabbed detail page. Per `docs/08-admin-ui.md` §2.3.

use leptos::prelude::*;

use geonosis_core::client::{AccessTokenType, Client, ClientAuthMethod, ClientKind, GrantPolicy};

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::breadcrumb::Crumb;
use crate::leptos_ui::components::form::{
    ActionBar, CheckGrid, CheckOption, Field, Select, SelectOption, TextInput, Textarea, Toggle,
};
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;
use crate::leptos_ui::components::tabs::{TabBar, TabItem};
use crate::leptos_ui::components::widgets::{
    Alert, AlertKind, Badge, BadgeKind, ButtonKind, EmptyState, LinkButton, StateBadge,
};

#[derive(Clone, Debug)]
pub struct ClientRow {
    pub client_id: String,
    pub display_name: String,
    pub kind: String,
    pub enabled: bool,
}

#[component]
pub fn ClientsPage(realm_slug: String, rows: Vec<ClientRow>, ctx: PageContext) -> impl IntoView {
    let ctx = ctx
        .with_title("Clients")
        .with_section("clients")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::current("Clients"),
        ]);
    let create_href = format!("/admin/realms/{realm_slug}/clients/new");
    let is_empty = rows.is_empty();
    view! {
        <Page context=ctx>
            <PageHeader
                title="Clients".into()
                subtitle=Some("Applications that request tokens for users or service accounts.".into())
                actions=Some(view! {
                    <LinkButton href=create_href.clone() label="+ Create client".to_string() kind=ButtonKind::Primary/>
                }.into_any())
            />
            {if is_empty {
                view! {
                    <EmptyState
                        title="No clients yet".into()
                        description="Register your first OAuth or SAML SP to start issuing tokens.".into()
                    />
                }.into_any()
            } else {
                view! {
                    <ListTable headers=vec!["Client ID", "Display name", "Kind", "State"]>
                        {rows.into_iter().map(|r| {
                            let href = format!("/admin/realms/{}/clients/{}", realm_slug, r.client_id);
                            let kind_label = humanize_kind(&r.kind);
                            view! {
                                <tr>
                                    <td data-label="Client ID">
                                        <a href=href><code>{r.client_id}</code></a>
                                    </td>
                                    <td data-label="Display name">{r.display_name}</td>
                                    <td data-label="Kind"><Badge label=kind_label kind=BadgeKind::Info/></td>
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
pub fn ClientCreatePage(
    realm_slug: String,
    ctx: PageContext,
    #[prop(default = None)] error: Option<String>,
) -> impl IntoView {
    let ctx = ctx
        .with_title("Create client")
        .with_section("clients")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::link("Clients", format!("/admin/realms/{realm_slug}/clients")),
            Crumb::current("Create"),
        ]);
    let action = format!("/admin/realms/{realm_slug}/clients");
    let cancel = format!("/admin/realms/{realm_slug}/clients");
    view! {
        <Page context=ctx>
            <PageHeader title="Create client".into()
                subtitle=Some("Pick the kind first — defaults for auth method and grants flow from it.".into())/>
            {error.map(|e| view! { <Alert message=e kind=AlertKind::Danger/> })}
            <form method="post" action=action class="gn-form">
                <Field label="Client ID".into() name="client_id".into() required=true
                    hint=Some("OAuth public identifier; cannot be changed later.".into())>
                    <TextInput name="client_id".into() required=true placeholder="my-web-app".into()/>
                </Field>
                <Field label="Display name".into() name="display_name".into()>
                    <TextInput name="display_name".into() placeholder="My Web App".into()/>
                </Field>
                <Field label="Kind".into() name="kind".into() required=true>
                    <Select name="kind".into() value="confidential".into() options=vec![
                        SelectOption::new("confidential", "Confidential (server-side web app)"),
                        SelectOption::new("public", "Public (SPA / native)"),
                        SelectOption::new("bearer-only", "Bearer-only (API)"),
                        SelectOption::new("service-account", "Service account (M2M)"),
                        SelectOption::new("saml-service-provider", "SAML SP"),
                        SelectOption::new("scim-client", "SCIM client"),
                    ]/>
                </Field>
                <Field label="Auth method".into() name="auth_method".into()>
                    <Select name="auth_method".into() value="client-secret-basic".into() options=client_auth_options()/>
                </Field>
                <ActionBar>
                    <LinkButton href=cancel label="Cancel".to_string()/>
                    <button type="submit" class="gn-btn gn-btn--primary">"Create client"</button>
                </ActionBar>
            </form>
        </Page>
    }
}

pub const CLIENT_TABS: &[(&str, &str)] = &[
    ("general", "General"),
    ("uris", "URIs"),
    ("grants", "Grant types"),
    ("scopes", "Scopes"),
    ("flow-bindings", "Flow bindings"),
    ("consent", "Consent"),
    ("tokens", "Token overrides"),
    ("logout", "Logout"),
    ("saml", "SAML SP"),
    ("auth-keys", "Auth keys"),
];

#[component]
pub fn ClientDetailPage(
    realm_slug: String,
    client: Client,
    active_tab: String,
    ctx: PageContext,
) -> impl IntoView {
    let client_id = client.client_id.clone();
    let display = client
        .display_name
        .clone()
        .unwrap_or_else(|| client.client_id.clone());
    let ctx = ctx
        .with_title(format!("Client · {client_id}"))
        .with_section("clients")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::link("Clients", format!("/admin/realms/{realm_slug}/clients")),
            Crumb::current(client_id.clone()),
        ]);
    let tab_items = CLIENT_TABS
        .iter()
        .filter(|(key, _)| {
            // Hide the SAML tab unless the client is SAML.
            !(*key == "saml"
                && !matches!(client.kind, ClientKind::SamlServiceProvider))
        })
        .map(|(k, label)| {
            TabItem::new(
                *k,
                *label,
                format!("/admin/realms/{realm_slug}/clients/{client_id}?tab={k}"),
            )
        })
        .collect::<Vec<_>>();
    let panel = match active_tab.as_str() {
        "general" => tab_general(realm_slug.clone(), client.clone()).into_any(),
        "uris" => tab_uris(realm_slug.clone(), client.clone()).into_any(),
        "grants" => tab_grants(realm_slug.clone(), client.clone()).into_any(),
        "scopes" => tab_scopes(realm_slug.clone(), client.clone()).into_any(),
        "flow-bindings" => tab_flow_bindings(realm_slug.clone(), client.clone()).into_any(),
        "consent" => tab_consent(realm_slug.clone(), client.clone()).into_any(),
        "tokens" => tab_tokens(realm_slug.clone(), client.clone()).into_any(),
        "logout" => tab_logout(realm_slug.clone(), client.clone()).into_any(),
        "saml" => tab_saml(client.clone()).into_any(),
        "auth-keys" => tab_auth_keys(client.clone()).into_any(),
        _ => view! {
            <Alert message="Unknown tab.".into() kind=AlertKind::Warning/>
        }
        .into_any(),
    };
    view! {
        <Page context=ctx>
            <PageHeader
                title=display.clone()
                subtitle=Some(format!("Client ID: {client_id}"))
            />
            <TabBar active=active_tab.clone() items=tab_items/>
            {panel}
        </Page>
    }
}

fn tab_general(realm_slug: String, c: Client) -> impl IntoView {
    let client_id = c.client_id.clone();
    let display = c.display_name.clone().unwrap_or_default();
    let kind_label = kind_label(c.kind);
    let auth_value = auth_method_value(c.auth_method);
    let token_type = match c.access_token_type {
        AccessTokenType::Jwt => "jwt",
        AccessTokenType::Opaque => "opaque",
    };
    let action = format!("/admin/realms/{realm_slug}/clients/{client_id}/general");
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Client ID".into() name="client_id".into() required=true>
                <TextInput name="client_id".into() value=client_id read_only=true/>
            </Field>
            <Field label="Display name".into() name="display_name".into()>
                <TextInput name="display_name".into() value=display/>
            </Field>
            <Field label="Kind".into() name="kind".into()>
                <TextInput name="kind".into() value=kind_label read_only=true/>
            </Field>
            <Toggle name="enabled".into() label="Client enabled".into() checked=c.enabled/>
            <Field label="Auth method".into() name="auth_method".into()>
                <Select name="auth_method".into() value=auth_value options=client_auth_options()/>
            </Field>
            <Field label="Access token type".into() name="access_token_type".into()>
                <Select name="access_token_type".into() value=token_type.into() options=vec![
                    SelectOption::new("jwt", "JWT"),
                    SelectOption::new("opaque", "Opaque"),
                ]/>
            </Field>
            <ActionBar>
                <button type="submit" class="gn-btn gn-btn--primary">"Save"</button>
            </ActionBar>
        </form>
    }
}

fn tab_uris(realm_slug: String, c: Client) -> impl IntoView {
    let client_id = c.client_id.clone();
    let redirect_uris = c
        .redirect_uris
        .iter()
        .map(|u| u.uri.clone())
        .collect::<Vec<_>>()
        .join("\n");
    let post_logout = c
        .post_logout_redirect_uris
        .iter()
        .map(|u| u.uri.clone())
        .collect::<Vec<_>>()
        .join("\n");
    let origins = c.web_origins.join("\n");
    let action = format!("/admin/realms/{realm_slug}/clients/{client_id}/uris");
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Redirect URIs".into() name="redirect_uris".into()
                hint=Some("One per line. HTTPS required except for loopback hosts.".into())>
                <Textarea name="redirect_uris".into() value=redirect_uris rows=4
                    placeholder="https://app.example.com/callback".into()/>
            </Field>
            <Field label="Post-logout redirect URIs".into() name="post_logout_redirect_uris".into()>
                <Textarea name="post_logout_redirect_uris".into() value=post_logout rows=3/>
            </Field>
            <Field label="Web origins (CORS)".into() name="web_origins".into()
                hint=Some("One per line. Used to validate the Origin header on token requests.".into())>
                <Textarea name="web_origins".into() value=origins rows=3/>
            </Field>
            <ActionBar>
                <button type="submit" class="gn-btn gn-btn--primary">"Save URIs"</button>
            </ActionBar>
        </form>
    }
}

fn tab_grants(realm_slug: String, c: Client) -> impl IntoView {
    let g: &GrantPolicy = &c.grants;
    let client_id = c.client_id.clone();
    let action = format!("/admin/realms/{realm_slug}/clients/{client_id}/grants");
    view! {
        <form method="post" action=action class="gn-form">
            <CheckGrid options=vec![
                CheckOption::new("authorization_code", "Authorization code", g.authorization_code),
                CheckOption::new("refresh_token", "Refresh token", g.refresh_token),
                CheckOption::new("client_credentials", "Client credentials", g.client_credentials),
                CheckOption::new("password", "Password (direct grant)", g.password),
                CheckOption::new("device_code", "Device code", g.device_code),
                CheckOption::new("token_exchange", "Token exchange", g.token_exchange),
            ]/>
            <ActionBar>
                <button type="submit" class="gn-btn gn-btn--primary">"Save grants"</button>
            </ActionBar>
        </form>
    }
}

fn tab_scopes(realm_slug: String, c: Client) -> impl IntoView {
    let client_id = c.client_id.clone();
    let defaults = c
        .default_scopes
        .iter()
        .map(|s| s.as_str().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let optionals = c
        .optional_scopes
        .iter()
        .map(|s| s.as_str().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let action = format!("/admin/realms/{realm_slug}/clients/{client_id}/scopes");
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Default scopes".into() name="default_scopes".into()
                hint=Some("Comma-separated. Applied automatically on every token issuance.".into())>
                <TextInput name="default_scopes".into() value=defaults
                    placeholder="openid, profile, email".into()/>
            </Field>
            <Field label="Optional scopes".into() name="optional_scopes".into()
                hint=Some("Comma-separated. Only granted when the client requests them.".into())>
                <TextInput name="optional_scopes".into() value=optionals/>
            </Field>
            <ActionBar>
                <button type="submit" class="gn-btn gn-btn--primary">"Save scopes"</button>
            </ActionBar>
        </form>
    }
}

fn tab_flow_bindings(realm_slug: String, c: Client) -> impl IntoView {
    let client_id = c.client_id.clone();
    let b = c.flow_binding;
    let action = format!("/admin/realms/{realm_slug}/clients/{client_id}/flow-bindings");
    let v = |o: Option<geonosis_core::id::FlowId>| o.map(|f| f.to_string()).unwrap_or_default();
    let browser = v(b.browser);
    let direct = v(b.direct_grant);
    let registration = v(b.registration);
    let reset = v(b.reset_credentials);
    let client_auth = v(b.client_authentication);
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Browser flow".into() name="browser".into()>
                <TextInput name="browser".into() value=browser placeholder="(use realm default)".into()/>
            </Field>
            <Field label="Direct-grant flow".into() name="direct_grant".into()>
                <TextInput name="direct_grant".into() value=direct/>
            </Field>
            <Field label="Registration flow".into() name="registration".into()>
                <TextInput name="registration".into() value=registration/>
            </Field>
            <Field label="Reset credentials flow".into() name="reset_credentials".into()>
                <TextInput name="reset_credentials".into() value=reset/>
            </Field>
            <Field label="Client auth flow".into() name="client_authentication".into()>
                <TextInput name="client_authentication".into() value=client_auth/>
            </Field>
            <ActionBar>
                <button type="submit" class="gn-btn gn-btn--primary">"Save bindings"</button>
            </ActionBar>
        </form>
    }
}

fn tab_consent(realm_slug: String, c: Client) -> impl IntoView {
    let client_id = c.client_id.clone();
    let consent = &c.consent;
    let text = consent.consent_screen_text.clone().unwrap_or_default();
    let action = format!("/admin/realms/{realm_slug}/clients/{client_id}/consent");
    view! {
        <form method="post" action=action class="gn-form">
            <Toggle name="required".into() label="Consent required".into() checked=consent.required/>
            <Toggle name="display_on_consent_screen".into() label="Display on consent screen".into()
                checked=consent.display_on_consent_screen/>
            <Field label="Consent screen text".into() name="consent_screen_text".into()>
                <Textarea name="consent_screen_text".into() value=text rows=4/>
            </Field>
            <ActionBar>
                <button type="submit" class="gn-btn gn-btn--primary">"Save consent"</button>
            </ActionBar>
        </form>
    }
}

fn tab_tokens(realm_slug: String, c: Client) -> impl IntoView {
    let client_id = c.client_id.clone();
    let access_life = c
        .access_token_lifespan
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default();
    let refresh_life = c
        .refresh_token_lifespan
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default();
    let alg = c
        .access_token_signing_alg
        .map(|a| a.as_str().to_string())
        .unwrap_or_default();
    let pairwise = c.pairwise_sub_algorithm.clone().unwrap_or_default();
    let action = format!("/admin/realms/{realm_slug}/clients/{client_id}/tokens");
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Access token lifespan (s)".into() name="access_token_lifespan".into()
                hint=Some("Leave blank to use realm default.".into())>
                <TextInput name="access_token_lifespan".into() input_type="number".into() value=access_life/>
            </Field>
            <Field label="Refresh token lifespan (s)".into() name="refresh_token_lifespan".into()>
                <TextInput name="refresh_token_lifespan".into() input_type="number".into() value=refresh_life/>
            </Field>
            <Field label="Access token signing alg".into() name="access_token_signing_alg".into()>
                <TextInput name="access_token_signing_alg".into() value=alg placeholder="RS256".into()/>
            </Field>
            <Field label="Pairwise subject algorithm".into() name="pairwise_sub_algorithm".into()>
                <TextInput name="pairwise_sub_algorithm".into() value=pairwise placeholder="sha256".into()/>
            </Field>
            <ActionBar>
                <button type="submit" class="gn-btn gn-btn--primary">"Save token settings"</button>
            </ActionBar>
        </form>
    }
}

fn tab_logout(realm_slug: String, c: Client) -> impl IntoView {
    let client_id = c.client_id.clone();
    let url = c
        .backchannel_logout_url
        .as_ref()
        .map(|u| u.to_string())
        .unwrap_or_default();
    let action = format!("/admin/realms/{realm_slug}/clients/{client_id}/logout");
    view! {
        <form method="post" action=action class="gn-form">
            <Toggle name="front_channel_logout_enabled".into() label="Front-channel logout enabled".into()
                checked=c.front_channel_logout_enabled/>
            <Field label="Backchannel logout URL".into() name="backchannel_logout_url".into()>
                <TextInput name="backchannel_logout_url".into() input_type="url".into() value=url/>
            </Field>
            <ActionBar>
                <button type="submit" class="gn-btn gn-btn--primary">"Save logout"</button>
            </ActionBar>
        </form>
    }
}

fn tab_saml(c: Client) -> impl IntoView {
    if let Some(cfg) = &c.saml_sp_config {
        let pretty = serde_json::to_string_pretty(cfg).unwrap_or_default();
        view! {
            <p class="gn-text-muted gn-text-sm">
                "SAML SP configuration in raw JSON. Inline form lands in v0.2."
            </p>
            <pre class="gn-json">{pretty}</pre>
        }.into_any()
    } else {
        view! {
            <Alert message="This client is not a SAML SP.".into() kind=AlertKind::Info/>
        }.into_any()
    }
}

fn tab_auth_keys(c: Client) -> impl IntoView {
    if c.client_authentication_keys.is_empty() {
        view! {
            <EmptyState
                title="No client auth keys registered".into()
                description="Upload a JWK to enable private_key_jwt client authentication.".into()
            />
        }.into_any()
    } else {
        view! {
            <ListTable headers=vec!["Key (JWKS entry)"]>
                {c.client_authentication_keys.iter().map(|k| view! {
                    <tr><td data-label="Key"><code class="gn-mono">{k.clone()}</code></td></tr>
                }).collect_view()}
            </ListTable>
        }.into_any()
    }
}

fn client_auth_options() -> Vec<SelectOption> {
    vec![
        SelectOption::new("client-secret-basic", "client_secret_basic"),
        SelectOption::new("client-secret-post", "client_secret_post"),
        SelectOption::new("client-secret-jwt", "client_secret_jwt"),
        SelectOption::new("private-key-jwt", "private_key_jwt"),
        SelectOption::new("none", "none (public)"),
        SelectOption::new("tls-client-auth", "tls_client_auth"),
    ]
}

fn auth_method_value(m: ClientAuthMethod) -> String {
    match m {
        ClientAuthMethod::ClientSecretBasic => "client-secret-basic",
        ClientAuthMethod::ClientSecretPost => "client-secret-post",
        ClientAuthMethod::ClientSecretJwt => "client-secret-jwt",
        ClientAuthMethod::PrivateKeyJwt => "private-key-jwt",
        ClientAuthMethod::None => "none",
        ClientAuthMethod::TlsClientAuth => "tls-client-auth",
    }
    .to_string()
}

pub fn kind_label(k: ClientKind) -> String {
    match k {
        ClientKind::Confidential => "Confidential",
        ClientKind::Public => "Public",
        ClientKind::BearerOnly => "Bearer-only",
        ClientKind::ServiceAccount => "Service account",
        ClientKind::SamlServiceProvider => "SAML SP",
        ClientKind::ScimClient => "SCIM client",
    }
    .to_string()
}

fn humanize_kind(k: &str) -> String {
    match k {
        "confidential" => "Confidential".into(),
        "public" => "Public".into(),
        "bearer_only" | "bearer-only" | "bearerOnly" => "Bearer-only".into(),
        "service_account" | "service-account" | "serviceaccount" => "Service account".into(),
        "samlserviceprovider" | "saml-service-provider" => "SAML SP".into(),
        "scim_client" | "scim-client" | "scimclient" => "SCIM client".into(),
        other => other.to_string(),
    }
}
