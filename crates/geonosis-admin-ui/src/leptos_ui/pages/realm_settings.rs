//! `/admin/realms/{slug}/settings?tab=...` — realm settings.
//!
//! Per `docs/08-admin-ui.md` §2.2 the settings page exposes every
//! realm-level policy across 14 tabs. The tabs are URL-routed via
//! `?tab=` so each panel deep-links and renders fully on the server.
//! Each tab owns its own POST handler at `/settings/{tab}` so saves
//! stay scoped — bouncing the entire `Realm` through one PUT was
//! noisy and fragile while individual policies still settle.

use leptos::prelude::*;

use geonosis_core::common::SslRequirement;
use geonosis_core::realm::{AcrRequirement, PasswordRule, Realm};
use geonosis_core::JwsAlgorithm;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::breadcrumb::Crumb;
use crate::leptos_ui::components::form::{
    ActionBar, Field, Select, SelectOption, TextInput, Toggle,
};
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;
use crate::leptos_ui::components::tabs::{TabBar, TabItem};
use crate::leptos_ui::components::widgets::{Alert, AlertKind, LinkButton};

pub const TABS: &[(&str, &str)] = &[
    ("general", "General"),
    ("login", "Login"),
    ("sessions", "Sessions"),
    ("tokens", "Tokens"),
    ("password", "Password policy"),
    ("brute-force", "Brute force"),
    ("otp", "OTP"),
    ("webauthn", "WebAuthn"),
    ("themes", "Themes"),
    ("localization", "Localization"),
    ("events", "Events"),
    ("acr", "ACR"),
    ("org-policy", "Org policy"),
    ("defaults", "Defaults"),
];

#[component]
pub fn RealmSettingsPage(
    realm: Realm,
    active_tab: String,
    ctx: PageContext,
    #[prop(default = None)] flash: Option<String>,
) -> impl IntoView {
    let slug = realm.slug.clone();
    let display = realm.display_name.clone();
    let ctx = ctx
        .with_title(format!("{display} · Settings"))
        .with_section("settings")
        .with_realm(slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(display.clone(), format!("/admin/realms/{slug}")),
            Crumb::current("Settings"),
        ]);
    let tab_items = TABS
        .iter()
        .map(|(k, label)| {
            TabItem::new(*k, *label, format!("/admin/realms/{slug}/settings?tab={k}"))
        })
        .collect::<Vec<_>>();
    let body = render_tab(&active_tab, realm.clone());
    let subtitle =
        format!("Configure policies that apply to all users, clients and sessions in {display}.");
    view! {
        <Page context=ctx>
            <PageHeader title="Realm settings".into() subtitle=Some(subtitle)/>
            {flash.map(|m| view! { <Alert message=m kind=AlertKind::Success/> })}
            <TabBar active=active_tab.clone() items=tab_items/>
            {body}
        </Page>
    }
}

fn render_tab(tab: &str, realm: Realm) -> AnyView {
    match tab {
        "general" => tab_general(realm).into_any(),
        "login" => tab_login(realm).into_any(),
        "sessions" => tab_sessions(realm).into_any(),
        "tokens" => tab_tokens(realm).into_any(),
        "password" => tab_password(realm).into_any(),
        "brute-force" => tab_brute(realm).into_any(),
        "otp" => tab_otp(realm).into_any(),
        "webauthn" => tab_webauthn(realm).into_any(),
        "themes" => tab_themes(realm).into_any(),
        "localization" => tab_localization(realm).into_any(),
        "events" => tab_events(realm).into_any(),
        "acr" => tab_acr(realm).into_any(),
        "org-policy" => tab_org_policy(realm).into_any(),
        "defaults" => tab_defaults(realm).into_any(),
        _ => view! { <Alert message="Unknown settings tab.".into() kind=AlertKind::Warning/> }
            .into_any(),
    }
}

fn form_post(slug: &str, tab: &str) -> String {
    format!("/admin/realms/{slug}/settings/{tab}")
}

fn save_bar(slug: String) -> impl IntoView {
    let back = format!("/admin/realms/{slug}");
    view! {
        <ActionBar>
            <LinkButton href=back label="Cancel".to_string()/>
            <button type="submit" class="gn-btn gn-btn--primary">"Save changes"</button>
        </ActionBar>
    }
}

fn tab_general(realm: Realm) -> impl IntoView {
    let slug = realm.slug.clone();
    let display = realm.display_name.clone();
    let frontend = realm
        .frontend_url
        .map(|u| u.to_string())
        .unwrap_or_default();
    let admin_frontend = realm
        .admin_frontend_url
        .map(|u| u.to_string())
        .unwrap_or_default();
    let ssl_value = match realm.ssl_required {
        SslRequirement::None => "none",
        SslRequirement::ExternalRequests => "external-requests",
        SslRequirement::All => "all",
    };
    let enabled = realm.enabled;
    let orgs = realm.organizations_enabled;
    let action = form_post(&slug, "general");
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Display name".into() name="display_name".into() required=true>
                <TextInput name="display_name".into() value=display required=true/>
            </Field>
            <Field label="Frontend URL".into() name="frontend_url".into()
                hint=Some("Public-facing base URL for end-user pages.".into())>
                <TextInput name="frontend_url".into() input_type="url".into() value=frontend/>
            </Field>
            <Field label="Admin frontend URL".into() name="admin_frontend_url".into()
                hint=Some("Admin console base URL (defaults to public).".into())>
                <TextInput name="admin_frontend_url".into() input_type="url".into() value=admin_frontend/>
            </Field>
            <Field label="SSL required".into() name="ssl_required".into()>
                <Select name="ssl_required".into() value=ssl_value.into() options=vec![
                    SelectOption::new("none", "None"),
                    SelectOption::new("external-requests", "External requests"),
                    SelectOption::new("all", "All requests"),
                ]/>
            </Field>
            <Toggle name="enabled".into() label="Realm enabled".into() checked=enabled/>
            <Toggle name="organizations_enabled".into() label="Organizations enabled".into() checked=orgs/>
            {save_bar(slug)}
        </form>
    }
}

fn tab_login(realm: Realm) -> impl IntoView {
    let login = realm.login;
    let reg = realm.registration;
    let slug = realm.slug.clone();
    let action = form_post(&slug, "login");
    view! {
        <form method="post" action=action class="gn-form">
            <Toggle name="registration".into() label="User registration".into() checked=reg.enabled/>
            <Toggle name="reset_password".into() label="Forgot password".into() checked=login.reset_password_allowed/>
            <Toggle name="remember_me".into() label="Remember me".into() checked=login.remember_me_enabled/>
            <Toggle name="email_login".into() label="Login with email".into() checked=login.login_with_email_allowed/>
            <Toggle name="email_as_username".into() label="Email as username".into() checked=reg.email_as_username/>
            <Toggle name="duplicate_emails".into() label="Allow duplicate emails".into() checked=login.duplicate_emails_allowed/>
            <Toggle name="verify_email".into() label="Verify email".into() checked=login.verify_email_required/>
            <Toggle name="edit_username".into() label="Allow username edit".into() checked=login.edit_username_allowed/>
            <Toggle name="require_terms_acceptance".into() label="Require terms acceptance".into() checked=reg.require_terms_acceptance/>
            {save_bar(slug)}
        </form>
    }
}

fn tab_sessions(realm: Realm) -> impl IntoView {
    let s = realm.session_policy;
    let slug = realm.slug.clone();
    let action = form_post(&slug, "sessions");
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="SSO session idle (s)".into() name="sso_session_idle".into()
                hint=Some("Seconds of inactivity before the session ends.".into())>
                <TextInput name="sso_session_idle".into() input_type="number".into()
                    value=s.sso_session_idle.as_secs().to_string()/>
            </Field>
            <Field label="SSO session max (s)".into() name="sso_session_max".into()>
                <TextInput name="sso_session_max".into() input_type="number".into()
                    value=s.sso_session_max.as_secs().to_string()/>
            </Field>
            <Field label="Remember-me idle (s)".into() name="remember_me_idle".into()>
                <TextInput name="remember_me_idle".into() input_type="number".into()
                    value=s.remember_me_idle.as_secs().to_string()/>
            </Field>
            <Field label="Remember-me max (s)".into() name="remember_me_max".into()>
                <TextInput name="remember_me_max".into() input_type="number".into()
                    value=s.remember_me_max.as_secs().to_string()/>
            </Field>
            {save_bar(slug)}
        </form>
    }
}

fn tab_tokens(realm: Realm) -> impl IntoView {
    let t = realm.token_policy;
    let slug = realm.slug.clone();
    let action = form_post(&slug, "tokens");
    let alg_value = t.default_signing_alg.as_str().to_string();
    let allowed_csv = t
        .allowed_signing_algs
        .iter()
        .map(|a| a.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let access = t.access_token_lifespan.as_secs().to_string();
    let access_impl = t.access_token_lifespan_implicit.as_secs().to_string();
    let refresh = t.refresh_token_lifespan.as_secs().to_string();
    let code = t.auth_code_lifespan.as_secs().to_string();
    let max_reuse = t.refresh_token_max_reuse.to_string();
    let revoke = t.revoke_refresh_token_on_use;
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Access token lifespan (s)".into() name="access_token_lifespan".into()>
                <TextInput name="access_token_lifespan".into() input_type="number".into() value=access/>
            </Field>
            <Field label="Implicit access token lifespan (s)".into() name="access_token_lifespan_implicit".into()>
                <TextInput name="access_token_lifespan_implicit".into() input_type="number".into() value=access_impl/>
            </Field>
            <Field label="Refresh token lifespan (s)".into() name="refresh_token_lifespan".into()>
                <TextInput name="refresh_token_lifespan".into() input_type="number".into() value=refresh/>
            </Field>
            <Field label="Authorization code lifespan (s)".into() name="auth_code_lifespan".into()>
                <TextInput name="auth_code_lifespan".into() input_type="number".into() value=code/>
            </Field>
            <Toggle name="revoke_refresh_on_use".into() label="Revoke refresh token on use".into() checked=revoke/>
            <Field label="Max refresh reuse".into() name="refresh_token_max_reuse".into()>
                <TextInput name="refresh_token_max_reuse".into() input_type="number".into() value=max_reuse/>
            </Field>
            <Field label="Default signing algorithm".into() name="default_signing_alg".into()>
                <Select name="default_signing_alg".into() value=alg_value options=alg_options()/>
            </Field>
            <Field label="Allowed signing algorithms".into() name="allowed_signing_algs".into()
                hint=Some("Comma-separated list. Example: RS256, ES256, EdDSA.".into())>
                <TextInput name="allowed_signing_algs".into() value=allowed_csv/>
            </Field>
            {save_bar(slug)}
        </form>
    }
}

fn alg_options() -> Vec<SelectOption> {
    vec![
        SelectOption::new("RS256", "RS256"),
        SelectOption::new("RS384", "RS384"),
        SelectOption::new("RS512", "RS512"),
        SelectOption::new("PS256", "PS256"),
        SelectOption::new("ES256", "ES256"),
        SelectOption::new("ES384", "ES384"),
        SelectOption::new("ES512", "ES512"),
        SelectOption::new("EdDSA", "EdDSA"),
    ]
}

fn tab_password(realm: Realm) -> impl IntoView {
    let described: Vec<(&'static str, String)> = realm
        .password_policy
        .rules
        .iter()
        .map(describe_rule)
        .collect();
    view! {
        <div>
            <p class="gn-text-muted gn-text-sm">
                "The password policy is enforced on every credential set. Edit the rules array via the admin API; UI inline editor lands in v0.2."
            </p>
            <ListTable headers=vec!["Rule", "Value"]>
                {described.into_iter().map(|(name, value)| view! {
                    <tr>
                        <td data-label="Rule">{name}</td>
                        <td data-label="Value"><code>{value}</code></td>
                    </tr>
                }).collect_view()}
            </ListTable>
        </div>
    }
}

fn describe_rule(rule: &PasswordRule) -> (&'static str, String) {
    match rule {
        PasswordRule::Length { min } => ("Length", format!("min {min}")),
        PasswordRule::SpecialChars { min } => ("Special chars", format!("min {min}")),
        PasswordRule::UpperCase { min } => ("Uppercase", format!("min {min}")),
        PasswordRule::LowerCase { min } => ("Lowercase", format!("min {min}")),
        PasswordRule::Digits { min } => ("Digits", format!("min {min}")),
        PasswordRule::HashIterations { iterations } => ("Hash iterations", iterations.to_string()),
        PasswordRule::HashAlgorithm { algorithm } => ("Hash algorithm", algorithm.clone()),
        PasswordRule::NotUsername => ("Not username", "-".into()),
        PasswordRule::NotEmail => ("Not email", "-".into()),
        PasswordRule::PasswordHistory { count } => ("Password history", format!("{count} entries")),
        PasswordRule::Pwned => ("Pwned check", "-".into()),
        PasswordRule::Expire { days } => ("Expire", format!("{days} days")),
        PasswordRule::BlacklistRegex { pattern } => ("Regex blocklist", pattern.clone()),
    }
}

fn tab_brute(realm: Realm) -> impl IntoView {
    let b = realm.brute_force;
    let slug = realm.slug.clone();
    let action = form_post(&slug, "brute-force");
    view! {
        <form method="post" action=action class="gn-form">
            <Toggle name="enabled".into() label="Brute-force protection enabled".into() checked=b.enabled/>
            <Toggle name="permanent_lockout".into() label="Permanent lockout".into() checked=b.permanent_lockout/>
            <Field label="Max failures".into() name="max_failures".into()>
                <TextInput name="max_failures".into() input_type="number".into() value=b.max_login_failures.to_string()/>
            </Field>
            <Field label="Wait increment (s)".into() name="wait_increment".into()>
                <TextInput name="wait_increment".into() input_type="number".into() value=b.wait_increment.as_secs().to_string()/>
            </Field>
            <Field label="Max wait (s)".into() name="max_wait".into()>
                <TextInput name="max_wait".into() input_type="number".into() value=b.max_wait.as_secs().to_string()/>
            </Field>
            <Field label="Failure reset (s)".into() name="failure_reset".into()>
                <TextInput name="failure_reset".into() input_type="number".into() value=b.failure_reset.as_secs().to_string()/>
            </Field>
            {save_bar(slug)}
        </form>
    }
}

fn tab_otp(realm: Realm) -> impl IntoView {
    use geonosis_core::realm::{OtpAlgorithm, OtpKind};
    let o = realm.otp_policy;
    let slug = realm.slug.clone();
    let action = form_post(&slug, "otp");
    let kind = match o.kind {
        OtpKind::Totp => "totp",
        OtpKind::Hotp => "hotp",
    };
    let alg = match o.algorithm {
        OtpAlgorithm::Sha1 => "sha1",
        OtpAlgorithm::Sha256 => "sha256",
        OtpAlgorithm::Sha512 => "sha512",
    };
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Kind".into() name="kind".into()>
                <Select name="kind".into() value=kind.into() options=vec![
                    SelectOption::new("totp", "TOTP"),
                    SelectOption::new("hotp", "HOTP"),
                ]/>
            </Field>
            <Field label="Algorithm".into() name="algorithm".into()>
                <Select name="algorithm".into() value=alg.into() options=vec![
                    SelectOption::new("sha1", "SHA-1"),
                    SelectOption::new("sha256", "SHA-256"),
                    SelectOption::new("sha512", "SHA-512"),
                ]/>
            </Field>
            <Field label="Digits".into() name="digits".into()>
                <Select name="digits".into() value=o.digits.to_string() options=vec![
                    SelectOption::new("6", "6"),
                    SelectOption::new("8", "8"),
                ]/>
            </Field>
            <Field label="Period (s)".into() name="period_seconds".into()>
                <TextInput name="period_seconds".into() input_type="number".into() value=o.period_seconds.to_string()/>
            </Field>
            <Field label="Look-ahead window".into() name="look_ahead_window".into()>
                <TextInput name="look_ahead_window".into() input_type="number".into() value=o.look_ahead_window.to_string()/>
            </Field>
            <Field label="Initial counter (HOTP)".into() name="initial_counter".into()>
                <TextInput name="initial_counter".into() input_type="number".into() value=o.initial_counter.to_string()/>
            </Field>
            {save_bar(slug)}
        </form>
    }
}

fn tab_webauthn(realm: Realm) -> impl IntoView {
    let w = realm.webauthn_policy;
    let slug = realm.slug.clone();
    let action = form_post(&slug, "webauthn");
    let attestation = w.attestation_conveyance_preference.clone();
    let attachment = w.authenticator_attachment.unwrap_or_else(|| "any".into());
    let uv = w.user_verification.clone();
    let sigs_csv = w.signature_algorithms.join(", ");
    let rp_id = w.relying_party_id.unwrap_or_default();
    let rp_name = w.relying_party_name.clone();
    let require_resident = w.require_resident_key;
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Relying party ID".into() name="rp_id".into()
                hint=Some("Origin host (e.g. accounts.example.com).".into())>
                <TextInput name="rp_id".into() value=rp_id/>
            </Field>
            <Field label="Relying party name".into() name="rp_name".into()>
                <TextInput name="rp_name".into() value=rp_name/>
            </Field>
            <Field label="Signature algorithms".into() name="signature_algorithms".into()
                hint=Some("Comma-separated COSE algs (e.g. ES256, RS256, EdDSA).".into())>
                <TextInput name="signature_algorithms".into() value=sigs_csv/>
            </Field>
            <Field label="Attestation conveyance".into() name="attestation".into()>
                <Select name="attestation".into() value=attestation options=vec![
                    SelectOption::new("none", "none"),
                    SelectOption::new("indirect", "indirect"),
                    SelectOption::new("direct", "direct"),
                    SelectOption::new("enterprise", "enterprise"),
                ]/>
            </Field>
            <Field label="Authenticator attachment".into() name="attachment".into()>
                <Select name="attachment".into() value=attachment options=vec![
                    SelectOption::new("any", "any"),
                    SelectOption::new("platform", "platform"),
                    SelectOption::new("cross-platform", "cross-platform"),
                ]/>
            </Field>
            <Toggle name="require_resident_key".into() label="Require resident key".into() checked=require_resident/>
            <Field label="User verification".into() name="user_verification".into()>
                <Select name="user_verification".into() value=uv options=vec![
                    SelectOption::new("required", "required"),
                    SelectOption::new("preferred", "preferred"),
                    SelectOption::new("discouraged", "discouraged"),
                ]/>
            </Field>
            {save_bar(slug)}
        </form>
    }
}

fn tab_themes(realm: Realm) -> impl IntoView {
    let t = realm.theme_binding;
    let slug = realm.slug.clone();
    let action = form_post(&slug, "themes");
    let login = t.login.unwrap_or_else(|| "default".into());
    let account = t.account.unwrap_or_else(|| "default".into());
    let admin = t.admin.unwrap_or_else(|| "default".into());
    let email = t.email.unwrap_or_else(|| "default".into());
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Login theme".into() name="login".into()>
                <TextInput name="login".into() value=login placeholder="default".into()/>
            </Field>
            <Field label="Account theme".into() name="account".into()>
                <TextInput name="account".into() value=account placeholder="default".into()/>
            </Field>
            <Field label="Admin theme".into() name="admin".into()>
                <TextInput name="admin".into() value=admin placeholder="default".into()/>
            </Field>
            <Field label="Email theme".into() name="email".into()>
                <TextInput name="email".into() value=email placeholder="default".into()/>
            </Field>
            {save_bar(slug)}
        </form>
    }
}

fn tab_localization(realm: Realm) -> impl IntoView {
    let l = realm.localization;
    let slug = realm.slug.clone();
    let action = form_post(&slug, "localization");
    let supported = l.supported_locales.join(", ");
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Default locale".into() name="default_locale".into()>
                <TextInput name="default_locale".into() value=l.default_locale placeholder="en".into()/>
            </Field>
            <Field label="Supported locales".into() name="supported_locales".into()
                hint=Some("Comma-separated BCP-47 tags.".into())>
                <TextInput name="supported_locales".into() value=supported placeholder="en, tr, de".into()/>
            </Field>
            {save_bar(slug)}
        </form>
    }
}

fn tab_events(realm: Realm) -> impl IntoView {
    let e = realm.events;
    let slug = realm.slug.clone();
    let action = form_post(&slug, "events");
    let listeners = e.events_listeners.join(", ");
    view! {
        <form method="post" action=action class="gn-form">
            <Toggle name="login_enabled".into() label="Login events enabled".into() checked=e.login_enabled/>
            <Toggle name="admin_enabled".into() label="Admin events enabled".into() checked=e.admin_enabled/>
            <Field label="Retention (days)".into() name="retention_days".into()>
                <TextInput name="retention_days".into() input_type="number".into() value=e.retention_days.to_string()/>
            </Field>
            <Field label="Event listeners".into() name="events_listeners".into()
                hint=Some("Comma-separated listener URNs (jboss-logging, ...).".into())>
                <TextInput name="events_listeners".into() value=listeners/>
            </Field>
            {save_bar(slug)}
        </form>
    }
}

fn tab_acr(realm: Realm) -> impl IntoView {
    let levels = realm.acr_policy.levels;
    let is_empty = levels.is_empty();
    let rows: Vec<(String, String, String)> = levels
        .into_iter()
        .map(|l| (l.value, l.display_name, describe_acr(&l.require)))
        .collect();
    view! {
        <div>
            <p class="gn-text-muted gn-text-sm">
                "Map ACR values to AMR / authenticator requirements. Inline editor lands in v0.2."
            </p>
            {if is_empty {
                view! {
                    <div class="gn-empty">
                        <p class="gn-empty__title">"No ACR levels"</p>
                        <p class="gn-empty__desc">"Define `acr_values` mappings to step-up authentication."</p>
                    </div>
                }.into_any()
            } else {
                view! {
                    <ListTable headers=vec!["Value", "Display name", "Requirement"]>
                        {rows.into_iter().map(|(value, name, req)| view! {
                            <tr>
                                <td data-label="Value"><code>{value}</code></td>
                                <td data-label="Display name">{name}</td>
                                <td data-label="Requirement"><code>{req}</code></td>
                            </tr>
                        }).collect_view()}
                    </ListTable>
                }.into_any()
            }}
        </div>
    }
}

fn describe_acr(req: &AcrRequirement) -> String {
    match req {
        AcrRequirement::Any => "any".into(),
        AcrRequirement::AmrContains(v) => format!(
            "amr-contains({})",
            v.iter()
                .map(|a| a.as_token_value())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        AcrRequirement::AllOf(v) => format!("all-of({})", v.len()),
        AcrRequirement::AnyOf(v) => format!("any-of({})", v.len()),
        AcrRequirement::SenderConstrained(_) => "sender-constrained".into(),
    }
}

fn tab_org_policy(realm: Realm) -> impl IntoView {
    let p = realm.organization_policy;
    let slug = realm.slug.clone();
    let action = form_post(&slug, "org-policy");
    view! {
        <form method="post" action=action class="gn-form">
            <Field label="Default invitation TTL (days)".into() name="default_invitation_ttl_days".into()>
                <TextInput name="default_invitation_ttl_days".into() input_type="number".into()
                    value=p.default_invitation_ttl_days.to_string()/>
            </Field>
            <Field label="Default self-signup role".into() name="default_role_for_self_signup".into()>
                <TextInput name="default_role_for_self_signup".into()
                    value=p.default_role_for_self_signup.unwrap_or_default()/>
            </Field>
            <Toggle name="require_domain_verification".into()
                label="Require domain verification".into()
                checked=p.require_domain_verification/>
            <Toggle name="auto_join_on_domain_match".into()
                label="Auto-join on verified domain match".into()
                checked=p.auto_join_on_domain_match/>
            {save_bar(slug)}
        </form>
    }
}

fn tab_defaults(realm: Realm) -> impl IntoView {
    let d = realm.default_roles;
    let realm_role_count = d.realm_roles.len();
    let client_role_groups = d.client_roles.len();
    let group_count = realm.default_groups.len();
    view! {
        <div>
            <h2>"Default roles"</h2>
            <p class="gn-text-muted gn-text-sm">"New users automatically receive these realm and client roles."</p>
            <dl class="gn-defs">
                <dt>"Realm roles assigned"</dt>
                <dd>{realm_role_count.to_string()}</dd>
                <dt>"Client role groups"</dt>
                <dd>{client_role_groups.to_string()}</dd>
            </dl>
            <h2 style="margin-top:32px">"Default groups"</h2>
            <p class="gn-text-muted gn-text-sm">"New users automatically join these groups."</p>
            <dl class="gn-defs">
                <dt>"Groups assigned"</dt>
                <dd>{group_count.to_string()}</dd>
            </dl>
        </div>
    }
}

#[doc(hidden)]
pub fn _keep_jws() -> JwsAlgorithm {
    JwsAlgorithm::RS256
}
