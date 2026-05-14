//! `/admin/profile` — own-account management page (admin or user).

use leptos::prelude::*;

use geonosis_core::User;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::breadcrumb::Crumb;
use crate::leptos_ui::components::form::{ActionBar, Field, TextInput, Toggle};
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;
use crate::leptos_ui::components::tabs::{TabBar, TabItem};
use crate::leptos_ui::components::widgets::{
    Alert, AlertKind, ButtonKind, EmptyState, LinkButton,
};

pub const PROFILE_TABS: &[(&str, &str)] = &[
    ("general", "General"),
    ("password", "Password"),
    ("otp", "OTP"),
    ("webauthn", "WebAuthn"),
    ("sessions", "Sessions"),
    ("signout", "Sign out"),
];

#[derive(Clone, Debug)]
pub struct ProfileSession {
    pub id: String,
    pub started_at: String,
    pub last_seen_at: String,
    pub current: bool,
}

#[derive(Clone, Debug)]
pub struct ProfileData {
    pub user: User,
    pub sessions: Vec<ProfileSession>,
}

#[component]
pub fn ProfilePage(
    data: ProfileData,
    active_tab: String,
    ctx: PageContext,
    #[prop(default = None)] flash: Option<String>,
    #[prop(default = None)] error: Option<String>,
) -> impl IntoView {
    let username = data.user.username.clone();
    let display_name = data
        .user
        .name
        .as_ref()
        .and_then(|n| {
            let parts = [&n.given, &n.family]
                .iter()
                .filter_map(|s| (*s).clone())
                .collect::<Vec<_>>();
            (!parts.is_empty()).then(|| parts.join(" "))
        })
        .unwrap_or_else(|| username.clone());
    let ctx = ctx
        .with_title("My profile")
        .with_section("profile")
        .with_crumbs(vec![Crumb::current("My profile")]);
    let tab_items = PROFILE_TABS
        .iter()
        .map(|(k, l)| TabItem::new(*k, *l, format!("/admin/profile?tab={k}")))
        .collect::<Vec<_>>();
    let panel = match active_tab.as_str() {
        "general" => render_general(data.user.clone()).into_any(),
        "password" => render_password().into_any(),
        "otp" => render_otp().into_any(),
        "webauthn" => render_webauthn().into_any(),
        "sessions" => render_sessions(data.sessions.clone()).into_any(),
        "signout" => render_signout().into_any(),
        _ => view! { <Alert message="Unknown tab.".into() kind=AlertKind::Warning/> }.into_any(),
    };
    view! {
        <Page context=ctx>
            <PageHeader title=display_name subtitle=Some(format!("Signed in as @{username}"))/>
            {flash.map(|m| view! { <Alert message=m kind=AlertKind::Success/> })}
            {error.map(|e| view! { <Alert message=e kind=AlertKind::Danger/> })}
            <TabBar active=active_tab.clone() items=tab_items/>
            {panel}
        </Page>
    }
}

fn render_general(u: User) -> impl IntoView {
    let email = u.email.clone().unwrap_or_default();
    let first = u.name.as_ref().and_then(|n| n.given.clone()).unwrap_or_default();
    let last = u.name.as_ref().and_then(|n| n.family.clone()).unwrap_or_default();
    view! {
        <form method="post" action="/admin/profile/general" class="gn-form">
            <Field label="Username".into() name="username".into()>
                <TextInput name="username".into() value=u.username.clone() read_only=true/>
            </Field>
            <Field label="Email".into() name="email".into()>
                <TextInput name="email".into() input_type="email".into() value=email
                    autocomplete="email".into()/>
            </Field>
            <Toggle name="email_verified".into() label="Email verified".into() checked=u.email_verified/>
            <Field label="First name".into() name="first_name".into()>
                <TextInput name="first_name".into() value=first autocomplete="given-name".into()/>
            </Field>
            <Field label="Last name".into() name="last_name".into()>
                <TextInput name="last_name".into() value=last autocomplete="family-name".into()/>
            </Field>
            <ActionBar>
                <button type="submit" class="gn-btn gn-btn--primary">"Save"</button>
            </ActionBar>
        </form>
    }
}

fn render_password() -> impl IntoView {
    view! {
        <form method="post" action="/admin/profile/password" class="gn-form">
            <Field label="Current password".into() name="current".into() required=true>
                <TextInput name="current".into() input_type="password".into() required=true
                    autocomplete="current-password".into()/>
            </Field>
            <Field label="New password".into() name="new".into() required=true>
                <TextInput name="new".into() input_type="password".into() required=true
                    autocomplete="new-password".into()/>
            </Field>
            <Field label="Confirm new password".into() name="confirm".into() required=true>
                <TextInput name="confirm".into() input_type="password".into() required=true
                    autocomplete="new-password".into()/>
            </Field>
            <ActionBar>
                <button type="submit" class="gn-btn gn-btn--primary">"Update password"</button>
            </ActionBar>
        </form>
    }
}

fn render_otp() -> impl IntoView {
    view! {
        <div class="gn-card">
            <div class="gn-card__title">"Configure OTP"</div>
            <p class="gn-card__subtitle">
                "Scan the QR code with an authenticator app, then enter the 6-digit code to verify."
            </p>
            <p class="gn-text-muted">
                "OTP enrolment lands in v0.1.x once the credential service exposes the seeding endpoint."
            </p>
        </div>
    }
}

fn render_webauthn() -> impl IntoView {
    view! {
        <div class="gn-card">
            <div class="gn-card__title">"Security keys"</div>
            <p class="gn-card__subtitle">
                "Register a passkey or USB security key to enable strong authentication."
            </p>
            <p class="gn-text-muted">
                "WebAuthn enrolment ships in v0.2 alongside the browser ceremony JS."
            </p>
        </div>
    }
}

fn render_sessions(sessions: Vec<ProfileSession>) -> impl IntoView {
    if sessions.is_empty() {
        return view! {
            <EmptyState title="No active sessions".into()
                description="No live sessions tied to this account.".into()/>
        }.into_any();
    }
    view! {
        <ListTable headers=vec!["Session", "Started", "Last seen", "Actions"]>
            {sessions.iter().map(|s| {
                let revoke = format!("/admin/profile/sessions/{}/revoke", s.id);
                let label = if s.current { "Current".to_string() } else { s.id.clone() };
                view! {
                    <tr>
                        <td data-label="Session"><code class="gn-truncate">{label}</code></td>
                        <td data-label="Started" class="gn-text-subtle">{s.started_at.clone()}</td>
                        <td data-label="Last seen" class="gn-text-subtle">{s.last_seen_at.clone()}</td>
                        <td data-label="Actions" class="gn-table__actions">
                            {(!s.current).then(|| view! {
                                <form method="post" action=revoke style="display:inline" data-gn-confirm="Revoke this session?">
                                    <button type="submit" class="gn-btn gn-btn--sm gn-btn--danger">"Revoke"</button>
                                </form>
                            })}
                        </td>
                    </tr>
                }
            }).collect_view()}
        </ListTable>
    }.into_any()
}

fn render_signout() -> impl IntoView {
    view! {
        <div class="gn-card">
            <div class="gn-card__title">"Sign out"</div>
            <p class="gn-card__subtitle">
                "End your admin session immediately. You'll be redirected to the sign-in page."
            </p>
            <form method="post" action="/admin/logout" data-gn-confirm="Sign out now?">
                <button type="submit" class="gn-btn gn-btn--danger">"Sign out"</button>
            </form>
        </div>
    }
}

/// Hidden export: keep `LinkButton` import alive for future profile actions
/// without triggering an "unused import" warning during incremental builds.
pub fn _link_button_kind() -> ButtonKind {
    ButtonKind::Default
}

/// Convenience used by the profile router to wire the cancel button.
pub fn _link_button_cancel(href: String) -> impl IntoView {
    view! { <LinkButton href=href label="Cancel".to_string()/> }
}
