//! Small presentation primitives — buttons, badges, alerts, empty
//! states, stat cards, link cards. Pages compose these instead of
//! re-emitting the underlying CSS classes per call site.

use leptos::prelude::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ButtonKind {
    Default,
    Primary,
    Danger,
    Ghost,
}

impl ButtonKind {
    fn css(self) -> &'static str {
        match self {
            ButtonKind::Default => "gn-btn",
            ButtonKind::Primary => "gn-btn gn-btn--primary",
            ButtonKind::Danger => "gn-btn gn-btn--danger",
            ButtonKind::Ghost => "gn-btn gn-btn--ghost",
        }
    }
}

#[component]
pub fn LinkButton(
    href: String,
    label: String,
    #[prop(default = ButtonKind::Default)] kind: ButtonKind,
    #[prop(default = false)] small: bool,
) -> impl IntoView {
    let class = if small {
        format!("{} gn-btn--sm", kind.css())
    } else {
        kind.css().to_string()
    };
    view! { <a class=class href=href>{label}</a> }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BadgeKind {
    Neutral,
    Success,
    Danger,
    Warning,
    Info,
    Accent,
}

impl BadgeKind {
    fn css(self) -> &'static str {
        match self {
            BadgeKind::Neutral => "gn-badge",
            BadgeKind::Success => "gn-badge gn-badge--success",
            BadgeKind::Danger => "gn-badge gn-badge--danger",
            BadgeKind::Warning => "gn-badge gn-badge--warning",
            BadgeKind::Info => "gn-badge gn-badge--info",
            BadgeKind::Accent => "gn-badge gn-badge--accent",
        }
    }
}

#[component]
pub fn Badge(
    label: String,
    #[prop(default = BadgeKind::Neutral)] kind: BadgeKind,
    #[prop(default = false)] dot: bool,
) -> impl IntoView {
    view! {
        <span class=kind.css()>
            {dot.then(|| view! { <span class="gn-badge__dot"></span> })}
            {label}
        </span>
    }
}

/// Convenience: enabled/disabled state badge.
#[component]
pub fn StateBadge(enabled: bool) -> impl IntoView {
    if enabled {
        view! { <Badge label="Enabled".into() kind=BadgeKind::Success dot=true/> }
    } else {
        view! { <Badge label="Disabled".into() kind=BadgeKind::Danger dot=true/> }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AlertKind {
    Info,
    Success,
    Warning,
    Danger,
}

impl AlertKind {
    fn css(self) -> &'static str {
        match self {
            AlertKind::Info => "gn-alert gn-alert--info",
            AlertKind::Success => "gn-alert gn-alert--success",
            AlertKind::Warning => "gn-alert gn-alert--warning",
            AlertKind::Danger => "gn-alert gn-alert--danger",
        }
    }
}

#[component]
pub fn Alert(
    message: String,
    #[prop(default = AlertKind::Info)] kind: AlertKind,
) -> impl IntoView {
    view! { <div class=kind.css() role="status">{message}</div> }
}

#[component]
pub fn EmptyState(
    title: String,
    description: String,
    #[prop(default = None)] action: Option<AnyView>,
) -> impl IntoView {
    view! {
        <div class="gn-empty">
            <p class="gn-empty__title">{title}</p>
            <p class="gn-empty__desc">{description}</p>
            {action}
        </div>
    }
}

#[component]
pub fn StatCard(
    label: String,
    value: String,
    #[prop(default = None)] hint: Option<String>,
) -> impl IntoView {
    view! {
        <div class="gn-stat-card">
            <span class="gn-stat-card__label">{label}</span>
            <span class="gn-stat-card__value">{value}</span>
            {hint.map(|h| view! { <span class="gn-stat-card__hint">{h}</span> })}
        </div>
    }
}

#[component]
pub fn LinkCard(
    href: String,
    title: String,
    description: String,
    #[prop(default = None)] count: Option<String>,
) -> impl IntoView {
    view! {
        <a class="gn-link-card" href=href>
            <div>
                <div class="gn-link-card__title">{title}</div>
                <div class="gn-link-card__desc">{description}</div>
            </div>
            {count.map(|c| view! { <div class="gn-link-card__count">{c}</div> })}
        </a>
    }
}
