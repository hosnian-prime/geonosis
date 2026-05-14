use maud::{html, Markup, DOCTYPE};

/// Page-level wrapper. Always emits the CSP nonce-friendly stylesheet
/// reference; callers pass the matched route so the side-nav can show
/// the active link. When `realm_slug` is `Some`, sub-realm nav links
/// resolve to `/admin/realms/{slug}/...`; when `None` (realm list
/// page), only the Realms link is shown.
pub fn page(title: &str, locale: &str, active: &str, realm_slug: Option<&str>, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang=(locale) dir="auto" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width,initial-scale=1";
                title { (title) " · Geonosis" }
                link rel="stylesheet" href="/static/admin.css";
            }
            body {
                div class="gn-page" {
                    nav class="gn-nav" {
                        div class="gn-nav-brand" { "Geonosis" }
                        (nav_link("/admin/realms", "Realms", active == "realms"))
                        @if let Some(slug) = realm_slug {
                            (nav_link(&format!("/admin/realms/{slug}/clients"), "Clients", active == "clients"))
                            (nav_link(&format!("/admin/realms/{slug}/users"), "Users", active == "users"))
                            (nav_link(&format!("/admin/realms/{slug}/flows"), "Flows", active == "flows"))
                            (nav_link(&format!("/admin/realms/{slug}/spi"), "SPI", active == "spi"))
                            (nav_link(&format!("/admin/realms/{slug}/idps"), "Identity providers", active == "idps"))
                            (nav_link(&format!("/admin/realms/{slug}/events"), "Events", active == "events"))
                        }
                    }
                    main class="gn-main" { (body) }
                }
            }
        }
    }
}

pub fn nav_link(href: &str, label: &str, active: bool) -> Markup {
    html! {
        @if active {
            a href=(href) aria-current="page" { (label) }
        } @else {
            a href=(href) { (label) }
        }
    }
}
