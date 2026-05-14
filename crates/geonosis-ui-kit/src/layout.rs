use maud::{html, Markup, DOCTYPE};

/// Page-level wrapper. Always emits the CSP nonce-friendly stylesheet
/// reference; callers pass the matched route so the side-nav can show
/// the active link.
pub fn page(title: &str, locale: &str, active: &str, body: Markup) -> Markup {
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
                        (nav_link("/admin/clients", "Clients", active == "clients"))
                        (nav_link("/admin/users", "Users", active == "users"))
                        (nav_link("/admin/flows", "Flows", active == "flows"))
                        (nav_link("/admin/spi", "SPI", active == "spi"))
                        (nav_link("/admin/idps", "Identity providers", active == "idps"))
                        (nav_link("/admin/events", "Events", active == "events"))
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
