use maud::{html, Markup};

/// Card container with an optional heading.
pub fn card(title: Option<&str>, body: Markup) -> Markup {
    html! {
        section class="gn-card" {
            @if let Some(t) = title {
                h2 { (t) }
            }
            (body)
        }
    }
}
