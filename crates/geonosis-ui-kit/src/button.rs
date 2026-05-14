use maud::{html, Markup};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonKind {
    Default,
    Primary,
    Danger,
}

pub fn button(label: &str, kind: ButtonKind, button_type: &str) -> Markup {
    let class = match kind {
        ButtonKind::Default => "gn-button",
        ButtonKind::Primary => "gn-button gn-button--primary",
        ButtonKind::Danger => "gn-button gn-button--danger",
    };
    html! {
        button type=(button_type) class=(class) { (label) }
    }
}
