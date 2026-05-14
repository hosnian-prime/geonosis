use maud::{html, Markup, PreEscaped};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Text,
    Email,
    Password,
}

impl FieldKind {
    fn as_input_type(self) -> &'static str {
        match self {
            FieldKind::Text => "text",
            FieldKind::Email => "email",
            FieldKind::Password => "password",
        }
    }
}

pub fn text_input(name: &str, value: &str, kind: FieldKind) -> Markup {
    html! {
        input class="gn-input" type=(kind.as_input_type()) name=(name) value=(value);
    }
}

/// Label + input pair with `aria-describedby` wiring.
pub fn field(
    label: &str,
    input_name: &str,
    value: &str,
    help: Option<&str>,
    kind: FieldKind,
) -> Markup {
    let describedby = help.map(|_| format!("{input_name}-help"));
    let describedby_attr = describedby
        .as_deref()
        .map(|d| PreEscaped(format!(" aria-describedby=\"{d}\"")))
        .unwrap_or(PreEscaped(String::new()));
    html! {
        label class="gn-field" {
            span class="gn-field-label" { (label) }
            (PreEscaped(format!(
                "<input class=\"gn-input\" type=\"{kind}\" name=\"{name}\" value=\"{value}\"{described}>",
                kind = kind.as_input_type(),
                name = html_escape_attr(input_name),
                value = html_escape_attr(value),
                described = describedby_attr.0,
            )))
            @if let Some(h) = help {
                span id=(describedby.unwrap()) class="gn-field-help" { (h) }
            }
        }
    }
}

fn html_escape_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
