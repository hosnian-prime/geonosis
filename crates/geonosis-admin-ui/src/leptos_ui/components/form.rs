//! Form primitives — every CRUD page composes these instead of
//! emitting raw `<label>`/`<input>` pairs. Keeps the markup
//! consistent (44-px touch targets, focus rings, hint/error layout)
//! and DRY across the dozens of settings tabs.

use leptos::prelude::*;

#[component]
pub fn Field(
    label: String,
    /// HTML element id — wired to the label's `for` attribute.
    name: String,
    /// The control. Caller supplies an input / select / textarea /
    /// custom widget already styled.
    children: Children,
    #[prop(default = false)] required: bool,
    #[prop(default = None)] hint: Option<String>,
    #[prop(default = None)] error: Option<String>,
) -> impl IntoView {
    view! {
        <div class="gn-field">
            <label class="gn-field__label" for=name.clone()>
                {label}
                {required.then(|| view! { <span class="gn-field__required" aria-hidden="true">"*"</span> })}
            </label>
            {children()}
            {hint.map(|h| view! { <span class="gn-field__hint">{h}</span> })}
            {error.map(|e| view! { <span class="gn-field__error" role="alert">{e}</span> })}
        </div>
    }
}

#[component]
pub fn TextInput(
    name: String,
    #[prop(default = "text".to_string())] input_type: String,
    #[prop(default = String::new())] value: String,
    #[prop(default = String::new())] placeholder: String,
    #[prop(default = false)] required: bool,
    #[prop(default = false)] read_only: bool,
    #[prop(default = String::new())] autocomplete: String,
) -> impl IntoView {
    view! {
        <input
            class="gn-input"
            type=input_type
            id=name.clone()
            name=name
            value=value
            placeholder=placeholder
            required=required
            readonly=read_only
            autocomplete=autocomplete
        />
    }
}

#[component]
pub fn Textarea(
    name: String,
    #[prop(default = String::new())] value: String,
    #[prop(default = String::new())] placeholder: String,
    #[prop(default = 4)] rows: u32,
    #[prop(default = false)] code: bool,
) -> impl IntoView {
    let class = if code {
        "gn-textarea gn-textarea--code"
    } else {
        "gn-textarea"
    };
    view! {
        <textarea
            class=class
            id=name.clone()
            name=name
            placeholder=placeholder
            rows=rows
        >{value}</textarea>
    }
}

#[derive(Clone, Debug)]
pub struct SelectOption {
    pub value: String,
    pub label: String,
}

impl SelectOption {
    pub fn new(value: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            label: label.into(),
        }
    }
}

#[component]
pub fn Select(
    name: String,
    options: Vec<SelectOption>,
    #[prop(default = String::new())] value: String,
) -> impl IntoView {
    view! {
        <select class="gn-select" id=name.clone() name=name>
            {options
                .into_iter()
                .map(|opt| {
                    let selected = opt.value == value;
                    view! {
                        <option value=opt.value.clone() selected=selected>{opt.label.clone()}</option>
                    }
                })
                .collect_view()}
        </select>
    }
}

#[component]
pub fn Toggle(
    name: String,
    label: String,
    #[prop(default = false)] checked: bool,
) -> impl IntoView {
    view! {
        <label class="gn-toggle">
            <input
                class="gn-toggle__input"
                type="checkbox"
                id=name.clone()
                name=name
                value="true"
                checked=checked
            />
            <span class="gn-toggle__slider" aria-hidden="true"></span>
            <span class="gn-toggle__label">{label}</span>
        </label>
    }
}

#[derive(Clone, Debug)]
pub struct CheckOption {
    pub name: String,
    pub label: String,
    pub checked: bool,
}

impl CheckOption {
    pub fn new(name: impl Into<String>, label: impl Into<String>, checked: bool) -> Self {
        Self {
            name: name.into(),
            label: label.into(),
            checked,
        }
    }
}

#[component]
pub fn CheckGrid(options: Vec<CheckOption>) -> impl IntoView {
    view! {
        <div class="gn-checks">
            {options
                .into_iter()
                .map(|o| view! {
                    <label class="gn-check">
                        <input type="checkbox" name=o.name.clone() value="true" checked=o.checked/>
                        <span>{o.label.clone()}</span>
                    </label>
                })
                .collect_view()}
        </div>
    }
}

#[component]
pub fn ActionBar(children: Children) -> impl IntoView {
    view! { <div class="gn-action-bar">{children()}</div> }
}
