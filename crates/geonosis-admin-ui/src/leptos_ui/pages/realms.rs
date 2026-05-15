//! `/admin/realms` — realm list page.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::breadcrumb::Crumb;
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;
use crate::leptos_ui::components::widgets::{EmptyState, LinkButton, StateBadge};

#[derive(Clone, Debug)]
pub struct RealmRow {
    pub slug: String,
    pub display_name: String,
    pub enabled: bool,
    pub created_at: String,
}

#[component]
pub fn RealmsPage(realms: Vec<RealmRow>, ctx: PageContext) -> impl IntoView {
    let ctx = ctx
        .with_title("Realms")
        .with_section("realms")
        .with_crumbs(vec![Crumb::current("Realms")]);
    let is_empty = realms.is_empty();
    view! {
        <Page context=ctx>
            <PageHeader
                title="Realms".to_string()
                subtitle=Some("All identity universes hosted by this Geonosis instance.".to_string())
                actions=Some(view! {
                    <LinkButton
                        href="/admin/realms/new".to_string()
                        label="+ Create realm".to_string()
                        kind=crate::leptos_ui::components::widgets::ButtonKind::Primary
                    />
                }.into_any())
            />
            {if is_empty {
                view! {
                    <EmptyState
                        title="No realms yet".into()
                        description="Realms isolate tenants, identity providers, users and clients.".into()
                        action=Some(view! {
                            <LinkButton
                                href="/admin/realms/new".to_string()
                                label="+ Create your first realm".to_string()
                                kind=crate::leptos_ui::components::widgets::ButtonKind::Primary
                            />
                        }.into_any())
                    />
                }
                .into_any()
            } else {
                view! {
                    <ListTable headers=vec!["Slug", "Display name", "State", "Created"]>
                        {realms.into_iter().map(|r| {
                            let href = format!("/admin/realms/{}", r.slug);
                            view! {
                                <tr>
                                    <td data-label="Slug"><a href=href.clone()><code>{r.slug}</code></a></td>
                                    <td data-label="Display name">{r.display_name}</td>
                                    <td data-label="State"><StateBadge enabled=r.enabled/></td>
                                    <td data-label="Created" class="gn-text-subtle gn-text-sm">{r.created_at}</td>
                                </tr>
                            }
                        }).collect_view()}
                    </ListTable>
                }
                .into_any()
            }}
        </Page>
    }
}

/// `/admin/realms/new` — minimal create form.
#[component]
pub fn RealmCreatePage(
    ctx: PageContext,
    #[prop(default = None)] error: Option<String>,
) -> impl IntoView {
    use crate::leptos_ui::components::form::{ActionBar, Field, TextInput, Toggle};
    use crate::leptos_ui::components::widgets::{Alert, AlertKind, LinkButton};
    let ctx = ctx
        .with_title("Create realm")
        .with_section("realms")
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::current("Create realm"),
        ]);
    view! {
        <Page context=ctx>
            <PageHeader
                title="Create realm".to_string()
                subtitle=Some("Realms isolate users, clients and configuration.".to_string())
            />
            {error.map(|e| view! { <Alert message=e kind=AlertKind::Danger/> })}
            <form method="post" action="/admin/realms" class="gn-form">
                <Field label="Slug".into() name="slug".into() required=true
                    hint=Some("URL-safe identifier; e.g. staging.".into())>
                    <TextInput name="slug".into() required=true placeholder="staging".into()/>
                </Field>
                <Field label="Display name".into() name="display_name".into() required=true>
                    <TextInput name="display_name".into() required=true placeholder="Staging".into()/>
                </Field>
                <Toggle name="enabled".into() label="Enabled".into() checked=true/>
                <ActionBar>
                    <LinkButton href="/admin/realms".to_string() label="Cancel".to_string()/>
                    <button type="submit" class="gn-btn gn-btn--primary">"Create realm"</button>
                </ActionBar>
            </form>
        </Page>
    }
}
