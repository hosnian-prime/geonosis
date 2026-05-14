//! `/admin/realms/{slug}/keys` — list realm signing keys.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::breadcrumb::Crumb;
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;
use crate::leptos_ui::components::widgets::{Badge, BadgeKind, EmptyState};

#[derive(Clone, Debug)]
pub struct KeyRow {
    pub kid: String,
    pub algorithm: String,
    pub usage: String,
    pub state: String,
    pub created_at: String,
    pub rotated_at: Option<String>,
}

#[component]
pub fn KeysPage(realm_slug: String, rows: Vec<KeyRow>, ctx: PageContext) -> impl IntoView {
    let ctx = ctx
        .with_title("Keys")
        .with_section("keys")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::current("Keys"),
        ]);
    let is_empty = rows.is_empty();
    view! {
        <Page context=ctx>
            <PageHeader
                title="Signing keys".into()
                subtitle=Some("Active and historical signing keys for tokens, JWE encryption, and SAML assertions.".into())
            />
            {if is_empty {
                view! {
                    <EmptyState title="No realm keys".into()
                        description="Bootstrap will provision a default key on first run.".into()/>
                }.into_any()
            } else {
                view! {
                    <ListTable headers=vec!["Key ID", "Algorithm", "Usage", "State", "Created", "Rotated"]>
                        {rows.into_iter().map(|r| {
                            let state_kind = match r.state.as_str() {
                                "active" | "Active" => BadgeKind::Success,
                                "legacy" | "Legacy" => BadgeKind::Warning,
                                "retired" | "Retired" => BadgeKind::Neutral,
                                _ => BadgeKind::Info,
                            };
                            view! {
                                <tr>
                                    <td data-label="KID"><code class="gn-truncate">{r.kid}</code></td>
                                    <td data-label="Algorithm"><Badge label=r.algorithm kind=BadgeKind::Accent/></td>
                                    <td data-label="Usage"><Badge label=r.usage kind=BadgeKind::Info/></td>
                                    <td data-label="State"><Badge label=r.state kind=state_kind/></td>
                                    <td data-label="Created" class="gn-text-subtle">{r.created_at}</td>
                                    <td data-label="Rotated" class="gn-text-subtle">{r.rotated_at.unwrap_or_else(|| "—".into())}</td>
                                </tr>
                            }
                        }).collect_view()}
                    </ListTable>
                }.into_any()
            }}
        </Page>
    }
}
