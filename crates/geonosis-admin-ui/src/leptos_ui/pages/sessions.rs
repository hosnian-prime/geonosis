//! `/admin/realms/{slug}/sessions` — active SSO session list with revoke action.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::breadcrumb::Crumb;
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;
use crate::leptos_ui::components::widgets::{Badge, BadgeKind, EmptyState};

#[derive(Clone, Debug)]
pub struct SessionRow {
    pub id: String,
    pub user_id: String,
    pub authn_level: String,
    pub idp_alias: Option<String>,
    pub started_at: String,
    pub last_seen_at: String,
    pub client_count: usize,
}

#[component]
pub fn SessionsPage(realm_slug: String, rows: Vec<SessionRow>, ctx: PageContext) -> impl IntoView {
    let ctx = ctx
        .with_title("Sessions")
        .with_section("sessions")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::current("Sessions"),
        ]);
    let is_empty = rows.is_empty();
    view! {
        <Page context=ctx>
            <PageHeader
                title="Sessions".into()
                subtitle=Some("Live SSO sessions, newest first. Revoke to log every bound client out.".into())
            />
            {if is_empty {
                view! {
                    <EmptyState title="No active sessions".into()
                        description="Sessions are created when a user signs in. Once active they appear here.".into()/>
                }.into_any()
            } else {
                view! {
                    <ListTable headers=vec![
                        "Session", "User", "Authn level", "IdP",
                        "Started", "Last seen", "Clients", "Actions"
                    ]>
                        {rows.into_iter().map(|r| {
                            let revoke = format!("/admin/realms/{realm_slug}/sessions/{}/revoke", r.id);
                            view! {
                                <tr>
                                    <td data-label="Session"><code class="gn-truncate">{r.id}</code></td>
                                    <td data-label="User"><code class="gn-truncate">{r.user_id}</code></td>
                                    <td data-label="Authn">
                                        <Badge label=r.authn_level kind=BadgeKind::Accent/>
                                    </td>
                                    <td data-label="IdP">{r.idp_alias.unwrap_or_else(|| "—".into())}</td>
                                    <td data-label="Started" class="gn-text-subtle">{r.started_at}</td>
                                    <td data-label="Last seen" class="gn-text-subtle">{r.last_seen_at}</td>
                                    <td data-label="Clients">{r.client_count.to_string()}</td>
                                    <td data-label="Actions" class="gn-table__actions">
                                        <form method="post" action=revoke style="display:inline" data-gn-confirm="Revoke this session?">
                                            <button type="submit" class="gn-btn gn-btn--sm gn-btn--danger">"Revoke"</button>
                                        </form>
                                    </td>
                                </tr>
                            }
                        }).collect_view()}
                    </ListTable>
                }.into_any()
            }}
        </Page>
    }
}
