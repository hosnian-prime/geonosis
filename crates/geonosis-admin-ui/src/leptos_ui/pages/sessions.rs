//! `/admin-next/realms/:slug/sessions` — active SSO sessions.
//!
//! Read-only list. Revocation lands via the existing
//! `DELETE /admin/v1/realms/:slug/sessions/:id` endpoint plus a
//! per-row form action once the form-action layer wires up CSRF.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;

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
pub fn SessionsPage(realm_slug: String, rows: Vec<SessionRow>) -> impl IntoView {
    let ctx = PageContext {
        title: "Sessions".into(),
        active_section: "sessions",
        realm_slug: Some(realm_slug.clone()),
    };
    let back = format!("/admin-next/realms/{realm_slug}");
    let empty = rows.is_empty();
    view! {
        <Page context=ctx>
            <PageHeader
                title="Sessions"
                back_href=back
                subtitle="Live SSO sessions, newest first. Revoke a session to log every bound client out."
            />
            {if empty {
                view! { <p class="gn-empty">"No active sessions in this realm."</p> }.into_any()
            } else {
                view! {
                    <ListTable headers=vec![
                        "Session", "User", "Authn level", "IdP",
                        "Started", "Last seen", "Clients"
                    ]>
                        {rows.into_iter().map(|r| view! {
                            <tr>
                                <td><code>{r.id}</code></td>
                                <td><code>{r.user_id}</code></td>
                                <td>{r.authn_level}</td>
                                <td>{r.idp_alias.unwrap_or_else(|| "—".into())}</td>
                                <td><time>{r.started_at}</time></td>
                                <td><time>{r.last_seen_at}</time></td>
                                <td>{r.client_count.to_string()}</td>
                            </tr>
                        }).collect_view()}
                    </ListTable>
                }.into_any()
            }}
        </Page>
    }
}
