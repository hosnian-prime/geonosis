//! `/admin/realms/{slug}/user-profile` — user-profile schema editor.

use leptos::prelude::*;

use geonosis_core::user_profile::{UnmanagedAttributePolicy, UserProfile};

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::breadcrumb::Crumb;
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;
use crate::leptos_ui::components::widgets::{Badge, BadgeKind, EmptyState};

#[component]
pub fn UserProfileSchemaPage(
    realm_slug: String,
    profile: UserProfile,
    ctx: PageContext,
) -> impl IntoView {
    let ctx = ctx
        .with_title("User profile schema")
        .with_section("settings")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::current("User profile schema"),
        ]);
    let policy = match profile.unmanaged_policy {
        UnmanagedAttributePolicy::Allow => "Allow",
        UnmanagedAttributePolicy::Reject => "Reject",
        UnmanagedAttributePolicy::Hidden => "Hidden",
    };
    view! {
        <Page context=ctx>
            <PageHeader
                title="User profile schema".into()
                subtitle=Some("Typed attributes, validators and permissions for every user in this realm.".into())
            />

            <section class="gn-section">
                <h2>"Attributes"</h2>
                {if profile.attributes.is_empty() {
                    view! {
                        <EmptyState title="No attributes declared".into()
                            description="Built-ins (username, email) are always present.".into()/>
                    }.into_any()
                } else {
                    view! {
                        <ListTable headers=vec![
                            "Name", "Display name", "Group", "Required",
                            "Multivalued", "Admin can edit", "User can edit"
                        ]>
                            {profile.attributes.iter().map(|a| {
                                let req = if a.required { "yes" } else { "no" };
                                let mv = if a.multivalued { "yes" } else { "no" };
                                let admin_edit = if a.permissions.edit.admin { "yes" } else { "no" };
                                let user_edit = if a.permissions.edit.user { "yes" } else { "no" };
                                view! {
                                    <tr>
                                        <td data-label="Name"><code>{a.name.clone()}</code></td>
                                        <td data-label="Display name">{a.display_name.clone()}</td>
                                        <td data-label="Group">{a.group.clone().unwrap_or_else(|| "—".into())}</td>
                                        <td data-label="Required">{req}</td>
                                        <td data-label="Multivalued">{mv}</td>
                                        <td data-label="Admin can edit">{admin_edit}</td>
                                        <td data-label="User can edit">{user_edit}</td>
                                    </tr>
                                }
                            }).collect_view()}
                        </ListTable>
                    }.into_any()
                }}
            </section>

            <section class="gn-section">
                <h2>"Groups"</h2>
                {if profile.groups.is_empty() {
                    view! { <p class="gn-text-muted">"No attribute groups."</p> }.into_any()
                } else {
                    view! {
                        <ListTable headers=vec!["Name", "Display name", "Description"]>
                            {profile.groups.iter().map(|g| view! {
                                <tr>
                                    <td data-label="Name"><code>{g.name.clone()}</code></td>
                                    <td data-label="Display name">{g.display_name.clone()}</td>
                                    <td data-label="Description">{g.description.clone().unwrap_or_else(|| "—".into())}</td>
                                </tr>
                            }).collect_view()}
                        </ListTable>
                    }.into_any()
                }}
            </section>

            <section class="gn-section">
                <div class="gn-card">
                    <div class="gn-card__title">"Unmanaged attribute policy"</div>
                    <p class="gn-card__subtitle">
                        "Controls how attributes outside this schema are handled."
                    </p>
                    <Badge label=policy.into() kind=BadgeKind::Accent/>
                </div>
            </section>
        </Page>
    }
}
