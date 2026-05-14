//! `/admin/realms/{slug}/spi` — WASM modules + bindings.

use leptos::prelude::*;

use crate::leptos_ui::app::{Page, PageContext};
use crate::leptos_ui::components::breadcrumb::Crumb;
use crate::leptos_ui::components::list_table::ListTable;
use crate::leptos_ui::components::page_header::PageHeader;
use crate::leptos_ui::components::widgets::{Badge, BadgeKind, EmptyState, StateBadge};

#[derive(Clone, Debug)]
pub struct ModuleRow {
    pub alias: String,
    pub interface: String,
    pub size_bytes: i64,
    pub created_at: String,
}

#[derive(Clone, Debug)]
pub struct BindingRow {
    pub interface: String,
    pub provider_urn: String,
    pub origin: String,
    pub priority: i32,
    pub enabled: bool,
}

#[component]
pub fn SpiPage(
    realm_slug: String,
    modules: Vec<ModuleRow>,
    bindings: Vec<BindingRow>,
    ctx: PageContext,
) -> impl IntoView {
    let ctx = ctx
        .with_title("SPI plugins")
        .with_section("spi")
        .with_realm(realm_slug.clone())
        .with_crumbs(vec![
            Crumb::link("Realms", "/admin/realms"),
            Crumb::link(realm_slug.clone(), format!("/admin/realms/{realm_slug}")),
            Crumb::current("SPI plugins"),
        ]);
    let modules_view = if modules.is_empty() {
        view! {
            <EmptyState title="No WASM modules uploaded".into()
                description="Upload a .wasm artifact via the admin API to extend the realm.".into()/>
        }.into_any()
    } else {
        view! {
            <ListTable headers=vec!["Alias", "Interface", "Size", "Created"]>
                {modules.into_iter().map(|m| view! {
                    <tr>
                        <td data-label="Alias"><code>{m.alias}</code></td>
                        <td data-label="Interface"><code>{m.interface}</code></td>
                        <td data-label="Size">{format!("{:.1} KB", (m.size_bytes as f64) / 1024.0)}</td>
                        <td data-label="Created" class="gn-text-subtle">{m.created_at}</td>
                    </tr>
                }).collect_view()}
            </ListTable>
        }.into_any()
    };
    let bindings_view = if bindings.is_empty() {
        view! {
            <EmptyState title="No bindings configured".into()
                description="Bind a provider URN to an interface to make Geonosis pick it up.".into()/>
        }.into_any()
    } else {
        view! {
            <ListTable headers=vec!["Interface", "Provider URN", "Origin", "Priority", "State"]>
                {bindings.into_iter().map(|b| {
                    let origin_kind = match b.origin.as_str() {
                        "wasm" | "WASM" => BadgeKind::Accent,
                        _ => BadgeKind::Info,
                    };
                    view! {
                        <tr>
                            <td data-label="Interface"><code>{b.interface}</code></td>
                            <td data-label="Provider URN"><code class="gn-truncate">{b.provider_urn}</code></td>
                            <td data-label="Origin"><Badge label=b.origin kind=origin_kind/></td>
                            <td data-label="Priority">{b.priority.to_string()}</td>
                            <td data-label="State"><StateBadge enabled=b.enabled/></td>
                        </tr>
                    }
                }).collect_view()}
            </ListTable>
        }.into_any()
    };
    view! {
        <Page context=ctx>
            <PageHeader
                title="SPI plugins".into()
                subtitle=Some("Built-in and WASM service-provider implementations bound into this realm.".into())
            />
            <section class="gn-section">
                <h2>"WASM modules"</h2>
                {modules_view}
            </section>
            <section class="gn-section">
                <h2>"Active bindings"</h2>
                {bindings_view}
            </section>
        </Page>
    }
}
