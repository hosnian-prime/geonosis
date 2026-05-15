// Admin chrome — theme toggle, mobile drawer, realm selector.
//
// Per `docs/08-admin-ui.md` §1.4 the admin console toggles between
// light and dark via `data-theme` on `<html>`. The selection is
// persisted to `localStorage` so the choice survives navigation and
// reload, and `prefers-color-scheme` provides the first-visit
// default. This script is the only client-side JS the admin shell
// needs; the flow editor ships its own hydrator.
//
// No dependencies. Targets evergreen browsers.

(function () {
    "use strict";

    // ---- Theme toggle ----------------------------------------------
    const STORAGE_KEY = "gn-theme";
    const root = document.documentElement;

    function applyTheme(theme) {
        if (theme === "light") {
            root.setAttribute("data-theme", "light");
        } else {
            root.setAttribute("data-theme", "dark");
        }
    }

    // The boot inline script in layout.rs already applied the right
    // theme so we don't get a flash. This block just keeps the
    // attribute and storage in sync when the user clicks the toggle.
    const toggle = document.querySelector("[data-gn-theme-toggle]");
    if (toggle) {
        toggle.addEventListener("click", function () {
            const current = root.getAttribute("data-theme") === "light"
                ? "light"
                : "dark";
            const next = current === "light" ? "dark" : "light";
            applyTheme(next);
            try {
                localStorage.setItem(STORAGE_KEY, next);
            } catch (_) {
                // Storage unavailable (private mode); swallow.
            }
        });
    }

    // ---- Mobile sidebar drawer -------------------------------------
    const sidebar = document.querySelector("[data-gn-sidebar]");
    const backdrop = document.querySelector("[data-gn-sidebar-backdrop]");
    const menuBtn = document.querySelector("[data-gn-menu-toggle]");

    function openDrawer() {
        if (!sidebar) return;
        sidebar.classList.add("is-open");
        if (backdrop) backdrop.classList.add("is-open");
        if (menuBtn) menuBtn.setAttribute("aria-expanded", "true");
    }

    function closeDrawer() {
        if (!sidebar) return;
        sidebar.classList.remove("is-open");
        if (backdrop) backdrop.classList.remove("is-open");
        if (menuBtn) menuBtn.setAttribute("aria-expanded", "false");
    }

    if (menuBtn) {
        menuBtn.addEventListener("click", function () {
            const open = sidebar && sidebar.classList.contains("is-open");
            if (open) closeDrawer(); else openDrawer();
        });
    }
    if (backdrop) {
        backdrop.addEventListener("click", closeDrawer);
    }
    document.addEventListener("keydown", function (e) {
        if (e.key === "Escape") closeDrawer();
    });

    // ---- Realm selector --------------------------------------------
    const selector = document.querySelector("[data-gn-realm-selector]");
    if (selector) {
        selector.addEventListener("change", function () {
            const slug = selector.value;
            if (!slug) return;
            const target = slug === "__root"
                ? "/admin/realms"
                : "/admin/realms/" + encodeURIComponent(slug);
            window.location.href = target;
        });
    }

    // ---- Confirm before destructive actions ------------------------
    document.querySelectorAll("[data-gn-confirm]").forEach(function (el) {
        el.addEventListener("click", function (event) {
            const msg = el.getAttribute("data-gn-confirm") || "Are you sure?";
            if (!window.confirm(msg)) {
                event.preventDefault();
                event.stopPropagation();
            }
        });
        if (el.tagName === "FORM") {
            el.addEventListener("submit", function (event) {
                const msg = el.getAttribute("data-gn-confirm") || "Are you sure?";
                if (!window.confirm(msg)) {
                    event.preventDefault();
                }
            });
        }
    });
})();
