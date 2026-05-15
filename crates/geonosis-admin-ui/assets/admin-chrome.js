// Admin chrome — theme toggle, mobile drawer, realm selector.
//
// Per `docs/08-admin-ui.md` §1.4 the admin console toggles between
// light and dark via `data-theme` on `<html>`. The selection is
// persisted to `localStorage` so the choice survives navigation and
// reload, and `prefers-color-scheme` provides the first-visit
// default. This script is the only client-side JS the admin shell
// needs; the flow editor ships its own hydrator.
//
// Loaded synchronously in `<head>` (no `defer`) so the `data-theme`
// attribute is set before the body renders — avoids the
// dark→light "flash of unstyled theme" + complies with the
// `script-src 'self'` CSP (no inline scripts).
//
// No dependencies. Targets evergreen browsers.

// ---- Theme bootstrap (runs synchronously at parse time) -----------
(function () {
    "use strict";
    try {
        var stored = localStorage.getItem("gn-theme");
        var theme;
        if (stored === "light" || stored === "dark") {
            theme = stored;
        } else if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) {
            theme = "light";
        } else {
            theme = "dark";
        }
        document.documentElement.setAttribute("data-theme", theme);
    } catch (_) {
        document.documentElement.setAttribute("data-theme", "dark");
    }
})();

// ---- Interaction wiring (waits for DOMContentLoaded) --------------
(function () {
    "use strict";

    function init() {
        var STORAGE_KEY = "gn-theme";
        var root = document.documentElement;

        function applyTheme(theme) {
            if (theme === "light") {
                root.setAttribute("data-theme", "light");
            } else {
                root.setAttribute("data-theme", "dark");
            }
        }

        // Theme toggle button — flips data-theme + persists.
        var toggle = document.querySelector("[data-gn-theme-toggle]");
        if (toggle) {
            toggle.addEventListener("click", function () {
                var current = root.getAttribute("data-theme") === "light" ? "light" : "dark";
                var next = current === "light" ? "dark" : "light";
                applyTheme(next);
                try {
                    localStorage.setItem(STORAGE_KEY, next);
                } catch (_) {
                    // Storage unavailable (private mode); swallow.
                }
            });
        }

        // Mobile sidebar drawer.
        var sidebar = document.querySelector("[data-gn-sidebar]");
        var backdrop = document.querySelector("[data-gn-sidebar-backdrop]");
        var menuBtn = document.querySelector("[data-gn-menu-toggle]");

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
                var open = sidebar && sidebar.classList.contains("is-open");
                if (open) closeDrawer(); else openDrawer();
            });
        }
        if (backdrop) {
            backdrop.addEventListener("click", closeDrawer);
        }
        document.addEventListener("keydown", function (e) {
            if (e.key === "Escape") closeDrawer();
        });

        // Realm selector — navigate on change.
        var selector = document.querySelector("[data-gn-realm-selector]");
        if (selector) {
            selector.addEventListener("change", function () {
                var slug = selector.value;
                if (!slug) return;
                var target = slug === "__root"
                    ? "/admin/realms"
                    : "/admin/realms/" + encodeURIComponent(slug);
                window.location.href = target;
            });
        }

        // Confirm-before-destructive helper for links + forms.
        document.querySelectorAll("[data-gn-confirm]").forEach(function (el) {
            el.addEventListener("click", function (event) {
                var msg = el.getAttribute("data-gn-confirm") || "Are you sure?";
                if (!window.confirm(msg)) {
                    event.preventDefault();
                    event.stopPropagation();
                }
            });
            if (el.tagName === "FORM") {
                el.addEventListener("submit", function (event) {
                    var msg = el.getAttribute("data-gn-confirm") || "Are you sure?";
                    if (!window.confirm(msg)) {
                        event.preventDefault();
                    }
                });
            }
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
