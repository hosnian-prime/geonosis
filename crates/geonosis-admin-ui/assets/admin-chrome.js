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

// ---- Toast notification system -----------------------------------
//
// Global, available on every admin page via `window.GnToast`.
//
// API:
//   GnToast.success(title, message?)
//   GnToast.warning(title, message?)
//   GnToast.error(title, message?)
//   GnToast.info(title, message?)
//   GnToast.show({ kind, title, message?, duration? })
//
// Toasts stack bottom-right, newest at bottom. Auto-dismiss after
// `duration` ms (default 4s for success/info, 8s for warning/error).
// Warning and error toasts show a "Copy" button. All show a close "×".

(function () {
    "use strict";

    var DEFAULTS = {
        success: { duration: 4000, icon: "\u2713" },
        info:    { duration: 4000, icon: "\u2139" },
        warning: { duration: 8000, icon: "\u26A0" },
        error:   { duration: 8000, icon: "\u2717" },
    };

    var container = null;

    function ensureContainer() {
        if (container && document.body.contains(container)) return;
        container = document.createElement("div");
        container.className = "gn-toast-container";
        container.setAttribute("aria-live", "polite");
        container.setAttribute("aria-label", "Notifications");
        document.body.appendChild(container);
    }

    function esc(s) {
        var d = document.createElement("div");
        d.appendChild(document.createTextNode(s || ""));
        return d.innerHTML;
    }

    function show(opts) {
        var kind = opts.kind || "info";
        var title = opts.title || "";
        var message = opts.message || "";
        var cfg = DEFAULTS[kind] || DEFAULTS.info;
        var duration = opts.duration != null ? opts.duration : cfg.duration;

        ensureContainer();

        var el = document.createElement("div");
        el.className = "gn-toast gn-toast--" + kind;
        el.setAttribute("role", "status");

        var hasCopy = kind === "warning" || kind === "error";
        var copyText = (title + (message ? "\n" + message : "")).trim();

        el.innerHTML =
            '<span class="gn-toast__icon" aria-hidden="true">' + esc(cfg.icon) + "</span>" +
            '<div class="gn-toast__body">' +
                (title ? '<div class="gn-toast__title">' + esc(title) + "</div>" : "") +
                (message ? '<div class="gn-toast__msg">' + esc(message) + "</div>" : "") +
            "</div>" +
            '<div class="gn-toast__actions">' +
                (hasCopy ? '<button class="gn-toast__btn gn-toast__btn--copy" data-gn-toast-copy>Copy</button>' : "") +
                '<button class="gn-toast__btn gn-toast__btn--close" data-gn-toast-close aria-label="Dismiss">\u00D7</button>' +
            "</div>";

        // Close button
        el.querySelector("[data-gn-toast-close]").addEventListener("click", function () {
            dismiss(el);
        });

        // Copy button
        var copyBtn = el.querySelector("[data-gn-toast-copy]");
        if (copyBtn) {
            copyBtn.addEventListener("click", function () {
                if (navigator.clipboard) {
                    navigator.clipboard.writeText(copyText).then(function () {
                        copyBtn.textContent = "Copied!";
                        setTimeout(function () { copyBtn.textContent = "Copy"; }, 1500);
                    });
                }
            });
        }

        container.appendChild(el);

        // Auto-dismiss
        if (duration > 0) {
            var timer = setTimeout(function () { dismiss(el); }, duration);
            el._gnTimer = timer;
            // Pause on hover
            el.addEventListener("mouseenter", function () { clearTimeout(el._gnTimer); });
            el.addEventListener("mouseleave", function () {
                el._gnTimer = setTimeout(function () { dismiss(el); }, duration);
            });
        }
    }

    function dismiss(el) {
        if (el._gnDismissed) return;
        el._gnDismissed = true;
        clearTimeout(el._gnTimer);
        el.classList.add("gn-toast--leaving");
        el.addEventListener("animationend", function () {
            if (el.parentNode) el.parentNode.removeChild(el);
        });
    }

    // Public API
    window.GnToast = {
        show: show,
        success: function (title, message) { show({ kind: "success", title: title, message: message }); },
        warning: function (title, message) { show({ kind: "warning", title: title, message: message }); },
        error:   function (title, message) { show({ kind: "error",   title: title, message: message }); },
        info:    function (title, message) { show({ kind: "info",    title: title, message: message }); },
    };
})();
