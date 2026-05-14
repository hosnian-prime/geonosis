//! Design tokens served from `/static/tokens.css`.
//!
//! Themes override these by shipping their own stylesheet with `:root`
//! selectors of higher specificity.

pub const TOKENS_CSS: &str = r#":root {
    --gn-color-bg: #0f1115;
    --gn-color-bg-alt: #161a22;
    --gn-color-bg-hover: #1c2028;
    --gn-color-text: #f5f5f7;
    --gn-color-text-muted: #9ba3af;
    --gn-color-accent: #4f8cff;
    --gn-color-accent-hover: #6ba0ff;
    --gn-color-danger: #d04848;
    --gn-color-danger-hover: #e05858;
    --gn-color-success: #2fa67a;
    --gn-color-warning: #e5a12f;
    --gn-color-border: #2a2f3b;
    --gn-color-border-hover: #3a4050;
    --gn-radius-sm: 6px;
    --gn-radius-md: 10px;
    --gn-radius-lg: 14px;
    --gn-radius-full: 9999px;
    --gn-space-1: 4px;
    --gn-space-2: 8px;
    --gn-space-3: 12px;
    --gn-space-4: 16px;
    --gn-space-6: 24px;
    --gn-space-8: 32px;
    --gn-space-12: 48px;
    --gn-shadow-sm: 0 1px 3px rgba(0,0,0,.3), 0 1px 2px rgba(0,0,0,.2);
    --gn-shadow-md: 0 4px 14px rgba(0,0,0,.35), 0 2px 4px rgba(0,0,0,.2);
    --gn-shadow-lg: 0 10px 30px rgba(0,0,0,.4);
    --gn-transition-fast: 150ms ease;
    --gn-transition-base: 200ms ease;
    --gn-font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, sans-serif;
    --gn-font-mono: "JetBrains Mono", ui-monospace, SFMono-Regular, monospace;
    --gn-font-size-xs: 11px;
    --gn-font-size-sm: 13px;
    --gn-font-size-md: 14px;
    --gn-font-size-lg: 16px;
    --gn-font-size-xl: 22px;
    --gn-font-size-2xl: 28px;
    --gn-font-weight-normal: 400;
    --gn-font-weight-medium: 500;
    --gn-font-weight-semibold: 600;
    --gn-font-weight-bold: 700;
}

*, *::before, *::after { box-sizing: border-box; }

html { color-scheme: dark; }

body {
    font-family: var(--gn-font-family);
    font-size: var(--gn-font-size-md);
    font-weight: var(--gn-font-weight-normal);
    line-height: 1.6;
    background: var(--gn-color-bg);
    color: var(--gn-color-text);
    margin: 0;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}

a {
    color: var(--gn-color-accent);
    text-decoration: none;
    transition: color var(--gn-transition-fast);
}
a:hover { color: var(--gn-color-accent-hover); text-decoration: underline; }

code {
    font-family: var(--gn-font-mono);
    font-size: 0.9em;
    background: rgba(255,255,255,.06);
    padding: 2px 6px;
    border-radius: var(--gn-radius-sm);
}

/* ---- Page layout ---- */

.gn-page {
    display: grid;
    grid-template-columns: 240px 1fr;
    min-block-size: 100vh;
}

/* ---- Sidebar nav ---- */

.gn-nav {
    background: var(--gn-color-bg-alt);
    border-inline-end: 1px solid var(--gn-color-border);
    padding-block: var(--gn-space-6);
    padding-inline: var(--gn-space-3);
    position: sticky;
    inset-block-start: 0;
    block-size: 100vh;
    overflow-y: auto;
}

.gn-nav-brand {
    font-weight: var(--gn-font-weight-bold);
    font-size: var(--gn-font-size-lg);
    padding-block-end: var(--gn-space-6);
    padding-inline: var(--gn-space-2);
    margin-block-end: var(--gn-space-3);
    border-block-end: 1px solid var(--gn-color-border);
    letter-spacing: -0.02em;
    color: var(--gn-color-text);
}

.gn-nav a, .gn-nav .gn-nav__item {
    display: block;
    padding-block: 7px;
    padding-inline: var(--gn-space-3);
    border-radius: var(--gn-radius-sm);
    color: var(--gn-color-text-muted);
    font-size: var(--gn-font-size-sm);
    font-weight: var(--gn-font-weight-medium);
    transition: background var(--gn-transition-fast), color var(--gn-transition-fast);
    margin-block-end: 2px;
}
.gn-nav a:hover, .gn-nav .gn-nav__item:hover {
    background: var(--gn-color-bg-hover);
    color: var(--gn-color-text);
    text-decoration: none;
}
.gn-nav a[aria-current="page"], .gn-nav .gn-nav__item.is-active {
    background: rgba(79,140,255,.15);
    color: var(--gn-color-accent);
    font-weight: var(--gn-font-weight-semibold);
}

/* ---- Main content ---- */

.gn-main {
    padding-block: var(--gn-space-8);
    padding-inline: var(--gn-space-8);
    max-inline-size: 1200px;
}

.gn-main h1 {
    font-size: var(--gn-font-size-2xl);
    font-weight: var(--gn-font-weight-bold);
    letter-spacing: -0.025em;
    margin-block: 0 var(--gn-space-6);
    line-height: 1.2;
}
.gn-main h2 {
    font-size: var(--gn-font-size-lg);
    font-weight: var(--gn-font-weight-semibold);
    letter-spacing: -0.01em;
    margin-block: 0 var(--gn-space-3);
}

/* ---- Cards ---- */

.gn-card {
    background: var(--gn-color-bg-alt);
    border: 1px solid var(--gn-color-border);
    border-radius: var(--gn-radius-md);
    padding: var(--gn-space-6);
    margin-block-end: var(--gn-space-4);
    box-shadow: var(--gn-shadow-sm);
    transition: border-color var(--gn-transition-fast), box-shadow var(--gn-transition-fast);
}
.gn-card:hover {
    border-color: var(--gn-color-border-hover);
    box-shadow: var(--gn-shadow-md);
}

/* ---- Buttons ---- */

.gn-button {
    appearance: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: var(--gn-space-2);
    border: 1px solid var(--gn-color-border);
    background: var(--gn-color-bg-alt);
    color: var(--gn-color-text);
    padding-block: var(--gn-space-2);
    padding-inline: var(--gn-space-4);
    border-radius: var(--gn-radius-sm);
    cursor: pointer;
    font: inherit;
    font-size: var(--gn-font-size-sm);
    font-weight: var(--gn-font-weight-medium);
    line-height: 1.4;
    transition: background var(--gn-transition-fast), border-color var(--gn-transition-fast), box-shadow var(--gn-transition-fast), color var(--gn-transition-fast);
}
.gn-button:hover {
    background: var(--gn-color-bg-hover);
    border-color: var(--gn-color-border-hover);
}
.gn-button--primary {
    background: var(--gn-color-accent);
    border-color: var(--gn-color-accent);
    color: white;
}
.gn-button--primary:hover {
    background: var(--gn-color-accent-hover);
    border-color: var(--gn-color-accent-hover);
}
.gn-button--danger {
    background: var(--gn-color-danger);
    border-color: var(--gn-color-danger);
    color: white;
}
.gn-button--danger:hover {
    background: var(--gn-color-danger-hover);
    border-color: var(--gn-color-danger-hover);
}
.gn-button:focus-visible {
    outline: 2px solid var(--gn-color-accent);
    outline-offset: 2px;
}
.gn-button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
}

/* ---- Forms ---- */

.gn-field { display: block; margin-block-end: var(--gn-space-4); }
.gn-field-label {
    display: block;
    margin-block-end: var(--gn-space-1);
    color: var(--gn-color-text-muted);
    font-size: var(--gn-font-size-sm);
    font-weight: var(--gn-font-weight-medium);
}
.gn-input {
    inline-size: 100%;
    padding-block: 10px;
    padding-inline: var(--gn-space-3);
    background: var(--gn-color-bg);
    border: 1px solid var(--gn-color-border);
    border-radius: var(--gn-radius-sm);
    color: var(--gn-color-text);
    font: inherit;
    font-size: var(--gn-font-size-md);
    transition: border-color var(--gn-transition-fast), box-shadow var(--gn-transition-fast);
}
.gn-input::placeholder {
    color: var(--gn-color-text-muted);
    opacity: 0.6;
}
.gn-input:focus {
    outline: none;
    border-color: var(--gn-color-accent);
    box-shadow: 0 0 0 3px rgba(79,140,255,.2);
}

/* ---- Tables ---- */

table.gn-table { inline-size: 100%; border-collapse: collapse; }
.gn-table th, .gn-table td {
    text-align: start;
    padding-block: var(--gn-space-3);
    padding-inline: var(--gn-space-3);
    border-block-end: 1px solid var(--gn-color-border);
}
.gn-table th {
    color: var(--gn-color-text-muted);
    font-weight: var(--gn-font-weight-semibold);
    font-size: var(--gn-font-size-xs);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    padding-block: var(--gn-space-2);
}
.gn-table tbody tr {
    transition: background var(--gn-transition-fast);
}
.gn-table tbody tr:hover {
    background: rgba(255,255,255,.03);
}

/* ---- Badges ---- */

.gn-badge {
    display: inline-flex;
    align-items: center;
    padding-block: 2px;
    padding-inline: var(--gn-space-2);
    border-radius: var(--gn-radius-full);
    font-size: var(--gn-font-size-xs);
    font-weight: var(--gn-font-weight-semibold);
    letter-spacing: 0.02em;
    line-height: 1.6;
}
.gn-badge--success {
    background: rgba(47,166,122,.15);
    color: var(--gn-color-success);
}
.gn-badge--danger {
    background: rgba(208,72,72,.15);
    color: var(--gn-color-danger);
}
.gn-badge--warning {
    background: rgba(229,161,47,.15);
    color: var(--gn-color-warning);
}
.gn-badge--muted {
    background: rgba(155,163,175,.12);
    color: var(--gn-color-text-muted);
}

/* ---- Login page ---- */

.gn-login-page {
    min-block-size: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--gn-color-bg);
    padding: var(--gn-space-4);
}
.gn-login-card {
    background: var(--gn-color-bg-alt);
    border: 1px solid var(--gn-color-border);
    border-radius: var(--gn-radius-lg);
    padding: var(--gn-space-8);
    inline-size: 100%;
    max-inline-size: 400px;
    box-shadow: var(--gn-shadow-lg);
}
.gn-login-card h1 {
    font-size: var(--gn-font-size-xl);
    font-weight: var(--gn-font-weight-bold);
    text-align: center;
    margin-block: 0 var(--gn-space-2);
    letter-spacing: -0.02em;
}
.gn-login-card .gn-login-subtitle {
    text-align: center;
    color: var(--gn-color-text-muted);
    font-size: var(--gn-font-size-sm);
    margin-block-end: var(--gn-space-6);
}
.gn-login-card .gn-button--primary {
    inline-size: 100%;
    padding-block: var(--gn-space-3);
    font-size: var(--gn-font-size-md);
}
.gn-login-error {
    background: rgba(208,72,72,.12);
    border: 1px solid rgba(208,72,72,.3);
    color: var(--gn-color-danger);
    border-radius: var(--gn-radius-sm);
    padding: var(--gn-space-3);
    font-size: var(--gn-font-size-sm);
    margin-block-end: var(--gn-space-4);
}

/* ---- Flow editor canvas (admin A6 — v0.1 MVP) ----
 *
 * Hand-rolled SVG canvas hydrated by /static/flow-editor.js. Kept in
 * the design-token sheet so the canvas inherits theme overrides without
 * needing a second stylesheet round-trip.
 */

.gn-flow-canvas {
    display: flex;
    flex-direction: column;
    gap: var(--gn-space-3);
    background: var(--gn-color-bg-alt);
    border: 1px solid var(--gn-color-border);
    border-radius: var(--gn-radius-md);
    padding: var(--gn-space-3);
    margin-block-end: var(--gn-space-4);
}
.gn-flow-toolbar {
    display: flex;
    align-items: center;
    gap: var(--gn-space-2);
    flex-wrap: wrap;
}
.gn-flow-toolbar__sep {
    flex: 1 1 auto;
}
.gn-flow-toolbar__btn[aria-pressed="true"] {
    background: var(--gn-color-accent);
    border-color: var(--gn-color-accent);
    color: white;
}
.gn-flow-toolbar__status {
    color: var(--gn-color-text-muted);
    font-size: var(--gn-font-size-sm);
    min-block-size: 1.2em;
}
.gn-flow-toolbar__status--error { color: var(--gn-color-danger); }
.gn-flow-canvas__svg {
    inline-size: 100%;
    block-size: auto;
    aspect-ratio: 12 / 7;
    background: var(--gn-color-bg);
    border-radius: var(--gn-radius-sm);
    touch-action: none;
    user-select: none;
}
.gn-flow-node { cursor: grab; }
.gn-flow-node--dragging { cursor: grabbing; }
.gn-flow-node:focus-visible .gn-flow-node__bg {
    stroke: var(--gn-color-accent);
    stroke-width: 2;
}
.gn-flow-canvas__note {
    color: var(--gn-color-text-muted);
    font-size: var(--gn-font-size-sm);
    margin: 0;
}
.gn-flow-canvas__noscript p {
    color: var(--gn-color-danger);
    font-size: var(--gn-font-size-sm);
}
.gn-flow-json { margin-block-start: var(--gn-space-4); }
.gn-flow-json--active { outline: 2px solid var(--gn-color-accent); border-radius: var(--gn-radius-sm); }

/* ---- Responsive ---- */

@media (max-width: 768px) {
    .gn-page {
        grid-template-columns: 1fr;
    }
    .gn-nav {
        position: static;
        block-size: auto;
        border-inline-end: none;
        border-block-end: 1px solid var(--gn-color-border);
        padding-block: var(--gn-space-3);
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: var(--gn-space-1);
    }
    .gn-nav-brand {
        border-block-end: none;
        padding-block-end: 0;
        margin-block-end: 0;
        margin-inline-end: var(--gn-space-4);
    }
    .gn-nav a, .gn-nav .gn-nav__item {
        padding-block: var(--gn-space-1);
        padding-inline: var(--gn-space-2);
        font-size: var(--gn-font-size-xs);
    }
    .gn-main {
        padding: var(--gn-space-4);
    }
    .gn-login-card {
        padding: var(--gn-space-6);
    }
}
"#;
