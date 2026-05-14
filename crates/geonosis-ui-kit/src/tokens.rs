//! Design tokens served from `/static/tokens.css`.
//!
//! Themes override these by shipping their own stylesheet with `:root`
//! selectors of higher specificity.

pub const TOKENS_CSS: &str = r#":root {
    --gn-color-bg: #0f1115;
    --gn-color-bg-alt: #161a22;
    --gn-color-text: #f5f5f7;
    --gn-color-text-muted: #9ba3af;
    --gn-color-accent: #4f8cff;
    --gn-color-danger: #d04848;
    --gn-color-success: #2fa67a;
    --gn-color-border: #2a2f3b;
    --gn-radius-sm: 4px;
    --gn-radius-md: 8px;
    --gn-radius-lg: 12px;
    --gn-space-1: 4px;
    --gn-space-2: 8px;
    --gn-space-3: 12px;
    --gn-space-4: 16px;
    --gn-space-6: 24px;
    --gn-space-8: 32px;
    --gn-font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, sans-serif;
    --gn-font-mono: "JetBrains Mono", ui-monospace, SFMono-Regular, monospace;
    --gn-font-size-sm: 13px;
    --gn-font-size-md: 14px;
    --gn-font-size-lg: 16px;
    --gn-font-size-xl: 22px;
}

html { color-scheme: dark; }

body {
    font-family: var(--gn-font-family);
    font-size: var(--gn-font-size-md);
    background: var(--gn-color-bg);
    color: var(--gn-color-text);
    margin: 0;
}

a { color: var(--gn-color-accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.gn-page {
    display: grid;
    grid-template-columns: 220px 1fr;
    min-block-size: 100vh;
}

.gn-nav {
    background: var(--gn-color-bg-alt);
    border-inline-end: 1px solid var(--gn-color-border);
    padding-block: var(--gn-space-4);
    padding-inline: var(--gn-space-3);
}

.gn-nav-brand {
    font-weight: 700;
    font-size: var(--gn-font-size-lg);
    padding-block-end: var(--gn-space-4);
    margin-block-end: var(--gn-space-3);
    border-block-end: 1px solid var(--gn-color-border);
}

.gn-nav a {
    display: block;
    padding-block: var(--gn-space-2);
    padding-inline: var(--gn-space-2);
    border-radius: var(--gn-radius-sm);
    color: var(--gn-color-text-muted);
}
.gn-nav a:hover { background: rgba(255,255,255,.06); color: var(--gn-color-text); text-decoration: none; }
.gn-nav a[aria-current="page"] { background: var(--gn-color-accent); color: white; }

.gn-main {
    padding-block: var(--gn-space-6);
    padding-inline: var(--gn-space-6);
}

.gn-card {
    background: var(--gn-color-bg-alt);
    border: 1px solid var(--gn-color-border);
    border-radius: var(--gn-radius-md);
    padding-block: var(--gn-space-4);
    padding-inline: var(--gn-space-4);
    margin-block-end: var(--gn-space-4);
}

.gn-button {
    appearance: none;
    border: 1px solid var(--gn-color-border);
    background: var(--gn-color-bg-alt);
    color: var(--gn-color-text);
    padding-block: var(--gn-space-2);
    padding-inline: var(--gn-space-4);
    border-radius: var(--gn-radius-sm);
    cursor: pointer;
    font: inherit;
}
.gn-button--primary { background: var(--gn-color-accent); border-color: var(--gn-color-accent); color: white; }
.gn-button--danger { background: var(--gn-color-danger); border-color: var(--gn-color-danger); color: white; }
.gn-button:focus-visible { outline: 2px solid var(--gn-color-accent); outline-offset: 2px; }

.gn-field { display: block; margin-block-end: var(--gn-space-3); }
.gn-field-label { display: block; margin-block-end: var(--gn-space-1); color: var(--gn-color-text-muted); font-size: var(--gn-font-size-sm); }
.gn-input {
    inline-size: 100%;
    padding-block: var(--gn-space-2);
    padding-inline: var(--gn-space-3);
    background: var(--gn-color-bg);
    border: 1px solid var(--gn-color-border);
    border-radius: var(--gn-radius-sm);
    color: var(--gn-color-text);
    font: inherit;
}
.gn-input:focus { outline: 2px solid var(--gn-color-accent); border-color: var(--gn-color-accent); }

table.gn-table { inline-size: 100%; border-collapse: collapse; }
.gn-table th, .gn-table td {
    text-align: start;
    padding-block: var(--gn-space-2);
    padding-inline: var(--gn-space-3);
    border-block-end: 1px solid var(--gn-color-border);
}
.gn-table th { color: var(--gn-color-text-muted); font-weight: 500; font-size: var(--gn-font-size-sm); }

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
"#;
