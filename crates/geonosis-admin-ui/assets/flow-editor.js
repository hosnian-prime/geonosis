// Geonosis flow editor — hand-rolled vanilla-JS hydrator.
//
// Per `docs/08-admin-ui.md` §"Flow editor (special case)" the editor is
// the only admin page that requires extensive client-side state. We
// deliberately do not pull in a graph-editor library: the node set is
// small + tightly typed, the SVG is server-rendered by the Leptos
// `FlowCanvas` component, and this script attaches the interactive
// behaviour (drag-to-reposition + save) on top of that SSR tree.
//
// Two render targets coexist during the v0.1 → v0.1.x migration:
//
//   1. `/admin-next/realms/:slug/flows/:alias` — Leptos page that
//      ships the full SVG inline plus an embedded JSON island via
//      `<script type="application/json" data-flow-initial>`. We
//      attach drag handlers + a save button that POSTs the patched
//      JSON back through the existing form endpoint.
//
//   2. `/admin/realms/:slug/flows` — legacy Maud preview page that
//      fetches the flow from the REST API and draws a read-only
//      grid. Kept for compatibility while operators migrate; the
//      legacy code path activates only when the hydrator finds the
//      Maud-specific `data-realm` + `data-alias` attributes without
//      the Leptos `data-flow-initial` script tag.
//
// No frameworks, no dependencies. Targets evergreen browsers (the
// only baseline operators run an admin UI on).

(function () {
    "use strict";

    const root = document.getElementById("gn-flow-canvas");
    if (!root) return;

    const initialScript = root.querySelector('script[data-flow-initial="true"]');
    if (initialScript) {
        hydrateLeptosCanvas(root, initialScript);
    } else if (root.dataset.realm && root.dataset.alias) {
        hydrateLegacyPreview(root);
    }

    // ----- Leptos canvas: drag + save -------------------------------

    function hydrateLeptosCanvas(root, initialScript) {
        const flow = safeParseJson(initialScript.textContent);
        if (!flow || !Array.isArray(flow.nodes)) {
            status(root, "Embedded flow JSON is malformed; switch to JSON view.", true);
            return;
        }

        const state = {
            root: root,
            flow: flow,
            svg: root.querySelector("svg.gn-flow-canvas__svg"),
            view: "canvas",
            dragging: null,
            saveAction: root.dataset.saveAction || "",
            viewW: parseFloat(root.dataset.viewW) || 960,
            viewH: parseFloat(root.dataset.viewH) || 560,
            boxW: parseFloat(root.dataset.boxW) || 168,
            boxH: parseFloat(root.dataset.boxH) || 56,
        };
        if (!state.svg) return;

        // Index server-rendered node groups by node id so drag handlers
        // can mutate `transform` in-place without re-rendering.
        state.nodeGroups = new Map();
        state.svg.querySelectorAll('[data-flow-node="true"]').forEach((g) => {
            const id = g.dataset.nodeId;
            if (id) state.nodeGroups.set(id, g);
        });
        // Edge paths are keyed by `from->to` so a node drag can re-route
        // every adjacent edge in O(deg(node)).
        state.edgeGroups = new Map();
        state.svg.querySelectorAll('[data-flow-edge="true"]').forEach((g) => {
            const key = edgeKey(g.dataset.from, g.dataset.to);
            if (!state.edgeGroups.has(key)) state.edgeGroups.set(key, []);
            state.edgeGroups.get(key).push(g);
        });

        attachDragHandlers(state);
        attachToolbar(state);
        attachJsonSync(state);

        status(state.root, "");
    }

    function attachDragHandlers(state) {
        const handleDown = (ev) => {
            const target = ev.target.closest('[data-flow-node="true"]');
            if (!target) return;
            const id = target.dataset.nodeId;
            const node = state.flow.nodes.find((n) => n.id === id);
            if (!node) return;
            ev.preventDefault();
            const start = svgPoint(state.svg, ev);
            const layout = node.layout || readTransform(target);
            state.dragging = {
                id: id,
                target: target,
                offsetX: start.x - layout.x,
                offsetY: start.y - layout.y,
            };
            target.classList.add("gn-flow-node--dragging");
            // Capture moves on the window so a fast pointer release
            // outside the SVG still ends the drag cleanly.
            window.addEventListener("pointermove", handleMove);
            window.addEventListener("pointerup", handleUp, { once: true });
        };
        const handleMove = (ev) => {
            const d = state.dragging;
            if (!d) return;
            ev.preventDefault();
            const p = svgPoint(state.svg, ev);
            let x = clamp(p.x - d.offsetX, 0, state.viewW - state.boxW);
            let y = clamp(p.y - d.offsetY, 0, state.viewH - state.boxH);
            d.target.setAttribute("transform", `translate(${x}, ${y})`);
            const node = state.flow.nodes.find((n) => n.id === d.id);
            if (node) node.layout = { x: x, y: y };
            reroute(state, d.id);
        };
        const handleUp = () => {
            const d = state.dragging;
            if (!d) return;
            d.target.classList.remove("gn-flow-node--dragging");
            state.dragging = null;
            window.removeEventListener("pointermove", handleMove);
            mirrorToTextarea(state);
        };
        state.svg.addEventListener("pointerdown", handleDown);
    }

    function attachToolbar(state) {
        state.root.querySelectorAll("[data-flow-view]").forEach((btn) => {
            btn.addEventListener("click", () => {
                const view = btn.dataset.flowView;
                if (view === state.view) return;
                state.view = view;
                state.root.querySelectorAll("[data-flow-view]").forEach((b) => {
                    b.setAttribute(
                        "aria-pressed",
                        b.dataset.flowView === view ? "true" : "false"
                    );
                });
                const form = document.getElementById("gn-flow-json-form");
                if (view === "canvas") {
                    state.svg.style.display = "";
                    if (form) form.classList.remove("gn-flow-json--active");
                } else {
                    state.svg.style.display = "none";
                    if (form) form.classList.add("gn-flow-json--active");
                }
            });
        });
        const saveBtn = state.root.querySelector('[data-flow-action="save"]');
        if (saveBtn) {
            saveBtn.addEventListener("click", () => save(state, saveBtn));
        }
    }

    /// Keep the JSON textarea in sync with canvas edits so a switch to
    /// JSON view always shows the freshest graph + "Save JSON" never
    /// regresses positions an operator just dragged.
    function attachJsonSync(state) {
        mirrorToTextarea(state);
        const textarea = document.getElementById("gn-flow-json-textarea");
        if (!textarea) return;
        textarea.addEventListener("input", () => {
            const parsed = safeParseJson(textarea.value);
            if (!parsed) return;
            state.flow = parsed;
            // Re-stamp node positions from the new JSON.
            state.flow.nodes.forEach((n) => {
                const g = state.nodeGroups.get(n.id);
                if (!g) return;
                const l = n.layout || readTransform(g);
                g.setAttribute("transform", `translate(${l.x}, ${l.y})`);
            });
            // Best-effort edge re-route after a JSON edit.
            state.edgeGroups.forEach((_groups, key) => {
                const [from, to] = key.split("->");
                rerouteEdge(state, from, to);
            });
        });
    }

    function mirrorToTextarea(state) {
        const textarea = document.getElementById("gn-flow-json-textarea");
        if (!textarea) return;
        try {
            textarea.value = JSON.stringify(state.flow, null, 2);
        } catch (e) {
            // Leave the textarea as-is; the operator can save manually.
        }
    }

    function reroute(state, nodeId) {
        state.edgeGroups.forEach((_groups, key) => {
            const [from, to] = key.split("->");
            if (from === nodeId || to === nodeId) {
                rerouteEdge(state, from, to);
            }
        });
    }

    function rerouteEdge(state, fromId, toId) {
        const groups = state.edgeGroups.get(edgeKey(fromId, toId));
        if (!groups || !groups.length) return;
        const from = state.flow.nodes.find((n) => n.id === fromId);
        const to = state.flow.nodes.find((n) => n.id === toId);
        if (!from || !to) return;
        const fromGroup = state.nodeGroups.get(fromId);
        const toGroup = state.nodeGroups.get(toId);
        if (!fromGroup || !toGroup) return;
        const fl = readTransform(fromGroup);
        const tl = readTransform(toGroup);
        const fx = fl.x + state.boxW / 2;
        const fy = fl.y + state.boxH;
        const tx = tl.x + state.boxW / 2;
        const ty = tl.y;
        const my = (fy + ty) / 2;
        const d = `M ${fx.toFixed(1)} ${fy.toFixed(1)} C ${fx.toFixed(1)} ${my.toFixed(1)}, ${tx.toFixed(1)} ${my.toFixed(1)}, ${tx.toFixed(1)} ${ty.toFixed(1)}`;
        const midx = ((fx + tx) / 2).toFixed(1);
        const labelY = (my - 14).toFixed(1);
        groups.forEach((g) => {
            const path = g.querySelector(".gn-flow-edge__path");
            if (path) path.setAttribute("d", d);
            const label = g.querySelector(".gn-flow-edge__label");
            if (label) {
                label.setAttribute("x", midx);
                label.setAttribute("y", labelY);
            }
        });
    }

    function save(state, button) {
        if (!state.saveAction) {
            status(state.root, "No save endpoint configured.", true);
            return;
        }
        let payload;
        try {
            payload = JSON.stringify(state.flow);
        } catch (e) {
            status(state.root, "Cannot serialize graph: " + e.message, true);
            return;
        }
        const body = new URLSearchParams();
        body.set("definition", payload);
        button.disabled = true;
        status(state.root, "Saving...");
        fetch(state.saveAction, {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: body.toString(),
        })
            .then((r) => {
                if (r.ok || r.redirected) {
                    status(state.root, "Saved.");
                    mirrorToTextarea(state);
                } else if (r.status === 200) {
                    // Server re-rendered the page with a validation
                    // error inline; surface a short hint and let the
                    // operator switch to JSON view to read the detail.
                    status(state.root, "Server rejected save (see JSON view).", true);
                } else {
                    status(state.root, "Save failed: HTTP " + r.status, true);
                }
            })
            .catch((e) => status(state.root, "Save failed: " + e.message, true))
            .finally(() => {
                button.disabled = false;
            });
    }

    function status(root, msg, isError) {
        const el = root.querySelector("[data-flow-status]");
        if (!el) return;
        el.textContent = msg || "";
        el.classList.toggle("gn-flow-toolbar__status--error", !!isError);
    }

    // ----- Geometry helpers ----------------------------------------

    function svgPoint(svg, ev) {
        const pt = svg.createSVGPoint();
        pt.x = ev.clientX;
        pt.y = ev.clientY;
        const ctm = svg.getScreenCTM();
        if (!ctm) return { x: ev.clientX, y: ev.clientY };
        const inv = ctm.inverse();
        const local = pt.matrixTransform(inv);
        return { x: local.x, y: local.y };
    }

    function readTransform(g) {
        const t = g.getAttribute("transform") || "";
        const m = /translate\(\s*(-?[\d.]+)\s*,\s*(-?[\d.]+)\s*\)/.exec(t);
        if (m) return { x: parseFloat(m[1]), y: parseFloat(m[2]) };
        return { x: 0, y: 0 };
    }

    function clamp(v, lo, hi) {
        return Math.min(hi, Math.max(lo, v));
    }

    function edgeKey(from, to) {
        return from + "->" + to;
    }

    function safeParseJson(s) {
        try {
            return JSON.parse(s);
        } catch (e) {
            return null;
        }
    }

    // ----- Legacy Maud preview --------------------------------------
    //
    // The pre-Leptos `/admin/realms/:slug/flows` page mounts this same
    // script via `flow_editor_mount()` and expects a read-only canvas
    // backed by `/admin/v1/realms/.../flows/...`. We keep the original
    // behaviour for backward compatibility; the Leptos page above is
    // the primary editor going forward.

    function hydrateLegacyPreview(node) {
        const realm = node.dataset.realm;
        const alias = node.dataset.alias;
        if (!realm || !alias) return;
        fetch(
            `/admin/v1/realms/${encodeURIComponent(realm)}/flows/${encodeURIComponent(alias)}`
        )
            .then((r) => r.json())
            .then((flow) => renderLegacy(node, flow))
            .catch((e) => {
                node.textContent = `Failed to load flow: ${e}`;
            });
    }

    function renderLegacy(node, flow) {
        const ns = "http://www.w3.org/2000/svg";
        const svg = document.createElementNS(ns, "svg");
        svg.setAttribute("viewBox", "0 0 800 500");
        svg.setAttribute("width", "100%");
        svg.setAttribute("height", "500");

        const nodes = flow.nodes || [];
        const edges = flow.edges || [];
        const positions = layoutGrid(nodes);

        for (const e of edges) {
            const from = positions.get(e.from);
            const to = positions.get(e.to);
            if (!from || !to) continue;
            const line = document.createElementNS(ns, "line");
            line.setAttribute("x1", from.x);
            line.setAttribute("y1", from.y);
            line.setAttribute("x2", to.x);
            line.setAttribute("y2", to.y);
            line.setAttribute("stroke", "var(--gn-color-accent, #5b8cff)");
            line.setAttribute("stroke-width", "2");
            svg.appendChild(line);
        }
        for (const n of nodes) {
            const p = positions.get(n.id);
            if (!p) continue;
            const rect = document.createElementNS(ns, "rect");
            rect.setAttribute("x", p.x - 60);
            rect.setAttribute("y", p.y - 22);
            rect.setAttribute("width", 120);
            rect.setAttribute("height", 44);
            rect.setAttribute("rx", 8);
            rect.setAttribute("fill", "var(--gn-color-bg-elev, #161a23)");
            rect.setAttribute("stroke", "var(--gn-color-border, #232735)");
            svg.appendChild(rect);
            const text = document.createElementNS(ns, "text");
            text.setAttribute("x", p.x);
            text.setAttribute("y", p.y + 5);
            text.setAttribute("text-anchor", "middle");
            text.setAttribute("fill", "var(--gn-color-text, #f4f5f8)");
            text.setAttribute("font-size", "12");
            text.textContent = n.display_name || nodeKindLabel(n.kind);
            svg.appendChild(text);
        }
        node.innerHTML = "";
        node.appendChild(svg);
    }

    function layoutGrid(nodes) {
        const positions = new Map();
        const cols = Math.max(1, Math.ceil(Math.sqrt(nodes.length)));
        nodes.forEach((n, i) => {
            const col = i % cols;
            const row = Math.floor(i / cols);
            positions.set(n.id, {
                x: 100 + col * 160,
                y: 60 + row * 90,
            });
        });
        return positions;
    }

    function nodeKindLabel(kind) {
        if (!kind) return "node";
        if (typeof kind === "string") return kind;
        return Object.keys(kind)[0] || "node";
    }
})();
