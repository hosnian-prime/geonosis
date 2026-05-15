// Geonosis flow editor — orchestrator.
//
// This is the entry point for the flow editor. It initializes shared
// state and delegates to modular JS files loaded before it:
//
//   elk.min.js       — ELK graph layout engine (vendored)
//   flow-viewport.js — zoom / pan / minimap
//   flow-layout.js   — ELK layout integration
//   flow-crud.js     — node / edge CRUD + selection
//   flow-panels.js   — configuration side panel
//   flow-dryrun.js   — dry-run integration
//
// All modules register on `window.GnFlow`. This file coordinates
// initialization and owns the drag + save + view-toggle logic that
// was previously the entire flow-editor.js.

(function () {
    "use strict";

    var GnFlow = window.GnFlow || {};
    window.GnFlow = GnFlow;

    var root = document.getElementById("gn-flow-canvas");
    if (!root) return;

    var initialScript = root.querySelector('script[data-flow-initial="true"]');
    if (!initialScript) return;

    var flow = safeParseJson(initialScript.textContent);
    if (!flow || !Array.isArray(flow.nodes)) {
        status(root, "Embedded flow JSON is malformed; switch to JSON view.", true);
        return;
    }

    // ---- Shared state -------------------------------------------------

    var state = {
        root: root,
        flow: flow,
        svg: root.querySelector("svg.gn-flow-canvas__svg"),
        view: "canvas",
        dragging: null,
        saveAction: root.dataset.saveAction || "",
        dryrunAction: root.dataset.dryrunAction || "",
        viewW: parseFloat(root.dataset.viewW) || 1920,
        viewH: parseFloat(root.dataset.viewH) || 1080,
        boxW: parseFloat(root.dataset.boxW) || 180,
        boxH: parseFloat(root.dataset.boxH) || 64,
        portR: parseFloat(root.dataset.portR) || 6,
        // Selection state
        selected: null,
        // Viewport (managed by flow-viewport.js)
        viewport: { tx: 0, ty: 0, scale: 1 },
        // Dry-run (managed by flow-dryrun.js)
        dryRunActive: false,
        dryRunOverlay: null,
        pinnedOutcomes: {},
        // DOM indexes
        nodeGroups: new Map(),
        edgeGroups: new Map(),
    };
    if (!state.svg) return;

    // Index server-rendered node groups by node ID.
    state.svg.querySelectorAll('[data-flow-node="true"]').forEach(function (g) {
        var id = g.dataset.nodeId;
        if (id) state.nodeGroups.set(id, g);
    });

    // Index edge groups by "from->to" key.
    state.svg.querySelectorAll('[data-flow-edge="true"]').forEach(function (g) {
        var key = edgeKey(g.dataset.from, g.dataset.to);
        if (!state.edgeGroups.has(key)) state.edgeGroups.set(key, []);
        state.edgeGroups.get(key).push(g);
    });

    // ---- Initialize modules -------------------------------------------

    if (GnFlow.initViewport) GnFlow.initViewport(state);
    if (GnFlow.initCrud) GnFlow.initCrud(state);
    if (GnFlow.initPanels) GnFlow.initPanels(state);
    if (GnFlow.initDryRun) GnFlow.initDryRun(state);

    // Run initial auto-layout if nodes have no persisted positions.
    var hasLayout = state.flow.nodes.some(function (n) { return n.layout; });
    if (!hasLayout && GnFlow.autoLayout) {
        GnFlow.autoLayout(state);
    }

    attachDragHandlers(state);
    attachToolbar(state);
    attachJsonSync(state);

    status(state.root, "");

    // ---- Node drag ----------------------------------------------------

    function attachDragHandlers(st) {
        var handleDown = function (ev) {
            // Don't drag if clicking a port (edge creation handles that).
            if (ev.target.closest("[data-port]")) return;
            var target = ev.target.closest('[data-flow-node="true"]');
            if (!target) return;
            var id = target.dataset.nodeId;
            var node = st.flow.nodes.find(function (n) { return n.id === id; });
            if (!node) return;
            ev.preventDefault();
            var start = svgPoint(st.svg, ev);
            var layout = node.layout || readTransform(target);
            st.dragging = {
                id: id,
                target: target,
                offsetX: start.x - layout.x,
                offsetY: start.y - layout.y,
            };
            target.classList.add("gn-flow-node--dragging");
            window.addEventListener("pointermove", handleMove);
            window.addEventListener("pointerup", handleUp, { once: true });
        };

        var handleMove = function (ev) {
            var d = st.dragging;
            if (!d) return;
            ev.preventDefault();
            var p = svgPoint(st.svg, ev);
            var x = clamp(p.x - d.offsetX, 0, st.viewW - st.boxW);
            var y = clamp(p.y - d.offsetY, 0, st.viewH - st.boxH);
            d.target.setAttribute("transform", "translate(" + x + ", " + y + ")");
            var node = st.flow.nodes.find(function (n) { return n.id === d.id; });
            if (node) node.layout = { x: x, y: y };
            reroute(st, d.id);
        };

        var handleUp = function () {
            var d = st.dragging;
            if (!d) return;
            d.target.classList.remove("gn-flow-node--dragging");
            st.dragging = null;
            window.removeEventListener("pointermove", handleMove);
            mirrorToTextarea(st);
            if (GnFlow.updateMinimap) GnFlow.updateMinimap(st);
        };

        st.svg.addEventListener("pointerdown", handleDown);
    }

    // ---- Toolbar ------------------------------------------------------

    function attachToolbar(st) {
        // Canvas / JSON view toggle
        st.root.querySelectorAll("[data-flow-view]").forEach(function (btn) {
            btn.addEventListener("click", function () {
                var view = btn.dataset.flowView;
                if (view === st.view) return;
                st.view = view;
                st.root.querySelectorAll("[data-flow-view]").forEach(function (b) {
                    b.setAttribute("aria-pressed", b.dataset.flowView === view ? "true" : "false");
                });
                var viewport = st.root.querySelector(".gn-flow-canvas__viewport");
                var form = document.getElementById("gn-flow-json-form");
                if (view === "canvas") {
                    if (viewport) viewport.style.display = "";
                    if (form) form.classList.remove("gn-flow-json--active");
                } else {
                    if (viewport) viewport.style.display = "none";
                    if (form) form.classList.add("gn-flow-json--active");
                }
            });
        });

        // Save button
        var saveBtn = st.root.querySelector('[data-flow-action="save"]');
        if (saveBtn) {
            saveBtn.addEventListener("click", function () { save(st, saveBtn); });
        }

        // Auto Layout button
        var layoutBtn = st.root.querySelector('[data-flow-action="auto-layout"]');
        if (layoutBtn) {
            layoutBtn.addEventListener("click", function () {
                if (GnFlow.autoLayout) GnFlow.autoLayout(st);
            });
        }

        // Zoom buttons
        var zoomIn = st.root.querySelector('[data-flow-action="zoom-in"]');
        var zoomOut = st.root.querySelector('[data-flow-action="zoom-out"]');
        var zoomFit = st.root.querySelector('[data-flow-action="zoom-fit"]');
        if (zoomIn && GnFlow.zoomIn) zoomIn.addEventListener("click", function () { GnFlow.zoomIn(st); });
        if (zoomOut && GnFlow.zoomOut) zoomOut.addEventListener("click", function () { GnFlow.zoomOut(st); });
        if (zoomFit && GnFlow.fitToView) zoomFit.addEventListener("click", function () { GnFlow.fitToView(st); });

        // Dry-run toggle
        var dryRunBtn = st.root.querySelector('[data-flow-action="dry-run"]');
        if (dryRunBtn && GnFlow.toggleDryRun) {
            dryRunBtn.addEventListener("click", function () {
                GnFlow.toggleDryRun(st);
                dryRunBtn.setAttribute("aria-pressed", st.dryRunActive ? "true" : "false");
            });
        }

        // Add Node dropdown
        var addNodeBtn = st.root.querySelector('[data-flow-action="add-node"]');
        var nodeMenu = st.root.querySelector("[data-flow-node-menu]");
        if (addNodeBtn && nodeMenu) {
            addNodeBtn.addEventListener("click", function (ev) {
                ev.stopPropagation();
                nodeMenu.hidden = !nodeMenu.hidden;
            });
            nodeMenu.querySelectorAll("[data-node-kind]").forEach(function (item) {
                item.addEventListener("click", function () {
                    nodeMenu.hidden = true;
                    if (GnFlow.addNode) GnFlow.addNode(st, item.dataset.nodeKind);
                });
            });
            // Close menu on outside click
            document.addEventListener("click", function () { nodeMenu.hidden = true; });
        }
    }

    // ---- JSON sync ----------------------------------------------------

    function attachJsonSync(st) {
        mirrorToTextarea(st);
        var textarea = document.getElementById("gn-flow-json-textarea");
        if (!textarea) return;
        textarea.addEventListener("input", function () {
            var parsed = safeParseJson(textarea.value);
            if (!parsed) return;
            st.flow = parsed;
            // Re-stamp node positions from the new JSON.
            st.flow.nodes.forEach(function (n) {
                var g = st.nodeGroups.get(n.id);
                if (!g) return;
                var l = n.layout || readTransform(g);
                g.setAttribute("transform", "translate(" + l.x + ", " + l.y + ")");
            });
            // Re-route all edges.
            if (GnFlow.rerouteAllEdges) {
                GnFlow.rerouteAllEdges(st);
            } else {
                st.edgeGroups.forEach(function (_groups, key) {
                    var parts = key.split("->");
                    rerouteEdge(st, parts[0], parts[1]);
                });
            }
        });
    }

    // ---- Edge re-routing (fallback Bezier) ----------------------------

    function reroute(st, nodeId) {
        if (GnFlow.rerouteAllEdges) {
            // Let layout module handle it if available.
            st.edgeGroups.forEach(function (_groups, key) {
                var parts = key.split("->");
                if (parts[0] === nodeId || parts[1] === nodeId) {
                    GnFlow.rerouteEdge(st, parts[0], parts[1]);
                }
            });
        } else {
            st.edgeGroups.forEach(function (_groups, key) {
                var parts = key.split("->");
                if (parts[0] === nodeId || parts[1] === nodeId) {
                    rerouteEdge(st, parts[0], parts[1]);
                }
            });
        }
    }

    function rerouteEdge(st, fromId, toId) {
        var groups = st.edgeGroups.get(edgeKey(fromId, toId));
        if (!groups || !groups.length) return;
        var fromGroup = st.nodeGroups.get(fromId);
        var toGroup = st.nodeGroups.get(toId);
        if (!fromGroup || !toGroup) return;
        var fl = readTransform(fromGroup);
        var tl = readTransform(toGroup);
        var fx = fl.x + st.boxW / 2;
        var fy = fl.y + st.boxH;
        var tx = tl.x + st.boxW / 2;
        var ty = tl.y;
        var my = (fy + ty) / 2;
        var d = "M " + fx.toFixed(1) + " " + fy.toFixed(1) +
                " C " + fx.toFixed(1) + " " + my.toFixed(1) +
                ", " + tx.toFixed(1) + " " + my.toFixed(1) +
                ", " + tx.toFixed(1) + " " + ty.toFixed(1);
        var midx = ((fx + tx) / 2).toFixed(1);
        var labelY = (my - 14).toFixed(1);
        groups.forEach(function (g) {
            var path = g.querySelector(".gn-flow-edge__path");
            if (path) path.setAttribute("d", d);
            var hit = g.querySelector(".gn-flow-edge__hit");
            if (hit) hit.setAttribute("d", d);
            var label = g.querySelector(".gn-flow-edge__label");
            if (label) {
                label.setAttribute("x", midx);
                label.setAttribute("y", labelY);
            }
        });
    }

    // ---- Save ---------------------------------------------------------

    function save(st, button) {
        if (!st.saveAction) {
            status(st.root, "No save endpoint configured.", true);
            return;
        }
        var payload;
        try {
            payload = JSON.stringify(st.flow);
        } catch (e) {
            status(st.root, "Cannot serialize graph: " + e.message, true);
            return;
        }
        var body = new URLSearchParams();
        body.set("definition", payload);
        button.disabled = true;
        status(st.root, "Saving\u2026");
        fetch(st.saveAction, {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: body.toString(),
        })
            .then(function (r) {
                if (r.ok || r.redirected) {
                    status(st.root, "Saved.");
                    mirrorToTextarea(st);
                } else {
                    status(st.root, "Save failed: HTTP " + r.status, true);
                }
            })
            .catch(function (e) { status(st.root, "Save failed: " + e.message, true); })
            .finally(function () { button.disabled = false; });
    }

    // ---- Helpers -------------------------------------------------------

    function status(rt, msg, isError) {
        var el = rt.querySelector("[data-flow-status]");
        if (!el) return;
        el.textContent = msg || "";
        el.classList.toggle("gn-flow-toolbar__status--error", !!isError);
    }

    function svgPoint(svg, ev) {
        var pt = svg.createSVGPoint();
        pt.x = ev.clientX;
        pt.y = ev.clientY;
        var ctm = svg.getScreenCTM();
        if (!ctm) return { x: ev.clientX, y: ev.clientY };
        return pt.matrixTransform(ctm.inverse());
    }

    function readTransform(g) {
        var t = g.getAttribute("transform") || "";
        var m = /translate\(\s*(-?[\d.]+)\s*,\s*(-?[\d.]+)\s*\)/.exec(t);
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
        try { return JSON.parse(s); } catch (e) { return null; }
    }

    // Shared mirror function — also used by crud/panels modules.
    function mirrorToTextarea(st) {
        var ta = document.getElementById("gn-flow-json-textarea");
        if (!ta) return;
        try { ta.value = JSON.stringify(st.flow, null, 2); } catch (e) { /* leave as-is */ }
    }

    // Export shared helpers for other modules.
    GnFlow.mirrorToTextarea = mirrorToTextarea;
    GnFlow.svgPoint = svgPoint;
    GnFlow.readTransform = readTransform;
    GnFlow.clamp = clamp;
    GnFlow.edgeKey = edgeKey;
    GnFlow.status = function (msg, isError) { status(state.root, msg, isError); };
    GnFlow._state = state;
})();
