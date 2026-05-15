// Geonosis flow editor — CRUD operations module.
//
// Registers on `window.GnFlow` namespace. Provides node/edge CRUD,
// SVG DOM manipulation, selection system, and edge creation via port
// drag. No imports, no bundler — vanilla JS targeting evergreen browsers.

(function () {
    "use strict";

    var GnFlow = (window.GnFlow = window.GnFlow || {});

    // ----- Constants ---------------------------------------------------

    var NS = "http://www.w3.org/2000/svg";
    var BOX_W = 180;
    var BOX_H = 64;

    // ----- Minimal ULID generator --------------------------------------
    //
    // Encodes a 48-bit millisecond timestamp + 80 bits of randomness as
    // 26 Crockford Base32 characters. Good enough for client-generated
    // node IDs that will be validated server-side on save.

    var CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    function encodeTime(now, len) {
        var str = "";
        for (var i = len; i > 0; i--) {
            var mod = now % 32;
            str = CROCKFORD[mod] + str;
            now = (now - mod) / 32;
        }
        return str;
    }

    function encodeRandom(len) {
        var str = "";
        var bytes = new Uint8Array(len);
        crypto.getRandomValues(bytes);
        for (var i = 0; i < len; i++) {
            str += CROCKFORD[bytes[i] & 31];
        }
        return str;
    }

    function ulid() {
        // 10 chars for timestamp (48-bit ms), 16 chars for randomness
        return encodeTime(Date.now(), 10) + encodeRandom(16);
    }

    // ----- Node kind defaults ------------------------------------------

    var NODE_DEFAULTS = {
        start:         function () { return { kind: "start", require_session: false }; },
        render:        function () { return { kind: "render", template: "" }; },
        authenticator: function () { return { kind: "authenticator", provider_urn: "" }; },
        broker:        function () { return { kind: "broker", idp_alias: "" }; },
        switch:        function () { return { kind: "switch", condition: "" }; },
        "sub-flow":    function () { return { kind: "sub-flow", flow_alias: "" }; },
        action:        function () { return { kind: "action", action: "" }; },
        success:       function () { return { kind: "success", acr: null, step_up_required: false }; },
        failure:       function () { return { kind: "failure", reason: "" }; },
    };

    // ----- Utility: capitalize -----------------------------------------

    function capitalize(s) {
        if (!s) return "";
        return s.charAt(0).toUpperCase() + s.slice(1);
    }

    // ----- Utility: edge key -------------------------------------------

    function edgeKey(from, to) {
        return from + "->" + to;
    }

    // ----- Utility: mirror to textarea ---------------------------------

    function mirrorToTextarea(state) {
        var ta = document.getElementById("gn-flow-json-textarea");
        if (ta) ta.value = JSON.stringify(state.flow, null, 2);
    }

    // ----- Utility: SVG coordinate conversion --------------------------

    function svgPoint(svg, ev) {
        var pt = svg.createSVGPoint();
        pt.x = ev.clientX;
        pt.y = ev.clientY;
        var ctm = svg.getScreenCTM();
        if (!ctm) return { x: ev.clientX, y: ev.clientY };
        return pt.matrixTransform(ctm.inverse());
    }

    // ----- Utility: read transform from a <g> --------------------------

    function readTransform(g) {
        var t = g.getAttribute("transform") || "";
        var m = /translate\(\s*(-?[\d.]+)\s*,\s*(-?[\d.]+)\s*\)/.exec(t);
        if (m) return { x: parseFloat(m[1]), y: parseFloat(m[2]) };
        return { x: 0, y: 0 };
    }

    // ----- Bezier path builder -----------------------------------------
    //
    // Builds a cubic bezier from the out-port of `fromId` to the in-port
    // of `toId`. Exported so other modules (layout, panels) can call it.

    function buildBezierPath(state, fromId, toId) {
        var fromG = state.nodeGroups.get(fromId);
        var toG = state.nodeGroups.get(toId);
        if (!fromG || !toG) return "";
        var fl = readTransform(fromG);
        var tl = readTransform(toG);
        // Out-port sits at bottom center of fromG.
        var fx = fl.x + BOX_W / 2;
        var fy = fl.y + BOX_H;
        // In-port sits at top center of toG.
        var tx = tl.x + BOX_W / 2;
        var ty = tl.y;
        var my = (fy + ty) / 2;
        return (
            "M " + fx.toFixed(1) + " " + fy.toFixed(1) +
            " C " + fx.toFixed(1) + " " + my.toFixed(1) +
            ", " + tx.toFixed(1) + " " + my.toFixed(1) +
            ", " + tx.toFixed(1) + " " + ty.toFixed(1)
        );
    }
    GnFlow.buildBezierPath = buildBezierPath;

    // ----- Reroute a single edge ---------------------------------------

    function rerouteEdge(state, fromId, toId) {
        var key = edgeKey(fromId, toId);
        var groups = state.edgeGroups.get(key);
        if (!groups) return;
        var d = buildBezierPath(state, fromId, toId);
        if (!d) return;

        // Compute label position at the curve midpoint.
        var fromG = state.nodeGroups.get(fromId);
        var toG = state.nodeGroups.get(toId);
        var fl = readTransform(fromG);
        var tl = readTransform(toG);
        var midX = ((fl.x + tl.x) / 2 + BOX_W / 2).toFixed(1);
        var midY = (((fl.y + BOX_H + tl.y) / 2) - 14).toFixed(1);

        // edgeGroups may store a single <g> or an array of <g>s.
        var list = Array.isArray(groups) ? groups : [groups];
        list.forEach(function (g) {
            var path = g.querySelector(".gn-flow-edge__path");
            if (path) path.setAttribute("d", d);
            var hit = g.querySelector(".gn-flow-edge__hit");
            if (hit) hit.setAttribute("d", d);
            var label = g.querySelector(".gn-flow-edge__label");
            if (label) {
                label.setAttribute("x", midX);
                label.setAttribute("y", midY);
            }
        });
    }
    GnFlow.rerouteEdge = rerouteEdge;

    // ===================================================================
    // renderNode — create SVG DOM for a single node
    // ===================================================================

    function renderNode(state, node) {
        var layout = node.layout || { x: 0, y: 0 };
        var g = document.createElementNS(NS, "g");
        g.classList.add("gn-flow-node");
        g.setAttribute("data-flow-node", "true");
        g.setAttribute("data-node-id", node.id);
        g.setAttribute("data-kind", node.kind || "");
        g.setAttribute("transform", "translate(" + layout.x + ", " + layout.y + ")");

        // Background rect
        var rect = document.createElementNS(NS, "rect");
        rect.classList.add("gn-flow-node__bg");
        rect.setAttribute("width", BOX_W);
        rect.setAttribute("height", BOX_H);
        rect.setAttribute("rx", 8);
        g.appendChild(rect);

        // Title text
        var title = document.createElementNS(NS, "text");
        title.classList.add("gn-flow-node__title");
        title.setAttribute("x", BOX_W / 2);
        title.setAttribute("y", (BOX_H * 0.38).toFixed(1));
        title.setAttribute("text-anchor", "middle");
        title.textContent = node.display_name || capitalize(node.kind || "node");
        g.appendChild(title);

        // Meta / kind label
        var meta = document.createElementNS(NS, "text");
        meta.classList.add("gn-flow-node__meta");
        meta.setAttribute("x", BOX_W / 2);
        meta.setAttribute("y", (BOX_H * 0.70).toFixed(1));
        meta.setAttribute("text-anchor", "middle");
        meta.textContent = node.kind || "";
        g.appendChild(meta);

        // In-port (top center)
        var portIn = document.createElementNS(NS, "circle");
        portIn.classList.add("gn-flow-port", "gn-flow-port--in");
        portIn.setAttribute("cx", BOX_W / 2);
        portIn.setAttribute("cy", 0);
        portIn.setAttribute("r", 6);
        g.appendChild(portIn);

        // Out-port (bottom center)
        var portOut = document.createElementNS(NS, "circle");
        portOut.classList.add("gn-flow-port", "gn-flow-port--out");
        portOut.setAttribute("cx", BOX_W / 2);
        portOut.setAttribute("cy", BOX_H);
        portOut.setAttribute("r", 6);
        g.appendChild(portOut);

        // Register in state and append to the nodes layer.
        state.nodeGroups.set(node.id, g);
        var layer = state.svg.querySelector('[data-flow-layer="nodes"]');
        if (layer) {
            layer.appendChild(g);
        } else {
            state.svg.appendChild(g);
        }

        return g;
    }
    GnFlow.renderNode = renderNode;

    // ===================================================================
    // renderEdge — create SVG DOM for a single edge
    // ===================================================================

    function renderEdge(state, edge) {
        var g = document.createElementNS(NS, "g");
        g.classList.add("gn-flow-edge");
        g.setAttribute("data-flow-edge", "true");
        g.setAttribute("data-from", edge.from);
        g.setAttribute("data-to", edge.to);

        // Compute the bezier path.
        var d = buildBezierPath(state, edge.from, edge.to);

        // Visible path
        var path = document.createElementNS(NS, "path");
        path.classList.add("gn-flow-edge__path");
        path.setAttribute("d", d);
        path.setAttribute("fill", "none");
        g.appendChild(path);

        // Invisible wider hit area for click/hover
        var hit = document.createElementNS(NS, "path");
        hit.classList.add("gn-flow-edge__hit");
        hit.setAttribute("d", d);
        hit.setAttribute("fill", "none");
        g.appendChild(hit);

        // Condition label at the midpoint
        var label = document.createElementNS(NS, "text");
        label.classList.add("gn-flow-edge__label");
        label.setAttribute("text-anchor", "middle");
        label.textContent = edge.condition || "";
        // Position the label roughly at the curve midpoint.
        var fromG = state.nodeGroups.get(edge.from);
        var toG = state.nodeGroups.get(edge.to);
        if (fromG && toG) {
            var fl = readTransform(fromG);
            var tl = readTransform(toG);
            label.setAttribute("x", ((fl.x + tl.x) / 2 + BOX_W / 2).toFixed(1));
            label.setAttribute("y", (((fl.y + BOX_H + tl.y) / 2) - 14).toFixed(1));
        }
        g.appendChild(label);

        // Register in state and append to the edges layer.
        var key = edgeKey(edge.from, edge.to);
        if (!state.edgeGroups.has(key)) {
            state.edgeGroups.set(key, g);
        } else {
            // Multiple edges between the same pair (different conditions)
            // are rare but possible; normalize to an array.
            var existing = state.edgeGroups.get(key);
            if (Array.isArray(existing)) {
                existing.push(g);
            } else {
                state.edgeGroups.set(key, [existing, g]);
            }
        }

        var layer = state.svg.querySelector('[data-flow-layer="edges"]');
        if (layer) {
            layer.appendChild(g);
        } else {
            state.svg.appendChild(g);
        }

        return g;
    }
    GnFlow.renderEdge = renderEdge;

    // ===================================================================
    // Selection system
    // ===================================================================

    function select(state, type, id) {
        // Deselect previous selection first.
        deselect(state);

        state.selected = { type: type, id: id };

        if (type === "node") {
            var g = state.nodeGroups.get(id);
            if (g) g.classList.add("gn-flow-node--selected");
            // Open the node properties panel if the panels module is loaded.
            if (typeof GnFlow.showNodePanel === "function") {
                GnFlow.showNodePanel(state, id);
            }
        } else if (type === "edge") {
            // Edge `id` is encoded as "fromId->toId".
            var parts = id.split("->");
            var fromId = parts[0];
            var toId = parts[1];
            var groups = state.edgeGroups.get(id);
            var list = Array.isArray(groups) ? groups : (groups ? [groups] : []);
            list.forEach(function (eg) {
                eg.classList.add("gn-flow-edge--selected");
            });
            if (typeof GnFlow.showEdgePanel === "function") {
                GnFlow.showEdgePanel(state, fromId, toId);
            }
        }
    }
    GnFlow.select = select;

    function deselect(state) {
        if (!state.selected) return;

        // Remove selection classes from every node and edge.
        state.svg.querySelectorAll(".gn-flow-node--selected").forEach(function (el) {
            el.classList.remove("gn-flow-node--selected");
        });
        state.svg.querySelectorAll(".gn-flow-edge--selected").forEach(function (el) {
            el.classList.remove("gn-flow-edge--selected");
        });

        state.selected = null;

        // Hide the properties panel if the panels module is loaded.
        if (typeof GnFlow.hidePanel === "function") {
            GnFlow.hidePanel();
        }
    }
    GnFlow.deselect = deselect;

    // ===================================================================
    // addNode — create a new node of `kind` and add it to the flow
    // ===================================================================

    function addNode(state, kind) {
        var id = ulid();
        var factory = NODE_DEFAULTS[kind];
        var config = factory ? factory() : { kind: kind };

        var node = {
            id: id,
            kind: kind,
            display_name: capitalize(kind),
            requirement: "required",
            config: config,
            layout: {
                x: (state.viewW || 1920) / 2 - BOX_W / 2,
                y: (state.viewH || 1080) / 2 - BOX_H / 2,
            },
        };

        state.flow.nodes.push(node);
        renderNode(state, node);

        // Trigger auto-layout if the layout module is loaded.
        if (typeof GnFlow.autoLayout === "function") {
            GnFlow.autoLayout(state);
        }

        mirrorToTextarea(state);
        return id;
    }
    GnFlow.addNode = addNode;

    // ===================================================================
    // deleteNode — remove a node and all its connected edges
    // ===================================================================

    function deleteNode(state, nodeId) {
        // Remove edges connected to this node.
        var edgesToRemove = state.flow.edges.filter(function (e) {
            return e.from === nodeId || e.to === nodeId;
        });
        edgesToRemove.forEach(function (e) {
            removeEdgeDom(state, e.from, e.to);
        });
        state.flow.edges = state.flow.edges.filter(function (e) {
            return e.from !== nodeId && e.to !== nodeId;
        });

        // Remove the node from the flow definition.
        state.flow.nodes = state.flow.nodes.filter(function (n) {
            return n.id !== nodeId;
        });

        // Remove the SVG group.
        var g = state.nodeGroups.get(nodeId);
        if (g && g.parentNode) g.parentNode.removeChild(g);
        state.nodeGroups.delete(nodeId);

        // Clear start reference if this was the start node.
        if (state.flow.start === nodeId) {
            state.flow.start = null;
        }

        deselect(state);
        mirrorToTextarea(state);
    }
    GnFlow.deleteNode = deleteNode;

    // ===================================================================
    // addEdge — connect two nodes
    // ===================================================================

    function addEdge(state, fromId, toId, condition) {
        condition = condition || "otherwise";

        // Check for duplicate.
        var dup = state.flow.edges.some(function (e) {
            return e.from === fromId && e.to === toId && e.condition === condition;
        });
        if (dup) return null;

        var edge = { from: fromId, to: toId, condition: condition };
        state.flow.edges.push(edge);
        renderEdge(state, edge);
        mirrorToTextarea(state);
        return edgeKey(fromId, toId);
    }
    GnFlow.addEdge = addEdge;

    // ===================================================================
    // deleteEdge — remove all edges from `fromId` to `toId`
    // ===================================================================

    function deleteEdge(state, fromId, toId) {
        state.flow.edges = state.flow.edges.filter(function (e) {
            return !(e.from === fromId && e.to === toId);
        });
        removeEdgeDom(state, fromId, toId);
        deselect(state);
        mirrorToTextarea(state);
    }
    GnFlow.deleteEdge = deleteEdge;

    // Remove all SVG <g> elements for a given edge key.
    function removeEdgeDom(state, fromId, toId) {
        var key = edgeKey(fromId, toId);
        var groups = state.edgeGroups.get(key);
        if (!groups) return;
        var list = Array.isArray(groups) ? groups : [groups];
        list.forEach(function (g) {
            if (g && g.parentNode) g.parentNode.removeChild(g);
        });
        state.edgeGroups.delete(key);
    }

    // ===================================================================
    // Port drag — create edges by dragging from an out-port to an in-port
    // ===================================================================

    function attachPortDrag(state) {
        var dragLine = null;   // Temporary SVG line during drag
        var sourceNodeId = null;

        state.svg.addEventListener("pointerdown", function (ev) {
            var port = ev.target.closest(".gn-flow-port--out");
            if (!port) return;
            ev.preventDefault();
            ev.stopPropagation();

            // Determine the source node.
            var nodeG = port.closest('[data-flow-node="true"]');
            if (!nodeG) return;
            sourceNodeId = nodeG.dataset.nodeId;

            // Port center in SVG coordinates.
            var layout = readTransform(nodeG);
            var startX = layout.x + BOX_W / 2;
            var startY = layout.y + BOX_H;

            // Create a temporary line from the port to the cursor.
            dragLine = document.createElementNS(NS, "line");
            dragLine.classList.add("gn-flow-edge__drag");
            dragLine.setAttribute("x1", startX);
            dragLine.setAttribute("y1", startY);
            dragLine.setAttribute("x2", startX);
            dragLine.setAttribute("y2", startY);
            state.svg.appendChild(dragLine);

            function onMove(moveEv) {
                if (!dragLine) return;
                var p = svgPoint(state.svg, moveEv);
                dragLine.setAttribute("x2", p.x);
                dragLine.setAttribute("y2", p.y);
            }

            function onUp(upEv) {
                window.removeEventListener("pointermove", onMove);
                window.removeEventListener("pointerup", onUp);

                // Check if the pointer landed on an in-port of a different node.
                var target = upEv.target.closest(".gn-flow-port--in");
                if (target) {
                    var targetNode = target.closest('[data-flow-node="true"]');
                    if (targetNode && targetNode.dataset.nodeId !== sourceNodeId) {
                        addEdge(state, sourceNodeId, targetNode.dataset.nodeId);
                    }
                }

                // Remove the temporary drag line.
                if (dragLine && dragLine.parentNode) {
                    dragLine.parentNode.removeChild(dragLine);
                }
                dragLine = null;
                sourceNodeId = null;
            }

            window.addEventListener("pointermove", onMove);
            window.addEventListener("pointerup", onUp, { once: true });
        });
    }

    // ===================================================================
    // initCrud — attach all CRUD event handlers to the SVG canvas
    // ===================================================================

    function initCrud(state) {
        // Ensure defaults for box / viewport dimensions.
        state.boxW = state.boxW || BOX_W;
        state.boxH = state.boxH || BOX_H;
        state.viewW = state.viewW || 1920;
        state.viewH = state.viewH || 1080;
        if (!state.selected) state.selected = null;

        // ---- Selection via click on the SVG ---------------------------
        state.svg.addEventListener("click", function (ev) {
            // Node click?
            var nodeG = ev.target.closest('[data-flow-node="true"]');
            if (nodeG) {
                select(state, "node", nodeG.dataset.nodeId);
                return;
            }
            // Edge click?
            var edgeG = ev.target.closest('[data-flow-edge="true"]');
            if (edgeG) {
                select(state, "edge", edgeKey(edgeG.dataset.from, edgeG.dataset.to));
                return;
            }
            // Background click — deselect.
            deselect(state);
        });

        // ---- Port drag for edge creation ------------------------------
        attachPortDrag(state);

        // ---- "Add Node" dropdown menu ---------------------------------
        var addBtn = state.root
            ? state.root.querySelector('[data-flow-action="add-node"]')
            : document.querySelector('[data-flow-action="add-node"]');
        if (addBtn) {
            var menu = addBtn.nextElementSibling; // expect adjacent dropdown
            if (menu && menu.classList.contains("gn-flow-add-menu")) {
                addBtn.addEventListener("click", function (ev) {
                    ev.stopPropagation();
                    menu.classList.toggle("gn-flow-add-menu--open");
                });
                // Close on outside click.
                document.addEventListener("click", function () {
                    menu.classList.remove("gn-flow-add-menu--open");
                });
                // Handle menu item clicks.
                menu.addEventListener("click", function (ev) {
                    var item = ev.target.closest("[data-node-kind]");
                    if (!item) return;
                    ev.stopPropagation();
                    var kind = item.dataset.nodeKind;
                    if (kind) addNode(state, kind);
                    menu.classList.remove("gn-flow-add-menu--open");
                });
            }
        }

        // ---- Custom events for external triggers ----------------------
        document.addEventListener("gn-flow:delete-selected", function () {
            if (!state.selected) return;
            if (state.selected.type === "node") {
                deleteNode(state, state.selected.id);
            } else if (state.selected.type === "edge") {
                var parts = state.selected.id.split("->");
                if (parts.length === 2) deleteEdge(state, parts[0], parts[1]);
            }
        });

        document.addEventListener("gn-flow:deselect", function () {
            deselect(state);
        });
    }
    GnFlow.initCrud = initCrud;

    // ---- Also expose helpers that other modules may need ----
    GnFlow.ulid = ulid;
    GnFlow.mirrorToTextarea = mirrorToTextarea;
    GnFlow.edgeKey = edgeKey;
})();
