// Geonosis flow layout — ELK.js integration for automatic graph layout.
//
// This module converts the flow definition JSON into an ELK graph
// descriptor, runs the ELK layered layout algorithm, and maps the
// computed coordinates back to the SVG canvas. It also provides
// orthogonal edge routing with rounded corners when ELK section data
// is available, falling back to cubic Bezier curves otherwise.
//
// Prerequisites: `elk.min.js` must be loaded before this file.
// It exposes `window.ELK` as a constructor.
//
// Registration: all public functions live on `window.GnFlow` so that
// flow-editor.js (and future modules) can call them without imports.

(function () {
    "use strict";

    window.GnFlow = window.GnFlow || {};

    // ── Constants ────────────────────────────────────────────────────

    /** Corner radius (px) for orthogonal bend points. */
    var CORNER_R = 4;

    // ── Public API ───────────────────────────────────────────────────

    /**
     * Run ELK layered layout on the current flow and apply results to
     * both the JSON model and the SVG canvas.
     *
     * @param {Object} state - Editor state (flow, nodeGroups, edgeGroups, boxW, boxH, …)
     * @returns {Promise<void>}
     */
    GnFlow.autoLayout = async function autoLayout(state) {
        if (typeof window.ELK !== "function") {
            console.warn("[gn-flow-layout] ELK not loaded; skipping auto-layout.");
            return;
        }

        var flow = state.flow;
        if (!flow || !Array.isArray(flow.nodes)) return;

        var boxW = state.boxW || 180;
        var boxH = state.boxH || 64;

        // 1. Build ELK graph descriptor ──────────────────────────────

        var elkNodes = flow.nodes.map(function (n) {
            return {
                id: n.id,
                width: boxW,
                height: boxH,
            };
        });

        var elkEdges = (flow.edges || []).map(function (e, i) {
            return {
                id: "e" + i + "_" + e.from + "_" + e.to,
                sources: [e.from],
                targets: [e.to],
            };
        });

        var graph = {
            id: "root",
            layoutOptions: {
                "elk.algorithm": "layered",
                "elk.direction": "DOWN",
                "elk.layered.spacing.nodeNodeBetweenLayers": "100",
                "elk.spacing.nodeNode": "50",
                "elk.edgeRouting": "ORTHOGONAL",
                "elk.layered.crossingMinimization.strategy": "LAYER_SWEEP",
                "elk.layered.nodePlacement.strategy": "BRANDES_KOEPF",
                "elk.padding": "[top=60,left=60,bottom=60,right=60]",
            },
            children: elkNodes,
            edges: elkEdges,
        };

        // 2. Run ELK layout ──────────────────────────────────────────

        var elk = new window.ELK();
        var layoutResult;
        try {
            layoutResult = await elk.layout(graph);
        } catch (err) {
            console.error("[gn-flow-layout] ELK layout failed:", err);
            return;
        }

        // 3. Map coordinates back to flow JSON ───────────────────────

        var elkNodeMap = new Map();
        (layoutResult.children || []).forEach(function (child) {
            elkNodeMap.set(child.id, child);
        });

        flow.nodes.forEach(function (n) {
            var elkNode = elkNodeMap.get(n.id);
            if (!elkNode) return;
            n.layout = { x: elkNode.x, y: elkNode.y };
        });

        // 4. Update SVG node transforms ──────────────────────────────

        flow.nodes.forEach(function (n) {
            var g = state.nodeGroups.get(n.id);
            if (!g || !n.layout) return;
            g.setAttribute(
                "transform",
                "translate(" + n.layout.x + ", " + n.layout.y + ")"
            );
        });

        // 5. Re-route edges using ELK section data ───────────────────

        // Build a lookup from "from->to" to ELK edge sections.
        var elkEdgeSections = new Map();
        (layoutResult.edges || []).forEach(function (elkEdge) {
            if (!elkEdge.sections || !elkEdge.sections.length) return;
            var fromId =
                elkEdge.sources && elkEdge.sources[0] ? elkEdge.sources[0] : "";
            var toId =
                elkEdge.targets && elkEdge.targets[0] ? elkEdge.targets[0] : "";
            var key = fromId + "->" + toId;
            elkEdgeSections.set(key, elkEdge.sections);
        });

        // Store ELK sections on state so rerouteEdge can use them later.
        state._elkEdgeSections = elkEdgeSections;

        state.edgeGroups.forEach(function (_groups, key) {
            var parts = key.split("->");
            var fromId = parts[0];
            var toId = parts[1];
            var sections = elkEdgeSections.get(key);

            _groups.forEach(function (g) {
                var path = g.querySelector(".gn-flow-edge__path");
                var hit = g.querySelector(".gn-flow-edge__hit");
                if (!path) return;

                if (sections && sections.length) {
                    // Orthogonal path from ELK sections.
                    var d = GnFlow.buildEdgePath(sections);
                    path.setAttribute("d", d);
                    if (hit) hit.setAttribute("d", d);

                    // Position label at midpoint of longest segment.
                    var label = g.querySelector(".gn-flow-edge__label");
                    if (label) {
                        var labelPos = findLabelPosition(sections);
                        label.setAttribute("x", labelPos.x.toFixed(1));
                        label.setAttribute("y", (labelPos.y - 6).toFixed(1));
                    }
                } else {
                    // Fallback: cubic Bezier between node centres.
                    rerouteSingleEdge(state, fromId, toId, g);
                }
            });
        });

        // 6. Update minimap if available ─────────────────────────────

        if (typeof GnFlow.updateMinimap === "function") {
            GnFlow.updateMinimap(state);
        }

        // 7. Mirror changes to the JSON textarea ─────────────────────

        if (typeof GnFlow.mirrorToTextarea === "function") {
            GnFlow.mirrorToTextarea(state);
        } else {
            syncTextarea(state);
        }
    };

    /**
     * Recalculate all edge paths based on current node positions.
     * Uses orthogonal routing when ELK section data is available on
     * state, otherwise falls back to cubic Bezier curves.
     *
     * @param {Object} state
     */
    GnFlow.rerouteAllEdges = function rerouteAllEdges(state) {
        state.edgeGroups.forEach(function (_groups, key) {
            var parts = key.split("->");
            GnFlow.rerouteEdge(state, parts[0], parts[1]);
        });
    };

    /**
     * Recalculate a single edge path.
     *
     * @param {Object} state
     * @param {string} fromId
     * @param {string} toId
     */
    GnFlow.rerouteEdge = function rerouteEdge(state, fromId, toId) {
        var key = fromId + "->" + toId;
        var groups = state.edgeGroups.get(key);
        if (!groups || !groups.length) return;

        // During drag, ELK sections are stale — always use Bezier fallback.
        // ELK sections are only valid right after autoLayout completes.
        groups.forEach(function (g) {
            rerouteSingleEdge(state, fromId, toId, g);
        });
    };

    /**
     * Convert ELK edge sections (with startPoint, endPoint, bendPoints)
     * to an SVG path `d` attribute. Uses L commands for orthogonal
     * segments with quadratic Bezier (Q) for small rounded corners at
     * each bend point.
     *
     * @param {Array} sections - Array of ELK edge section objects.
     * @returns {string} SVG path `d` attribute string.
     */
    GnFlow.buildEdgePath = function buildEdgePath(sections) {
        if (!sections || !sections.length) return "";

        var points = [];

        sections.forEach(function (section) {
            // Start point of this section.
            if (section.startPoint) {
                points.push({ x: section.startPoint.x, y: section.startPoint.y });
            }
            // Bend points (intermediate waypoints).
            if (section.bendPoints && section.bendPoints.length) {
                section.bendPoints.forEach(function (bp) {
                    points.push({ x: bp.x, y: bp.y });
                });
            }
            // End point of this section.
            if (section.endPoint) {
                points.push({ x: section.endPoint.x, y: section.endPoint.y });
            }
        });

        if (points.length < 2) return "";

        // Build the path with rounded corners at bend points.
        var d = "M " + fmt(points[0].x) + " " + fmt(points[0].y);

        for (var i = 1; i < points.length; i++) {
            if (i < points.length - 1) {
                // This is a bend point — apply corner radius.
                var prev = points[i - 1];
                var curr = points[i];
                var next = points[i + 1];

                // Compute distances to clamp the radius.
                var dPrev = dist(prev, curr);
                var dNext = dist(curr, next);
                var r = Math.min(CORNER_R, dPrev / 2, dNext / 2);

                if (r < 0.5) {
                    // Radius too small; just draw a straight line.
                    d += " L " + fmt(curr.x) + " " + fmt(curr.y);
                    continue;
                }

                // Direction vectors from curr towards prev and next.
                var dxPrev = (prev.x - curr.x) / dPrev;
                var dyPrev = (prev.y - curr.y) / dPrev;
                var dxNext = (next.x - curr.x) / dNext;
                var dyNext = (next.y - curr.y) / dNext;

                // Points where the curve begins and ends.
                var enterX = curr.x + dxPrev * r;
                var enterY = curr.y + dyPrev * r;
                var exitX = curr.x + dxNext * r;
                var exitY = curr.y + dyNext * r;

                // Line to the curve entry, then quadratic Bezier through
                // the corner using the bend point as control point.
                d += " L " + fmt(enterX) + " " + fmt(enterY);
                d +=
                    " Q " +
                    fmt(curr.x) +
                    " " +
                    fmt(curr.y) +
                    " " +
                    fmt(exitX) +
                    " " +
                    fmt(exitY);
            } else {
                // Last point — straight line to the end.
                d += " L " + fmt(points[i].x) + " " + fmt(points[i].y);
            }
        }

        return d;
    };

    /**
     * Fallback cubic Bezier edge path between two node attachment points.
     * Uses the same curve shape as flow-editor.js: a vertical S-curve
     * passing through the vertical midpoint.
     *
     * @param {number} fx - Source x (center-bottom of source node)
     * @param {number} fy - Source y
     * @param {number} tx - Target x (center-top of target node)
     * @param {number} ty - Target y
     * @param {number} boxW - Node box width (unused but kept for API symmetry)
     * @param {number} boxH - Node box height (unused but kept for API symmetry)
     * @returns {string} SVG path `d` attribute string.
     */
    GnFlow.buildBezierPath = function buildBezierPath(fx, fy, tx, ty, boxW, boxH) {
        var my = (fy + ty) / 2;
        return (
            "M " + fmt(fx) + " " + fmt(fy) +
            " C " + fmt(fx) + " " + fmt(my) +
            ", " + fmt(tx) + " " + fmt(my) +
            ", " + fmt(tx) + " " + fmt(ty)
        );
    };

    // ── Private helpers ──────────────────────────────────────────────

    /**
     * Reroute a single edge group element using the Bezier fallback.
     * Reads node positions from the SVG transforms.
     */
    function rerouteSingleEdge(state, fromId, toId, g) {
        var fromGroup = state.nodeGroups.get(fromId);
        var toGroup = state.nodeGroups.get(toId);
        if (!fromGroup || !toGroup) return;

        var boxW = state.boxW || 180;
        var boxH = state.boxH || 64;
        var fl = readTransform(fromGroup);
        var tl = readTransform(toGroup);

        // Attachment points: center-bottom of source, center-top of target.
        var fx = fl.x + boxW / 2;
        var fy = fl.y + boxH;
        var tx = tl.x + boxW / 2;
        var ty = tl.y;

        var d = GnFlow.buildBezierPath(fx, fy, tx, ty, boxW, boxH);
        var path = g.querySelector(".gn-flow-edge__path");
        if (path) path.setAttribute("d", d);
        var hit = g.querySelector(".gn-flow-edge__hit");
        if (hit) hit.setAttribute("d", d);

        // Position the label at the vertical midpoint.
        var label = g.querySelector(".gn-flow-edge__label");
        if (label) {
            var midX = (fx + tx) / 2;
            var midY = (fy + ty) / 2 - 6;
            label.setAttribute("x", fmt(midX));
            label.setAttribute("y", fmt(midY));
        }
    }

    /**
     * Find the best position for an edge label: the midpoint of the
     * longest segment in the orthogonal path described by ELK sections.
     *
     * @param {Array} sections - ELK edge sections
     * @returns {{x: number, y: number}}
     */
    function findLabelPosition(sections) {
        // Collect all points across sections.
        var points = [];
        sections.forEach(function (section) {
            if (section.startPoint) {
                points.push(section.startPoint);
            }
            if (section.bendPoints) {
                section.bendPoints.forEach(function (bp) {
                    points.push(bp);
                });
            }
            if (section.endPoint) {
                points.push(section.endPoint);
            }
        });

        if (points.length < 2) {
            // Degenerate case: return the single point or origin.
            return points.length === 1
                ? { x: points[0].x, y: points[0].y }
                : { x: 0, y: 0 };
        }

        // Walk all segments and find the longest one.
        var bestLen = -1;
        var bestMid = { x: 0, y: 0 };

        for (var i = 0; i < points.length - 1; i++) {
            var a = points[i];
            var b = points[i + 1];
            var segLen = dist(a, b);
            if (segLen > bestLen) {
                bestLen = segLen;
                bestMid = {
                    x: (a.x + b.x) / 2,
                    y: (a.y + b.y) / 2,
                };
            }
        }

        return bestMid;
    }

    /**
     * Read `translate(x, y)` from an SVG group's transform attribute.
     */
    function readTransform(g) {
        var t = g.getAttribute("transform") || "";
        var m = /translate\(\s*(-?[\d.]+)\s*,\s*(-?[\d.]+)\s*\)/.exec(t);
        if (m) return { x: parseFloat(m[1]), y: parseFloat(m[2]) };
        return { x: 0, y: 0 };
    }

    /**
     * Euclidean distance between two {x, y} points.
     */
    function dist(a, b) {
        var dx = b.x - a.x;
        var dy = b.y - a.y;
        return Math.sqrt(dx * dx + dy * dy);
    }

    /**
     * Format a number for SVG coordinates (1 decimal place).
     */
    function fmt(n) {
        return n.toFixed(1);
    }

    /**
     * Direct textarea sync fallback — used when mirrorToTextarea is not
     * accessible from the flow-editor.js closure.
     */
    function syncTextarea(state) {
        var textarea = document.getElementById("gn-flow-json-textarea");
        if (!textarea) return;
        try {
            textarea.value = JSON.stringify(state.flow, null, 2);
        } catch (e) {
            // Leave textarea as-is.
        }
    }
})();
