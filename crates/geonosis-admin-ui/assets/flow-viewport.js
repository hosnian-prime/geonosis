// Geonosis flow viewport — zoom, pan, minimap, keyboard navigation.
//
// This module manages the SVG viewport transform for the flow editor
// canvas. It registers functions on the `window.GnFlow` namespace so
// the orchestrator (flow-editor.js) can call them after hydration.
//
// The SVG is expected to contain a `<g data-flow-viewport="true">`
// wrapper around all visible content. Zoom and pan transforms are
// applied to that group's `transform` attribute.
//
// No imports, no bundler. Targets evergreen browsers.

(function () {
    "use strict";

    var GnFlow = window.GnFlow = window.GnFlow || {};

    // ---- Constants ---------------------------------------------------

    var MIN_SCALE = 0.15;
    var MAX_SCALE = 4.0;
    var ZOOM_IN_FACTOR = 1.25;
    var ZOOM_OUT_FACTOR = 0.8;
    var PAN_STEP = 50;
    var MINIMAP_W = 200;
    var MINIMAP_H = 140;
    var FIT_PADDING = 40; // px padding around content when fitting

    // ---- Public API --------------------------------------------------

    /**
     * Initialize viewport state and attach event listeners.
     *
     * Expects `state` to already have: svg, root, viewW, viewH, boxW, boxH.
     * Adds `state.viewport` with the current transform.
     */
    GnFlow.initViewport = function initViewport(state) {
        state.viewport = { tx: 0, ty: 0, scale: 1 };

        var vg = state.svg.querySelector('[data-flow-viewport="true"]');
        if (!vg) {
            // Graceful fallback: wrap nothing — transforms will be a no-op.
            return;
        }
        state._viewportGroup = vg;

        attachWheelZoom(state);
        attachPointerPan(state);
        attachKeyboard(state);
        attachMinimap(state);
        applyTransform(state);
    };

    /**
     * Zoom in by the standard factor (1.25x), centered on the viewport.
     */
    GnFlow.zoomIn = function zoomIn(state) {
        zoomAroundCenter(state, ZOOM_IN_FACTOR);
    };

    /**
     * Zoom out by the standard factor (0.8x), centered on the viewport.
     */
    GnFlow.zoomOut = function zoomOut(state) {
        zoomAroundCenter(state, ZOOM_OUT_FACTOR);
    };

    /**
     * Fit the viewport so all nodes are visible with padding.
     */
    GnFlow.fitToView = function fitToView(state) {
        var bb = computeContentBBox(state);
        if (!bb) return;

        // Available space is the SVG's own client dimensions.
        var svgRect = state.svg.getBoundingClientRect();
        var availW = svgRect.width || state.viewW;
        var availH = svgRect.height || state.viewH;

        var contentW = bb.maxX - bb.minX + FIT_PADDING * 2;
        var contentH = bb.maxY - bb.minY + FIT_PADDING * 2;

        if (contentW <= 0 || contentH <= 0) return;

        var scale = Math.min(availW / contentW, availH / contentH);
        scale = clampScale(scale);

        // Center the content in the available space.
        var tx = (availW - contentW * scale) / 2 - bb.minX * scale + FIT_PADDING * scale;
        var ty = (availH - contentH * scale) / 2 - bb.minY * scale + FIT_PADDING * scale;

        state.viewport.scale = scale;
        state.viewport.tx = tx;
        state.viewport.ty = ty;
        applyTransform(state);
        GnFlow.updateMinimap(state);
    };

    /**
     * Returns a copy of the current viewport transform.
     */
    GnFlow.getViewportTransform = function getViewportTransform(state) {
        return {
            tx: state.viewport.tx,
            ty: state.viewport.ty,
            scale: state.viewport.scale,
        };
    };

    /**
     * Redraw the minimap canvas, showing all nodes as small colored
     * rectangles and a viewport indicator rectangle.
     */
    GnFlow.updateMinimap = function updateMinimap(state) {
        var canvas = document.getElementById("gn-flow-minimap");
        if (!canvas || !canvas.getContext) return;

        var ctx = canvas.getContext("2d");
        var cw = canvas.width || MINIMAP_W;
        var ch = canvas.height || MINIMAP_H;

        // Clear
        ctx.clearRect(0, 0, cw, ch);

        // Compute the world-space bounding box of all nodes so we can
        // map world coordinates into minimap coordinates.
        var bb = computeContentBBox(state);
        if (!bb) return;

        var padded = {
            minX: bb.minX - FIT_PADDING,
            minY: bb.minY - FIT_PADDING,
            maxX: bb.maxX + FIT_PADDING,
            maxY: bb.maxY + FIT_PADDING,
        };

        var worldW = padded.maxX - padded.minX;
        var worldH = padded.maxY - padded.minY;
        if (worldW <= 0 || worldH <= 0) return;

        var miniScale = Math.min(cw / worldW, ch / worldH);

        // Offset to center the content in the minimap.
        var offsetX = (cw - worldW * miniScale) / 2;
        var offsetY = (ch - worldH * miniScale) / 2;

        // Draw a subtle background for the content area.
        ctx.fillStyle = "rgba(128, 128, 128, 0.08)";
        ctx.fillRect(offsetX, offsetY, worldW * miniScale, worldH * miniScale);

        // Draw each node as a small rectangle.
        var nodes = state.svg.querySelectorAll('[data-flow-node="true"]');
        nodes.forEach(function (g) {
            var pos = readTranslate(g);
            var rx = (pos.x - padded.minX) * miniScale + offsetX;
            var ry = (pos.y - padded.minY) * miniScale + offsetY;
            var rw = state.boxW * miniScale;
            var rh = state.boxH * miniScale;

            // Try to pick up the node's kind color from its computed style.
            var color = getNodeColor(g);
            ctx.fillStyle = color;
            ctx.fillRect(rx, ry, Math.max(rw, 2), Math.max(rh, 1));
        });

        // Draw the viewport indicator — shows what portion of the world
        // is currently visible in the main SVG.
        var svgRect = state.svg.getBoundingClientRect();
        var visW = (svgRect.width || state.viewW);
        var visH = (svgRect.height || state.viewH);

        // The visible region in world coordinates:
        var vp = state.viewport;
        var visMinX = -vp.tx / vp.scale;
        var visMinY = -vp.ty / vp.scale;
        var visMaxX = visMinX + visW / vp.scale;
        var visMaxY = visMinY + visH / vp.scale;

        var vrx = (visMinX - padded.minX) * miniScale + offsetX;
        var vry = (visMinY - padded.minY) * miniScale + offsetY;
        var vrw = (visMaxX - visMinX) * miniScale;
        var vrh = (visMaxY - visMinY) * miniScale;

        ctx.strokeStyle = "rgba(59, 130, 246, 0.7)";
        ctx.lineWidth = 1.5;
        ctx.strokeRect(vrx, vry, vrw, vrh);

        // Store mapping info for click-to-navigate.
        state._minimapMapping = {
            miniScale: miniScale,
            offsetX: offsetX,
            offsetY: offsetY,
            padded: padded,
        };
    };

    // ---- Wheel zoom --------------------------------------------------

    function attachWheelZoom(state) {
        state.svg.addEventListener("wheel", function (ev) {
            ev.preventDefault();

            // Determine zoom direction from deltaY.
            var factor = ev.deltaY < 0 ? ZOOM_IN_FACTOR : ZOOM_OUT_FACTOR;
            var newScale = clampScale(state.viewport.scale * factor);
            if (newScale === state.viewport.scale) return;

            // Zoom centered on the cursor position within the SVG.
            var rect = state.svg.getBoundingClientRect();
            var cx = ev.clientX - rect.left;
            var cy = ev.clientY - rect.top;

            // The world point under the cursor before zoom:
            var wx = (cx - state.viewport.tx) / state.viewport.scale;
            var wy = (cy - state.viewport.ty) / state.viewport.scale;

            state.viewport.scale = newScale;

            // Adjust translation so the same world point stays under the cursor.
            state.viewport.tx = cx - wx * newScale;
            state.viewport.ty = cy - wy * newScale;

            applyTransform(state);
            GnFlow.updateMinimap(state);
        }, { passive: false });
    }

    // ---- Pointer pan -------------------------------------------------

    function attachPointerPan(state) {
        var panning = null;

        state.svg.addEventListener("pointerdown", function (ev) {
            // Don't interfere with node or edge interactions.
            if (ev.target.closest("[data-flow-node]")) return;
            if (ev.target.closest("[data-flow-edge]")) return;

            // Only pan on primary button (left click / touch).
            if (ev.button !== 0) return;

            ev.preventDefault();
            panning = {
                startX: ev.clientX,
                startY: ev.clientY,
                startTx: state.viewport.tx,
                startTy: state.viewport.ty,
            };

            state.svg.setPointerCapture(ev.pointerId);
        });

        state.svg.addEventListener("pointermove", function (ev) {
            if (!panning) return;
            ev.preventDefault();

            var dx = ev.clientX - panning.startX;
            var dy = ev.clientY - panning.startY;
            state.viewport.tx = panning.startTx + dx;
            state.viewport.ty = panning.startTy + dy;

            applyTransform(state);
        });

        state.svg.addEventListener("pointerup", function (ev) {
            if (!panning) return;
            panning = null;
            state.svg.releasePointerCapture(ev.pointerId);
            GnFlow.updateMinimap(state);
        });

        // Clean up if pointer capture is lost (e.g. browser intervention).
        state.svg.addEventListener("lostpointercapture", function () {
            if (panning) {
                panning = null;
                GnFlow.updateMinimap(state);
            }
        });
    }

    // ---- Keyboard shortcuts ------------------------------------------

    function attachKeyboard(state) {
        // Listen on the flow container so shortcuts only fire when the
        // SVG area (or something inside it) has focus.
        var container = state.root;

        // Ensure the container can receive focus.
        if (!container.hasAttribute("tabindex")) {
            container.setAttribute("tabindex", "0");
        }

        container.addEventListener("keydown", function (ev) {
            // Don't intercept when typing in inputs/textareas/selects.
            var tag = ev.target.tagName;
            if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || ev.target.isContentEditable) return;

            var key = ev.key;
            var handled = true;

            switch (key) {
                case "+":
                case "=":
                    GnFlow.zoomIn(state);
                    break;
                case "-":
                    GnFlow.zoomOut(state);
                    break;
                case "0":
                    GnFlow.fitToView(state);
                    break;
                case "ArrowUp":
                    panBy(state, 0, PAN_STEP);
                    break;
                case "ArrowDown":
                    panBy(state, 0, -PAN_STEP);
                    break;
                case "ArrowLeft":
                    panBy(state, PAN_STEP, 0);
                    break;
                case "ArrowRight":
                    panBy(state, -PAN_STEP, 0);
                    break;
                case "Delete":
                case "Backspace":
                    // Dispatch a custom event for the CRUD module to handle.
                    container.dispatchEvent(new CustomEvent("gn-flow:delete-selected", {
                        bubbles: true,
                    }));
                    break;
                case "Escape":
                    // Dispatch a custom event to deselect everything.
                    container.dispatchEvent(new CustomEvent("gn-flow:deselect", {
                        bubbles: true,
                    }));
                    break;
                default:
                    handled = false;
            }

            if (handled) {
                ev.preventDefault();
                ev.stopPropagation();
            }
        });
    }

    // ---- Minimap interaction -----------------------------------------

    function attachMinimap(state) {
        var canvas = document.getElementById("gn-flow-minimap");
        if (!canvas) return;

        // Ensure the canvas has the expected dimensions.
        canvas.width = MINIMAP_W;
        canvas.height = MINIMAP_H;
        canvas.classList.add("gn-flow-minimap");

        // Initial draw.
        GnFlow.updateMinimap(state);

        // Click on minimap navigates the viewport to that world position.
        canvas.addEventListener("click", function (ev) {
            var map = state._minimapMapping;
            if (!map) return;

            var rect = canvas.getBoundingClientRect();
            var mx = ev.clientX - rect.left;
            var my = ev.clientY - rect.top;

            // Convert minimap coordinates to world coordinates.
            var worldX = (mx - map.offsetX) / map.miniScale + map.padded.minX;
            var worldY = (my - map.offsetY) / map.miniScale + map.padded.minY;

            // Center the viewport on the clicked world position.
            var svgRect = state.svg.getBoundingClientRect();
            var visW = svgRect.width || state.viewW;
            var visH = svgRect.height || state.viewH;

            state.viewport.tx = visW / 2 - worldX * state.viewport.scale;
            state.viewport.ty = visH / 2 - worldY * state.viewport.scale;

            applyTransform(state);
            GnFlow.updateMinimap(state);
        });
    }

    // ---- Internal helpers --------------------------------------------

    /**
     * Apply the current viewport transform to the SVG group.
     */
    function applyTransform(state) {
        if (!state._viewportGroup) return;
        var vp = state.viewport;
        state._viewportGroup.setAttribute(
            "transform",
            "translate(" + vp.tx + ", " + vp.ty + ") scale(" + vp.scale + ")"
        );
    }

    /**
     * Zoom by `factor` centered on the SVG's visual center.
     */
    function zoomAroundCenter(state, factor) {
        var newScale = clampScale(state.viewport.scale * factor);
        if (newScale === state.viewport.scale) return;

        var svgRect = state.svg.getBoundingClientRect();
        var cx = (svgRect.width || state.viewW) / 2;
        var cy = (svgRect.height || state.viewH) / 2;

        var wx = (cx - state.viewport.tx) / state.viewport.scale;
        var wy = (cy - state.viewport.ty) / state.viewport.scale;

        state.viewport.scale = newScale;
        state.viewport.tx = cx - wx * newScale;
        state.viewport.ty = cy - wy * newScale;

        applyTransform(state);
        GnFlow.updateMinimap(state);
    }

    /**
     * Pan the viewport by `dx`, `dy` in screen pixels.
     */
    function panBy(state, dx, dy) {
        state.viewport.tx += dx;
        state.viewport.ty += dy;
        applyTransform(state);
        GnFlow.updateMinimap(state);
    }

    /**
     * Clamp a scale value to the allowed range.
     */
    function clampScale(s) {
        return Math.min(MAX_SCALE, Math.max(MIN_SCALE, s));
    }

    /**
     * Compute the bounding box of all flow nodes in world coordinates.
     * Returns `{ minX, minY, maxX, maxY }` or null if no nodes exist.
     */
    function computeContentBBox(state) {
        var nodes = state.svg.querySelectorAll('[data-flow-node="true"]');
        if (!nodes.length) return null;

        var minX = Infinity, minY = Infinity;
        var maxX = -Infinity, maxY = -Infinity;

        nodes.forEach(function (g) {
            var pos = readTranslate(g);
            if (pos.x < minX) minX = pos.x;
            if (pos.y < minY) minY = pos.y;
            if (pos.x + state.boxW > maxX) maxX = pos.x + state.boxW;
            if (pos.y + state.boxH > maxY) maxY = pos.y + state.boxH;
        });

        if (minX === Infinity) return null;
        return { minX: minX, minY: minY, maxX: maxX, maxY: maxY };
    }

    /**
     * Read the translate(x, y) from a group's transform attribute.
     */
    function readTranslate(g) {
        var t = g.getAttribute("transform") || "";
        var m = /translate\(\s*(-?[\d.]+)\s*,\s*(-?[\d.]+)\s*\)/.exec(t);
        if (m) return { x: parseFloat(m[1]), y: parseFloat(m[2]) };
        return { x: 0, y: 0 };
    }

    /**
     * Extract a representative color from a node element for the minimap.
     * Falls back to a neutral blue-gray if no computed color is available.
     */
    function getNodeColor(g) {
        // Try the background rect's fill first (most reliable for SVG nodes).
        var bg = g.querySelector(".gn-flow-node__bg");
        if (bg) {
            var fill = bg.getAttribute("fill");
            if (fill && fill !== "none") return fill;

            // Fall back to computed style if fill is set via CSS.
            try {
                var computed = window.getComputedStyle(bg);
                if (computed.fill && computed.fill !== "none") return computed.fill;
            } catch (_) {
                // getComputedStyle can throw in edge cases; ignore.
            }
        }

        // Default color for minimap nodes.
        return "rgba(100, 116, 139, 0.7)";
    }

})();
