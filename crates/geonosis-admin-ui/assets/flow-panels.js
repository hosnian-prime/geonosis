// Geonosis flow editor — side panel for node & edge configuration.
//
// Renders dynamic HTML forms inside `#gn-flow-panel` based on the
// currently selected node or edge.  All mutations feed back into
// `state.flow` and are mirrored to the JSON textarea so the canvas
// and JSON views stay in sync.
//
// Registered on `window.GnFlow`; consumed by the main flow-editor
// hydrator after it builds the shared `state` object.

(function () {
    "use strict";

    window.GnFlow = window.GnFlow || {};

    // -- Guard-key autocomplete suggestions ---------------------------

    var GUARD_KEY_HINTS = [
        "context.username",
        "context.user_id",
        "context.client_id",
        "context.amr",
        "context.authn_level",
        "context.locals.",
    ];

    // -- Shared datalist (injected once) ------------------------------

    function ensureGuardDatalist() {
        if (document.getElementById("gn-guard-keys")) return;
        var dl = document.createElement("datalist");
        dl.id = "gn-guard-keys";
        GUARD_KEY_HINTS.forEach(function (hint) {
            var opt = document.createElement("option");
            opt.value = hint;
            dl.appendChild(opt);
        });
        document.body.appendChild(dl);
    }

    // -----------------------------------------------------------------
    //  initPanels
    // -----------------------------------------------------------------

    window.GnFlow.initPanels = function initPanels(/* state */) {
        // Ensure the guard-key datalist exists in the DOM so the edge
        // panel can reference it immediately.
        ensureGuardDatalist();
    };

    // -----------------------------------------------------------------
    //  hidePanel
    // -----------------------------------------------------------------

    window.GnFlow.hidePanel = function hidePanel() {
        var panel = document.getElementById("gn-flow-panel");
        if (!panel) return;
        panel.setAttribute("hidden", "");
        panel.innerHTML = "";
    };

    // -----------------------------------------------------------------
    //  showNodePanel
    // -----------------------------------------------------------------

    window.GnFlow.showNodePanel = function showNodePanel(state, nodeId) {
        var node = findNode(state, nodeId);
        if (!node) return;

        var panel = document.getElementById("gn-flow-panel");
        if (!panel) return;

        // Determine the kind tag (string key) and the kind payload.
        var kindTag = nodeKindTag(node.kind);
        var kindPayload = nodeKindPayload(node.kind);

        // Build the panel HTML.
        var html = "";

        // -- Header ---------------------------------------------------
        html += '<div class="gn-flow-panel__header">';
        html += "  <h3>Node: " + esc(node.display_name || kindTag) + "</h3>";
        html += '  <button class="gn-flow-panel__close">&times;</button>';
        html += "</div>";

        // -- Body -----------------------------------------------------
        html += '<div class="gn-flow-panel__body">';

        // Display Name
        html += field(
            "Display Name",
            '<input class="gn-input" data-field="display_name" value="' +
                escAttr(node.display_name || "") +
                '">'
        );

        // Requirement
        html += field(
            "Requirement",
            '<select class="gn-input" data-field="requirement">' +
                option("required", "Required", node.requirement) +
                option("optional", "Optional", node.requirement) +
                option("alternative", "Alternative", node.requirement) +
                option("disabled", "Disabled", node.requirement) +
                "</select>"
        );

        // Kind-specific fields
        html += renderKindFields(kindTag, kindPayload);

        // Node ID (readonly)
        html += field(
            "Node ID",
            '<input class="gn-input gn-mono" readonly value="' +
                escAttr(node.id) +
                '">'
        );

        // Divider + delete
        html += '<hr class="gn-flow-panel__divider">';
        html +=
            '<button class="gn-btn gn-btn--danger gn-btn--sm" data-action="delete-node">Delete Node</button>';

        html += "</div>"; // .gn-flow-panel__body

        panel.innerHTML = html;
        panel.removeAttribute("hidden");

        // -- Event wiring ---------------------------------------------

        // Close button
        panel
            .querySelector(".gn-flow-panel__close")
            .addEventListener("click", function () {
                window.GnFlow.hidePanel();
            });

        // Delete button
        var delBtn = panel.querySelector('[data-action="delete-node"]');
        if (delBtn) {
            delBtn.addEventListener("click", function () {
                if (window.GnFlow.deleteNode) {
                    window.GnFlow.deleteNode(state, nodeId);
                }
                window.GnFlow.hidePanel();
            });
        }

        // Input / change handlers on all editable fields
        panel.querySelectorAll("[data-field]").forEach(function (el) {
            var evName = el.tagName === "SELECT" ? "change" : "input";
            el.addEventListener(evName, function () {
                applyNodeFieldChange(state, nodeId, el);
            });
        });
    };

    // -----------------------------------------------------------------
    //  showEdgePanel
    // -----------------------------------------------------------------

    window.GnFlow.showEdgePanel = function showEdgePanel(state, fromId, toId) {
        var edge = findEdge(state, fromId, toId);
        if (!edge) return;

        var panel = document.getElementById("gn-flow-panel");
        if (!panel) return;

        var fromNode = findNode(state, fromId);
        var toNode = findNode(state, toId);
        var fromName = fromNode
            ? fromNode.display_name || nodeKindTag(fromNode.kind)
            : fromId;
        var toName = toNode
            ? toNode.display_name || nodeKindTag(toNode.kind)
            : toId;

        // Decode the current `on` value.
        var onInfo = decodeEdgeOn(edge.on);

        var html = "";

        // -- Header ---------------------------------------------------
        html += '<div class="gn-flow-panel__header">';
        html +=
            "  <h3>Edge: " + esc(fromName) + " &rarr; " + esc(toName) + "</h3>";
        html += '  <button class="gn-flow-panel__close">&times;</button>';
        html += "</div>";

        // -- Body -----------------------------------------------------
        html += '<div class="gn-flow-panel__body">';

        // Condition select
        html += field(
            "Condition",
            '<select class="gn-input" data-field="on">' +
                option("otherwise", "Otherwise", onInfo.tag) +
                option("success", "Success", onInfo.tag) +
                option("failure", "Failure", onInfo.tag) +
                option("status", "Status", onInfo.tag) +
                "</select>"
        );

        // Status sub-input (visible only when "status" is selected)
        var statusHidden = onInfo.tag !== "status" ? " hidden" : "";
        html +=
            '<div class="gn-field" data-status-row' +
            statusHidden +
            ">" +
            '<label class="gn-field__label">Status Value</label>' +
            '<input class="gn-input" data-field="on-status" value="' +
            escAttr(onInfo.statusValue) +
            '">' +
            "</div>";

        // Guard editor
        html += '<div class="gn-field">';
        html += '<label class="gn-field__label">Guards</label>';
        html += '<div data-guard-list>';
        html += renderGuardRows(edge.guard);
        html += "</div>";
        html +=
            '<button class="gn-btn gn-btn--sm" data-action="add-guard">+ Add guard</button>';
        html += "</div>";

        // Edge IDs (readonly)
        html += field(
            "From",
            '<input class="gn-input gn-mono" readonly value="' +
                escAttr(fromId) +
                '">'
        );
        html += field(
            "To",
            '<input class="gn-input gn-mono" readonly value="' +
                escAttr(toId) +
                '">'
        );

        // Divider + delete
        html += '<hr class="gn-flow-panel__divider">';
        html +=
            '<button class="gn-btn gn-btn--danger gn-btn--sm" data-action="delete-edge">Delete Edge</button>';

        html += "</div>"; // .gn-flow-panel__body

        panel.innerHTML = html;
        panel.removeAttribute("hidden");

        // -- Event wiring ---------------------------------------------

        // Close button
        panel
            .querySelector(".gn-flow-panel__close")
            .addEventListener("click", function () {
                window.GnFlow.hidePanel();
            });

        // Delete button
        var delBtn = panel.querySelector('[data-action="delete-edge"]');
        if (delBtn) {
            delBtn.addEventListener("click", function () {
                if (window.GnFlow.deleteEdge) {
                    window.GnFlow.deleteEdge(state, fromId, toId);
                }
                window.GnFlow.hidePanel();
            });
        }

        // Condition select
        var condSelect = panel.querySelector('[data-field="on"]');
        var statusRow = panel.querySelector("[data-status-row]");
        var statusInput = panel.querySelector('[data-field="on-status"]');

        if (condSelect) {
            condSelect.addEventListener("change", function () {
                var tag = condSelect.value;
                // Toggle status sub-input visibility
                if (statusRow) {
                    if (tag === "status") {
                        statusRow.removeAttribute("hidden");
                    } else {
                        statusRow.setAttribute("hidden", "");
                    }
                }
                applyEdgeOnChange(state, fromId, toId, tag, statusInput);
            });
        }

        if (statusInput) {
            statusInput.addEventListener("input", function () {
                applyEdgeOnChange(state, fromId, toId, "status", statusInput);
            });
        }

        // Guard inputs — use delegation because rows can be added/removed
        var guardList = panel.querySelector("[data-guard-list]");
        if (guardList) {
            guardList.addEventListener("input", function () {
                syncGuardsFromDom(state, fromId, toId, guardList);
            });
            guardList.addEventListener("click", function (ev) {
                if (ev.target.closest("[data-action='remove-guard']")) {
                    ev.target.closest(".gn-flow-guard-row").remove();
                    syncGuardsFromDom(state, fromId, toId, guardList);
                }
            });
        }

        // Add guard button
        var addGuardBtn = panel.querySelector('[data-action="add-guard"]');
        if (addGuardBtn && guardList) {
            addGuardBtn.addEventListener("click", function () {
                guardList.insertAdjacentHTML("beforeend", guardRow("", ""));
            });
        }
    };

    // =================================================================
    //  Node field helpers
    // =================================================================

    /** Apply a field change from the panel back into state.flow */
    function applyNodeFieldChange(state, nodeId, el) {
        var node = findNode(state, nodeId);
        if (!node) return;

        var fieldName = el.dataset.field;
        var value =
            el.type === "checkbox" ? el.checked : el.value;

        // Top-level fields
        if (fieldName === "display_name" || fieldName === "requirement") {
            node[fieldName] = value;

            // If display_name changed, also update the SVG label text.
            if (fieldName === "display_name" && state.nodeGroups) {
                var g = state.nodeGroups.get(nodeId);
                if (g) {
                    var title = g.querySelector(".gn-flow-node__title");
                    if (title) title.textContent = value;
                }
                // Update the panel header too.
                var header = document.querySelector(
                    "#gn-flow-panel .gn-flow-panel__header h3"
                );
                if (header) header.textContent = "Node: " + value;
            }
        } else {
            // Kind-specific field — update the kind payload.
            setKindField(node, fieldName, value);
        }

        mirrorToTextarea(state);
    }

    /** Write a kind-specific field into `node.kind`.
     *  Internally-tagged: {kind: "start", require_session: false}
     *  Fields are siblings of the `kind` discriminator. */
    function setKindField(node, fieldName, value) {
        if (!node.kind) return;
        if (typeof node.kind === "object") {
            node.kind[fieldName] = value;
        }
    }

    // =================================================================
    //  Edge helpers
    // =================================================================

    function applyEdgeOnChange(state, fromId, toId, tag, statusInput) {
        var edge = findEdge(state, fromId, toId);
        if (!edge) return;

        if (tag === "status") {
            var sv = statusInput ? statusInput.value : "";
            edge.on = { status: sv };
        } else {
            edge.on = tag;
        }

        // Update the SVG edge label if present.
        updateEdgeLabel(state, fromId, toId, edgeOnLabel(edge.on));

        mirrorToTextarea(state);
    }

    /** Sync all guard rows from the DOM back into edge.guard. */
    function syncGuardsFromDom(state, fromId, toId, guardList) {
        var edge = findEdge(state, fromId, toId);
        if (!edge) return;

        var guard = {};
        guardList.querySelectorAll(".gn-flow-guard-row").forEach(function (row) {
            var keyInput = row.querySelector("[data-guard-key]");
            var valInput = row.querySelector("[data-guard-value]");
            if (!keyInput || !valInput) return;
            var k = keyInput.value.trim();
            if (!k) return;

            // Try to parse the value as JSON; fall back to raw string.
            var raw = valInput.value;
            var parsed;
            try {
                parsed = JSON.parse(raw);
            } catch (e) {
                parsed = raw;
            }
            guard[k] = parsed;
        });

        edge.guard = Object.keys(guard).length ? guard : {};
        mirrorToTextarea(state);
    }

    function updateEdgeLabel(state, fromId, toId, text) {
        if (!state.edgeGroups) return;
        var key = fromId + "->" + toId;
        var groups = state.edgeGroups.get(key);
        if (!groups) return;
        groups.forEach(function (g) {
            var label = g.querySelector(".gn-flow-edge__label");
            if (label) label.textContent = text;
        });
    }

    // =================================================================
    //  Kind-specific field renderers
    // =================================================================

    function renderKindFields(kindTag, payload) {
        switch (kindTag) {
            case "start":
                return toggle(
                    "require_session",
                    "Require Session",
                    !!(payload && payload.require_session)
                );

            case "render":
                return textField("template", "Template", payload);

            case "authenticator":
                return textField("provider_urn", "Provider URN", payload);

            case "broker":
                return textField("idp_alias", "IdP Alias", payload);

            case "switch":
                return textField("condition", "Condition", payload);

            case "sub-flow":
                return textField("flow_alias", "Flow Alias", payload);

            case "action":
                return textField("action", "Action", payload);

            case "success":
                return (
                    field(
                        "ACR",
                        '<input class="gn-input" data-field="acr" placeholder="e.g. urn:..." value="' +
                            escAttr((payload && payload.acr) || "") +
                            '">'
                    ) +
                    toggle(
                        "step_up_required",
                        "Step-Up Required",
                        !!(payload && payload.step_up_required)
                    )
                );

            case "failure":
                return textField("reason", "Reason", payload);

            default:
                return "";
        }
    }

    // =================================================================
    //  Tiny template helpers
    // =================================================================

    /** Wrap a label + control in a `.gn-field`. */
    function field(label, controlHtml) {
        return (
            '<div class="gn-field">' +
            '<label class="gn-field__label">' +
            esc(label) +
            "</label>" +
            controlHtml +
            "</div>"
        );
    }

    /** Convenience: text input field for a kind-specific property. */
    function textField(fieldName, label, payload) {
        var val = (payload && payload[fieldName]) || "";
        return field(
            label,
            '<input class="gn-input" data-field="' +
                escAttr(fieldName) +
                '" value="' +
                escAttr(val) +
                '">'
        );
    }

    /** Checkbox toggle wrapped in `.gn-field`. */
    function toggle(fieldName, label, checked) {
        return (
            '<div class="gn-field">' +
            '<label class="gn-field__label">' +
            '<input type="checkbox" data-field="' +
            escAttr(fieldName) +
            '"' +
            (checked ? " checked" : "") +
            "> " +
            esc(label) +
            "</label>" +
            "</div>"
        );
    }

    /** A single `<option>` element, selected if `current` matches `val`. */
    function option(val, label, current) {
        return (
            '<option value="' +
            escAttr(val) +
            '"' +
            (current === val ? " selected" : "") +
            ">" +
            esc(label) +
            "</option>"
        );
    }

    /** Render existing guard entries as key-value rows. */
    function renderGuardRows(guard) {
        if (!guard || typeof guard !== "object") return "";
        var html = "";
        Object.keys(guard).forEach(function (k) {
            var v = guard[k];
            var display =
                typeof v === "string" ? v : JSON.stringify(v);
            html += guardRow(k, display);
        });
        return html;
    }

    /** A single guard key-value row. */
    function guardRow(key, value) {
        return (
            '<div class="gn-flow-guard-row">' +
            '<input class="gn-input" data-guard-key list="gn-guard-keys" placeholder="context.username" value="' +
            escAttr(key) +
            '">' +
            '<input class="gn-input" data-guard-value placeholder="value (JSON)" value="' +
            escAttr(value) +
            '">' +
            '<button class="gn-btn gn-btn--sm" data-action="remove-guard">&times;</button>' +
            "</div>"
        );
    }

    // =================================================================
    //  Edge `on` encode / decode
    // =================================================================

    /** Decode `edge.on` into { tag, statusValue }. */
    function decodeEdgeOn(on) {
        if (typeof on === "string") {
            return { tag: on, statusValue: "" };
        }
        if (on && typeof on === "object" && on.status !== undefined) {
            return { tag: "status", statusValue: on.status || "" };
        }
        return { tag: "otherwise", statusValue: "" };
    }

    /** Human-readable label for an `on` value (used in SVG edge labels). */
    function edgeOnLabel(on) {
        if (typeof on === "string") return on;
        if (on && typeof on === "object" && on.status !== undefined) {
            return "status: " + on.status;
        }
        return "otherwise";
    }

    // =================================================================
    //  Lookup utilities
    // =================================================================

    function findNode(state, nodeId) {
        if (!state.flow || !Array.isArray(state.flow.nodes)) return null;
        return state.flow.nodes.find(function (n) {
            return n.id === nodeId;
        }) || null;
    }

    function findEdge(state, fromId, toId) {
        if (!state.flow || !Array.isArray(state.flow.edges)) return null;
        return state.flow.edges.find(function (e) {
            return e.from === fromId && e.to === toId;
        }) || null;
    }

    /** Extract the kind tag string (e.g. "start", "render").
     *  Rust uses internally-tagged enum: { kind: "start", require_session: false } */
    function nodeKindTag(kind) {
        if (!kind) return "unknown";
        if (typeof kind === "string") return kind;
        return kind.kind || "unknown";
    }

    /** The kind object IS the payload for internally-tagged enums.
     *  Fields are siblings of the `kind` discriminator. */
    function nodeKindPayload(kind) {
        if (!kind) return null;
        if (typeof kind === "string") return null;
        return kind;
    }

    // =================================================================
    //  Mirror helper (same pattern as flow-editor.js)
    // =================================================================

    function mirrorToTextarea(state) {
        var textarea = document.getElementById("gn-flow-json-textarea");
        if (!textarea) return;
        try {
            textarea.value = JSON.stringify(state.flow, null, 2);
        } catch (e) {
            // Leave the textarea as-is.
        }
    }

    // =================================================================
    //  Escaping
    // =================================================================

    function esc(str) {
        var div = document.createElement("div");
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }

    function escAttr(str) {
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/"/g, "&quot;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;");
    }
})();
