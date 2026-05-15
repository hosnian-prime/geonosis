// Geonosis flow dry-run — context form, outcome pinning, API call, trace.
//
// This module provides dry-run integration for the flow editor. An
// operator can fill in a simulated authentication context, pin expected
// outcomes on individual nodes, and POST the configuration to the
// server's dry-run endpoint. The response (a DryRunReport) is then
// visualised as a highlighted trace on the SVG canvas.
//
// Registration: all public functions live on `window.GnFlow` so that
// flow-editor.js (and future modules) can call them without imports.
//
// No imports, no bundler. Targets evergreen browsers.

(function () {
    "use strict";

    var GnFlow = window.GnFlow = window.GnFlow || {};

    // ── Constants ────────────────────────────────────────────────────

    /** Outcome cycle order when clicking a node to pin an outcome. */
    var OUTCOME_CYCLE = ["success", "failure", "skip"];

    /** Visual labels for each outcome (single character for the badge). */
    var OUTCOME_LABELS = { success: "S", failure: "F", skip: "K" };

    /** Badge background colours per outcome. */
    var OUTCOME_COLORS = { success: "#16a34a", failure: "#dc2626", skip: "#ea580c" };

    /** Banner classes per terminal status. */
    var TERMINAL_CLASS = {
        success:    "gn-flow-dryrun__banner--success",
        failure:    "gn-flow-dryrun__banner--failure",
        incomplete: "gn-flow-dryrun__banner--incomplete",
    };

    /** Banner text per terminal status. */
    var TERMINAL_TEXT = {
        success: "Flow reached Success",
        failure: "Flow reached Failure",
    };

    // ── Public API ───────────────────────────────────────────────────

    /**
     * Initialise the dry-run subsystem.
     *
     * Sets up state fields, renders the configuration panel inside
     * `#gn-flow-dryrun`, and attaches event listeners.
     *
     * @param {Object} state - Shared editor state.
     */
    GnFlow.initDryRun = function initDryRun(state) {
        state.dryRunActive = false;
        state.pinnedOutcomes = {};
        state.dryRunOverlay = null;

        var panel = document.getElementById("gn-flow-dryrun");
        if (!panel) return;

        panel.innerHTML = buildPanelHTML();
        attachPanelListeners(state, panel);
    };

    /**
     * Toggle the dry-run mode on/off.
     *
     * When activating, the panel is shown and nodes become clickable
     * for outcome pinning. When deactivating, all overlays are cleared.
     *
     * @param {Object} state - Shared editor state.
     */
    GnFlow.toggleDryRun = function toggleDryRun(state) {
        state.dryRunActive = !state.dryRunActive;

        var panel = document.getElementById("gn-flow-dryrun");
        if (panel) {
            panel.hidden = !state.dryRunActive;
        }

        // Update the toolbar button's aria-pressed attribute.
        var btn = state.root
            ? state.root.querySelector('[data-flow-action="dry-run"]')
            : null;
        if (btn) {
            btn.setAttribute("aria-pressed", state.dryRunActive ? "true" : "false");
        }

        if (!state.dryRunActive) {
            GnFlow.clearDryRunOverlay(state);
        }
    };

    /**
     * Cycle the pinned outcome for a node.
     *
     * Cycles through: (none) -> success -> failure -> skip -> (none).
     * Updates the visual badge on the SVG node.
     *
     * @param {Object} state  - Shared editor state.
     * @param {string} nodeId - ID of the node to pin.
     */
    GnFlow.pinOutcome = function pinOutcome(state, nodeId) {
        var current = state.pinnedOutcomes[nodeId] || null;
        var idx = current ? OUTCOME_CYCLE.indexOf(current) : -1;
        var next = idx < OUTCOME_CYCLE.length - 1
            ? OUTCOME_CYCLE[idx + 1]
            : null; // wrap back to "none"

        if (next) {
            state.pinnedOutcomes[nodeId] = next;
        } else {
            delete state.pinnedOutcomes[nodeId];
        }

        renderOutcomeBadge(state, nodeId, next);
    };

    /**
     * Execute a dry-run request against the server.
     *
     * Gathers context from the form, builds the request body, POSTs
     * to the configured endpoint, and visualises the trace on success.
     *
     * @param {Object} state - Shared editor state.
     * @returns {Promise<void>}
     */
    GnFlow.runDryRun = async function runDryRun(state) {
        var endpoint = state.root ? state.root.dataset.dryrunAction : null;
        if (!endpoint) {
            showError(state, "No dry-run endpoint configured (data-dryrun-action).");
            return;
        }

        var context = gatherContext();
        var body = {
            context: context,
            expected_outcomes: Object.assign({}, state.pinnedOutcomes),
        };

        // Disable Run button while the request is in-flight.
        var runBtn = document.querySelector('[data-action="run-dryrun"]');
        if (runBtn) runBtn.disabled = true;

        try {
            var resp = await fetch(endpoint, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
            });

            if (!resp.ok) {
                var errText = await resp.text();
                showError(state, "Dry-run failed (" + resp.status + "): " + errText);
                return;
            }

            var report = await resp.json();
            GnFlow.showTrace(state, report);
        } catch (err) {
            showError(state, "Network error: " + err.message);
        } finally {
            if (runBtn) runBtn.disabled = false;
        }
    };

    /**
     * Visualise a DryRunReport on the canvas.
     *
     * Dims all nodes/edges, highlights the traced path, adds step
     * number badges, and renders the result summary in the panel.
     *
     * @param {Object} state  - Shared editor state.
     * @param {Object} report - DryRunReport from the server.
     */
    GnFlow.showTrace = function showTrace(state, report) {
        state.dryRunOverlay = report;

        // --- Result banner -------------------------------------------

        var resultEl = document.querySelector("[data-dryrun-result]");
        if (resultEl) {
            var cls = TERMINAL_CLASS[report.terminal] || TERMINAL_CLASS.incomplete;
            var text = TERMINAL_TEXT[report.terminal]
                || ("Incomplete: " + (report.reason || "unknown"));
            resultEl.innerHTML =
                '<div class="gn-flow-dryrun__banner ' + cls + '">' +
                escapeHtml(text) + "</div>";
            resultEl.hidden = false;
        }

        // --- Steps list in panel -------------------------------------

        var stepsEl = document.querySelector("[data-dryrun-steps]");
        if (stepsEl && Array.isArray(report.steps)) {
            var items = report.steps.map(function (step, i) {
                var label = (i + 1) + ". " + capitalize(step.kind);
                var detail = step.decision + ": " + (step.reason || "");
                return "<li><strong>" + escapeHtml(label) + "</strong> &mdash; " +
                    escapeHtml(detail) + "</li>";
            });
            stepsEl.innerHTML =
                '<ol class="gn-flow-dryrun__step-list">' + items.join("") + "</ol>";
            stepsEl.hidden = false;
        }

        // --- Canvas trace overlay ------------------------------------

        if (!state.svg) return;

        // 1. Dim everything first.
        dimAll(state);

        // 2. Build a set of traced node IDs for quick lookup.
        var tracedNodeIds = new Set();
        var steps = report.steps || [];
        steps.forEach(function (step) {
            tracedNodeIds.add(step.node_id);
        });

        // 3. Highlight traced nodes and add step-number badges.
        steps.forEach(function (step, i) {
            var g = state.nodeGroups ? state.nodeGroups.get(step.node_id) : null;
            if (!g) return;

            g.classList.remove("gn-flow-node--dimmed");

            if (step.decision === "taken") {
                g.classList.add("gn-flow-node--traced-taken");
            } else {
                g.classList.add("gn-flow-node--traced-skipped");
            }

            // Step number badge (top-left circle).
            addStepBadge(g, i + 1);
        });

        // 4. Highlight edges between consecutive traced steps.
        for (var i = 1; i < steps.length; i++) {
            var fromId = steps[i - 1].node_id;
            var toId = steps[i].node_id;
            var key = fromId + "->" + toId;
            var edgeGroups = state.edgeGroups ? state.edgeGroups.get(key) : null;
            if (edgeGroups) {
                edgeGroups.forEach(function (eg) {
                    eg.classList.remove("gn-flow-edge--dimmed");
                    eg.classList.add("gn-flow-edge--traced");
                });
            }
        }
    };

    /**
     * Remove all dry-run trace overlays from the canvas.
     *
     * Clears dimming classes, step badges, outcome badges, and resets
     * the panel result/steps areas.
     *
     * @param {Object} state - Shared editor state.
     */
    GnFlow.clearDryRunOverlay = function clearDryRunOverlay(state) {
        state.dryRunOverlay = null;
        state.pinnedOutcomes = {};

        // Remove trace classes from nodes.
        if (state.nodeGroups) {
            state.nodeGroups.forEach(function (g, nodeId) {
                g.classList.remove(
                    "gn-flow-node--dimmed",
                    "gn-flow-node--traced-taken",
                    "gn-flow-node--traced-skipped"
                );
                removeStepBadge(g);
                removeOutcomeBadge(g);
            });
        }

        // Remove trace classes from edges.
        if (state.edgeGroups) {
            state.edgeGroups.forEach(function (groups) {
                groups.forEach(function (eg) {
                    eg.classList.remove(
                        "gn-flow-edge--dimmed",
                        "gn-flow-edge--traced"
                    );
                });
            });
        }

        // Clear panel sections.
        var resultEl = document.querySelector("[data-dryrun-result]");
        if (resultEl) {
            resultEl.innerHTML = "";
            resultEl.hidden = true;
        }
        var stepsEl = document.querySelector("[data-dryrun-steps]");
        if (stepsEl) {
            stepsEl.innerHTML = "";
            stepsEl.hidden = true;
        }
    };

    // ── Panel HTML ───────────────────────────────────────────────────

    /**
     * Build the inner HTML for the dry-run configuration panel.
     * @returns {string}
     */
    function buildPanelHTML() {
        return (
            '<div class="gn-flow-dryrun__form">' +
                '<h4 class="gn-flow-dryrun__title">Dry Run Configuration</h4>' +
                '<div class="gn-flow-dryrun__grid">' +
                    field("Username",             "username",    "alice") +
                    field("User ID",              "user_id",     "01H...") +
                    field("Client ID",            "client_id",   "acme-web") +
                    field("AMR (comma-separated)", "amr",        "pwd, otp") +
                    fieldNumber("Authn Level",    "authn_level", "0") +
                '</div>' +
                '<div class="gn-flow-dryrun__locals">' +
                    '<label class="gn-field__label">Locals (key-value)</label>' +
                    '<div data-dryrun-locals></div>' +
                    '<button type="button" class="gn-btn gn-btn--sm gn-btn--ghost" ' +
                        'data-action="add-local">+ Add local</button>' +
                '</div>' +
                '<p class="gn-text-muted gn-text-sm">' +
                    'Click nodes on the canvas to pin expected outcomes ' +
                    '(Success/Failure/Skip).' +
                '</p>' +
                '<div class="gn-flow-dryrun__actions">' +
                    '<button type="button" class="gn-btn gn-btn--primary gn-btn--sm" ' +
                        'data-action="run-dryrun">Run</button>' +
                    '<button type="button" class="gn-btn gn-btn--sm gn-btn--ghost" ' +
                        'data-action="clear-dryrun">Clear</button>' +
                '</div>' +
            '</div>' +
            '<div class="gn-flow-dryrun__result" data-dryrun-result hidden></div>' +
            '<div class="gn-flow-dryrun__steps" data-dryrun-steps hidden></div>'
        );
    }

    /** Generate HTML for a text input field. */
    function field(label, key, placeholder) {
        return (
            '<div class="gn-field">' +
                '<label class="gn-field__label">' + escapeHtml(label) + '</label>' +
                '<input class="gn-input gn-input--sm" data-ctx="' + key + '" ' +
                    'placeholder="' + escapeHtml(placeholder) + '">' +
            '</div>'
        );
    }

    /** Generate HTML for a number input field. */
    function fieldNumber(label, key, defaultVal) {
        return (
            '<div class="gn-field">' +
                '<label class="gn-field__label">' + escapeHtml(label) + '</label>' +
                '<input class="gn-input gn-input--sm" type="number" data-ctx="' + key + '" ' +
                    'value="' + escapeHtml(defaultVal) + '">' +
            '</div>'
        );
    }

    // ── Panel event listeners ────────────────────────────────────────

    /**
     * Attach click handlers for the Run, Clear, and Add Local buttons.
     *
     * @param {Object}      state - Shared editor state.
     * @param {HTMLElement}  panel - The `#gn-flow-dryrun` container.
     */
    function attachPanelListeners(state, panel) {
        panel.addEventListener("click", function (ev) {
            var target = ev.target.closest("[data-action]");
            if (!target) return;

            var action = target.dataset.action;

            if (action === "run-dryrun") {
                GnFlow.runDryRun(state);
            } else if (action === "clear-dryrun") {
                GnFlow.clearDryRunOverlay(state);
                clearForm(panel);
            } else if (action === "add-local") {
                addLocalRow(panel);
            } else if (action === "remove-local") {
                var row = target.closest(".gn-flow-dryrun__local-row");
                if (row) row.remove();
            }
        });
    }

    // ── Locals key-value repeater ────────────────────────────────────

    /**
     * Append a new key-value row to the locals section.
     *
     * @param {HTMLElement} panel - The dry-run panel container.
     */
    function addLocalRow(panel) {
        var container = panel.querySelector("[data-dryrun-locals]");
        if (!container) return;

        var row = document.createElement("div");
        row.className = "gn-flow-dryrun__local-row";
        row.innerHTML =
            '<input class="gn-input gn-input--sm" data-local-key placeholder="key">' +
            '<input class="gn-input gn-input--sm" data-local-value placeholder="value">' +
            '<button type="button" class="gn-btn gn-btn--sm gn-btn--ghost" ' +
                'data-action="remove-local" aria-label="Remove">&times;</button>';
        container.appendChild(row);
    }

    /** Reset all form fields and remove local rows. */
    function clearForm(panel) {
        panel.querySelectorAll("[data-ctx]").forEach(function (input) {
            if (input.type === "number") {
                input.value = "0";
            } else {
                input.value = "";
            }
        });
        var locals = panel.querySelector("[data-dryrun-locals]");
        if (locals) locals.innerHTML = "";
    }

    // ── Context gathering ────────────────────────────────────────────

    /**
     * Read the dry-run context from form inputs.
     *
     * @returns {Object} Context object matching the API schema.
     */
    function gatherContext() {
        var ctx = {};
        var panel = document.getElementById("gn-flow-dryrun");
        if (!panel) return ctx;

        // Simple text/number fields.
        panel.querySelectorAll("[data-ctx]").forEach(function (input) {
            var key = input.dataset.ctx;
            var val = input.value.trim();
            if (!val) return;

            if (key === "amr") {
                // AMR is a comma-separated list of strings.
                ctx.amr = val.split(",").map(function (s) { return s.trim(); })
                    .filter(Boolean);
            } else if (key === "authn_level") {
                ctx.authn_level = parseInt(val, 10) || 0;
            } else {
                ctx[key] = val;
            }
        });

        // Locals key-value pairs.
        var locals = {};
        var hasLocals = false;
        panel.querySelectorAll(".gn-flow-dryrun__local-row").forEach(function (row) {
            var keyInput = row.querySelector("[data-local-key]");
            var valInput = row.querySelector("[data-local-value]");
            if (keyInput && valInput) {
                var k = keyInput.value.trim();
                var v = valInput.value.trim();
                if (k) {
                    locals[k] = v;
                    hasLocals = true;
                }
            }
        });
        if (hasLocals) {
            ctx.locals = locals;
        }

        return ctx;
    }

    // ── SVG badge helpers ────────────────────────────────────────────

    /**
     * Render (or remove) an outcome-pinning badge on a node's SVG group.
     *
     * The badge is a small coloured rectangle with a single-character
     * label placed at the top-right corner of the node.
     *
     * @param {Object}      state  - Shared editor state.
     * @param {string}      nodeId - Target node ID.
     * @param {string|null} outcome - "success", "failure", "skip", or null.
     */
    function renderOutcomeBadge(state, nodeId, outcome) {
        var g = state.nodeGroups ? state.nodeGroups.get(nodeId) : null;
        if (!g) return;

        // Remove any existing badge first.
        removeOutcomeBadge(g);

        if (!outcome) return;

        var ns = "http://www.w3.org/2000/svg";
        var boxW = state.boxW || 168;
        var badgeSize = 20;
        var x = boxW - badgeSize - 2;
        var y = 2;

        // Background rect.
        var rect = document.createElementNS(ns, "rect");
        rect.setAttribute("class", "gn-flow-node__outcome-bg");
        rect.setAttribute("x", x);
        rect.setAttribute("y", y);
        rect.setAttribute("width", badgeSize);
        rect.setAttribute("height", badgeSize);
        rect.setAttribute("rx", 3);
        rect.setAttribute("fill", OUTCOME_COLORS[outcome]);

        // Label text.
        var text = document.createElementNS(ns, "text");
        text.setAttribute("class", "gn-flow-node__outcome");
        text.setAttribute("x", x + badgeSize / 2);
        text.setAttribute("y", y + badgeSize / 2 + 1);
        text.setAttribute("text-anchor", "middle");
        text.setAttribute("dominant-baseline", "central");
        text.setAttribute("fill", "#fff");
        text.setAttribute("font-size", "11");
        text.setAttribute("font-weight", "600");
        text.textContent = OUTCOME_LABELS[outcome];

        g.appendChild(rect);
        g.appendChild(text);
    }

    /** Remove the outcome badge elements from a node group. */
    function removeOutcomeBadge(g) {
        g.querySelectorAll(".gn-flow-node__outcome-bg, .gn-flow-node__outcome")
            .forEach(function (el) { el.remove(); });
    }

    /**
     * Add a step-number badge (small circle at top-left) to a node group.
     *
     * @param {SVGGElement} g    - The node's SVG `<g>` element.
     * @param {number}      num  - 1-based step number.
     */
    function addStepBadge(g, num) {
        var ns = "http://www.w3.org/2000/svg";
        var r = 10;
        var cx = -4;
        var cy = -4;

        var circle = document.createElementNS(ns, "circle");
        circle.setAttribute("class", "gn-flow-node__step-bg");
        circle.setAttribute("cx", cx);
        circle.setAttribute("cy", cy);
        circle.setAttribute("r", r);
        circle.setAttribute("fill", "#2563eb");

        var text = document.createElementNS(ns, "text");
        text.setAttribute("class", "gn-flow-node__step");
        text.setAttribute("x", cx);
        text.setAttribute("y", cy + 1);
        text.setAttribute("text-anchor", "middle");
        text.setAttribute("dominant-baseline", "central");
        text.setAttribute("fill", "#fff");
        text.setAttribute("font-size", "10");
        text.setAttribute("font-weight", "700");
        text.textContent = String(num);

        g.appendChild(circle);
        g.appendChild(text);
    }

    /** Remove step-number badge elements from a node group. */
    function removeStepBadge(g) {
        g.querySelectorAll(".gn-flow-node__step-bg, .gn-flow-node__step")
            .forEach(function (el) { el.remove(); });
    }

    // ── Canvas dimming ───────────────────────────────────────────────

    /** Apply the dimmed class to every node and edge on the canvas. */
    function dimAll(state) {
        if (state.nodeGroups) {
            state.nodeGroups.forEach(function (g) {
                g.classList.add("gn-flow-node--dimmed");
            });
        }
        if (state.edgeGroups) {
            state.edgeGroups.forEach(function (groups) {
                groups.forEach(function (eg) {
                    eg.classList.add("gn-flow-edge--dimmed");
                });
            });
        }
    }

    // ── Error display ────────────────────────────────────────────────

    /**
     * Show an error message in the result area of the dry-run panel.
     *
     * @param {Object} state   - Shared editor state.
     * @param {string} message - Human-readable error text.
     */
    function showError(state, message) {
        var el = document.querySelector("[data-dryrun-result]");
        if (!el) return;
        el.innerHTML =
            '<div class="gn-flow-dryrun__banner gn-flow-dryrun__banner--failure">' +
            escapeHtml(message) + "</div>";
        el.hidden = false;
    }

    // ── Utilities ────────────────────────────────────────────────────

    /** Escape HTML special characters to prevent XSS. */
    function escapeHtml(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    /** Capitalise the first letter of a string. */
    function capitalize(str) {
        if (!str) return "";
        return str.charAt(0).toUpperCase() + str.slice(1);
    }

})();
