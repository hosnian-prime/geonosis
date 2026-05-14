// Geonosis flow editor (v0.1 island).
//
// The doc calls out the flow editor as the *only* admin page that needs
// extensive client-side state and hydration. v0.1 ships a minimal
// canvas/SVG-based renderer that visualises a compiled `FlowDefinition`
// loaded from `/admin/v1/realms/{slug}/flows/{alias}`. Editing is a
// follow-up; the GET-only view already covers the operator's "did my
// config apply?" use case and is the foundation the editor lands on
// in v0.1.x.

(function () {
    const node = document.getElementById("gn-flow-canvas");
    if (!node) return;
    const realm = node.dataset.realm;
    const alias = node.dataset.alias;
    if (!realm || !alias) return;

    fetch(`/admin/v1/realms/${encodeURIComponent(realm)}/flows/${encodeURIComponent(alias)}`)
        .then((r) => r.json())
        .then((flow) => render(flow))
        .catch((e) => {
            node.textContent = `Failed to load flow: ${e}`;
        });

    function render(flow) {
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
            line.setAttribute("stroke", "#4f8cff");
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
            rect.setAttribute("fill", "#161a22");
            rect.setAttribute("stroke", "#2a2f3b");
            svg.appendChild(rect);
            const text = document.createElementNS(ns, "text");
            text.setAttribute("x", p.x);
            text.setAttribute("y", p.y + 5);
            text.setAttribute("text-anchor", "middle");
            text.setAttribute("fill", "#f5f5f7");
            text.setAttribute("font-size", "12");
            text.textContent = n.display_name || nodeKindLabel(n.kind);
            svg.appendChild(text);
        }
        node.innerHTML = "";
        node.appendChild(svg);
    }

    function layoutGrid(nodes) {
        // Naive column-major layout. Good enough to confirm "yes the
        // graph parsed"; the real editor will track positions on the
        // node row itself.
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
