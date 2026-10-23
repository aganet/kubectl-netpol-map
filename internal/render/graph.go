package render

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/aganet/kubectl-netpol-map/internal/policy"
)

// graphEdge is one source→destination relationship destined for a graph
// renderer. Edges that are pure default-allow (no policy applied) are dropped
// before reaching here so the graph shows intent, not the open-by-default
// baseline.
type graphEdge struct {
	src, dst string
	verdict  graphVerdict
	ports    []string
}

type graphVerdict int

const (
	gvAllow graphVerdict = iota
	gvDeny
	gvPartial
	gvUnknown
)

// collectGraphEdges flattens a matrix into graph edges, honouring the
// namespace filter and --denies-only, and skipping self + boring edges.
func collectGraphEdges(m *policy.Matrix, view matrixView, opts Options) []graphEdge {
	rowIdx := indexBy(m.Rows)
	colIdx := indexBy(m.Cols)

	var edges []graphEdge
	for _, src := range view.Rows {
		si, ok := rowIdx[src.Display()]
		if !ok {
			continue
		}
		for _, dst := range view.Cols {
			dj, ok := colIdx[dst.Display()]
			if !ok {
				continue
			}
			cell := m.Cells[si][dj]
			if cell.IsSelf || isBoring(cell) {
				continue
			}
			if opts.DeniesOnly && cell.Allowed && !cell.Partial {
				continue
			}
			gv := gvAllow
			switch {
			case cell.Unknown:
				gv = gvUnknown
			case cell.Partial:
				gv = gvPartial
			case !cell.Allowed:
				gv = gvDeny
			}
			edges = append(edges, graphEdge{
				src:     src.Display(),
				dst:     dst.Display(),
				verdict: gv,
				ports:   cell.Ports,
			})
		}
	}
	sort.SliceStable(edges, func(i, j int) bool {
		if edges[i].src != edges[j].src {
			return edges[i].src < edges[j].src
		}
		return edges[i].dst < edges[j].dst
	})
	return edges
}

// nodeID returns a stable, syntactically-safe identifier for a node display
// name, plus registers it. Both Mermaid and DOT need alphanumeric IDs.
func sanitizeID(name string) string {
	var b strings.Builder
	b.WriteString("n_")
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func portLabel(ports []string) string {
	if len(ports) == 0 || (len(ports) == 1 && ports[0] == "*") {
		return ""
	}
	return ":" + strings.Join(policy.DisplayPorts(ports), ",")
}

func namespaceOf(display string) string {
	if i := strings.IndexByte(display, '/'); i >= 0 {
		return display[:i]
	}
	return ""
}

// Mermaid renders the reachability graph as a Mermaid flowchart. Nodes are
// grouped into one subgraph per namespace; edges are coloured by verdict.
// The output pastes directly into Markdown / Confluence fenced ```mermaid
// blocks, which is the primary audit-reporting use case.
func Mermaid(w io.Writer, m *policy.Matrix) error {
	return MermaidWithOptions(w, m, Options{})
}

func MermaidWithOptions(w io.Writer, m *policy.Matrix, opts Options) error {
	view := applyNamespaceFilter(m)
	edges := collectGraphEdges(m, view, opts)

	fmt.Fprintln(w, "flowchart LR")
	fmt.Fprintln(w, "  %% kubectl-netpol-map reachability graph")

	// Collect nodes per namespace (only nodes that appear in an edge).
	nsNodes := map[string]map[string]string{} // ns -> display -> id
	addNode := func(display string) {
		ns := namespaceOf(display)
		if nsNodes[ns] == nil {
			nsNodes[ns] = map[string]string{}
		}
		nsNodes[ns][display] = sanitizeID(display)
	}
	for _, e := range edges {
		addNode(e.src)
		addNode(e.dst)
	}

	nsList := make([]string, 0, len(nsNodes))
	for ns := range nsNodes {
		nsList = append(nsList, ns)
	}
	sort.Strings(nsList)
	for _, ns := range nsList {
		label := ns
		if label == "" {
			label = "(cluster)"
		}
		fmt.Fprintf(w, "  subgraph %s[\"%s\"]\n", sanitizeID("ns_"+ns), label)
		names := make([]string, 0, len(nsNodes[ns]))
		for d := range nsNodes[ns] {
			names = append(names, d)
		}
		sort.Strings(names)
		for _, d := range names {
			fmt.Fprintf(w, "    %s[\"%s\"]\n", nsNodes[ns][d], shortNodeLabel(d))
		}
		fmt.Fprintln(w, "  end")
	}

	idOf := func(display string) string {
		return nsNodes[namespaceOf(display)][display]
	}
	for i, e := range edges {
		arrow := "-->"
		lbl := portLabel(e.ports)
		switch e.verdict {
		case gvDeny:
			arrow = "-.->"
			lbl = "DENY"
		case gvPartial:
			if lbl == "" {
				lbl = "PARTIAL"
			} else {
				lbl = "PARTIAL" + lbl
			}
		case gvUnknown:
			arrow = "-.->"
			lbl = "UNKNOWN"
		}
		if lbl == "" {
			fmt.Fprintf(w, "  %s %s %s\n", idOf(e.src), arrow, idOf(e.dst))
		} else {
			fmt.Fprintf(w, "  %s %s|%s| %s\n", idOf(e.src), arrow, lbl, idOf(e.dst))
		}
		// Colour the edge by verdict via linkStyle (index = edge order).
		switch e.verdict {
		case gvAllow:
			fmt.Fprintf(w, "  linkStyle %d stroke:#2e7d32,stroke-width:2px;\n", i)
		case gvDeny:
			fmt.Fprintf(w, "  linkStyle %d stroke:#c62828,stroke-width:1px;\n", i)
		case gvPartial:
			fmt.Fprintf(w, "  linkStyle %d stroke:#f9a825,stroke-width:2px;\n", i)
		case gvUnknown:
			fmt.Fprintf(w, "  linkStyle %d stroke:#f9a825,stroke-width:1px,stroke-dasharray:3;\n", i)
		}
	}
	return nil
}

// Dot renders the reachability graph as Graphviz DOT. Same grouping and
// colouring as Mermaid; pipe through `dot -Tsvg` for an image.
func Dot(w io.Writer, m *policy.Matrix) error {
	return DotWithOptions(w, m, Options{})
}

func DotWithOptions(w io.Writer, m *policy.Matrix, opts Options) error {
	view := applyNamespaceFilter(m)
	edges := collectGraphEdges(m, view, opts)

	fmt.Fprintln(w, `digraph "netpol-map" {`)
	fmt.Fprintln(w, "  rankdir=LR;")
	fmt.Fprintln(w, "  node [shape=box,style=rounded,fontname=\"Helvetica\"];")

	nsNodes := map[string]map[string]string{}
	addNode := func(display string) {
		ns := namespaceOf(display)
		if nsNodes[ns] == nil {
			nsNodes[ns] = map[string]string{}
		}
		nsNodes[ns][display] = sanitizeID(display)
	}
	for _, e := range edges {
		addNode(e.src)
		addNode(e.dst)
	}

	nsList := make([]string, 0, len(nsNodes))
	for ns := range nsNodes {
		nsList = append(nsList, ns)
	}
	sort.Strings(nsList)
	for _, ns := range nsList {
		label := ns
		if label == "" {
			label = "(cluster)"
		}
		fmt.Fprintf(w, "  subgraph cluster_%s {\n", sanitizeID(ns))
		fmt.Fprintf(w, "    label=\"%s\"; style=dashed; color=gray;\n", label)
		names := make([]string, 0, len(nsNodes[ns]))
		for d := range nsNodes[ns] {
			names = append(names, d)
		}
		sort.Strings(names)
		for _, d := range names {
			fmt.Fprintf(w, "    %s [label=\"%s\"];\n", nsNodes[ns][d], shortNodeLabel(d))
		}
		fmt.Fprintln(w, "  }")
	}

	idOf := func(display string) string {
		return nsNodes[namespaceOf(display)][display]
	}
	for _, e := range edges {
		var attrs string
		switch e.verdict {
		case gvAllow:
			lbl := portLabel(e.ports)
			attrs = fmt.Sprintf("color=\"#2e7d32\",penwidth=2,label=\"%s\"", strings.TrimPrefix(lbl, ":"))
		case gvDeny:
			attrs = "color=\"#c62828\",style=dashed,label=\"DENY\""
		case gvPartial:
			attrs = "color=\"#f9a825\",penwidth=2,label=\"PARTIAL\""
		case gvUnknown:
			attrs = "color=\"#f9a825\",style=dotted,label=\"UNKNOWN\""
		}
		fmt.Fprintf(w, "  %s -> %s [%s];\n", idOf(e.src), idOf(e.dst), attrs)
	}
	fmt.Fprintln(w, "}")
	return nil
}

// shortNodeLabel strips the namespace prefix from a node display name for
// use inside a namespace subgraph (where the namespace is already the
// subgraph title). "ns/Kind/Name" -> "Kind/Name"; "ns/pod" -> "pod".
func shortNodeLabel(display string) string {
	if i := strings.IndexByte(display, '/'); i >= 0 {
		return display[i+1:]
	}
	return display
}
