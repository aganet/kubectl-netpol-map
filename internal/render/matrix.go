package render

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/aganet/kubectl-netpol-map/internal/policy"
)

// Options controls verbosity and filtering knobs that affect rendering only.
// Evaluation results (m.Cells) are unchanged; we slice/collapse what we show.
type Options struct {
	DeniesOnly  bool // hide ALLOW edges; show only DENY and PARTIAL
	ShowAllowed bool // render sub-matrices that are entirely default-allow
	ExpandEdges bool // list every cross-namespace edge (skip collapsing)
	FullWhy     bool // list every edge in Why? instead of aggregating reasons
	Verbose     bool // include policy inventory + full legend
}

// Matrix renders with default (terse) options.
func Matrix(w io.Writer, m *policy.Matrix) error {
	return MatrixWithOptions(w, m, Options{})
}

// MatrixWithOptions renders a reachability matrix. The default is terse: no
// policy inventory, no all-allow sub-matrices, collapsed cross-namespace
// edges. Flip Options.Verbose / ShowAllowed / ExpandEdges to opt back in.
func MatrixWithOptions(w io.Writer, m *policy.Matrix, opts Options) error {
	view := applyNamespaceFilter(m)
	if len(view.Rows) == 0 || len(view.Cols) == 0 {
		fmt.Fprintln(w, "no pods in selection")
		return nil
	}

	printHeader(w, m, view, opts)
	fmt.Fprintln(w)
	if opts.Verbose {
		printStandardPolicies(w, m)
		fmt.Fprintln(w)
		printCiliumPolicies(w, m)
		fmt.Fprintln(w)
	}
	printTable(w, m, view, opts)
	fmt.Fprintln(w)
	printExternalEgress(w, m)
	printLegend(w, opts)
	fmt.Fprintln(w)
	printExplanations(w, m, view, opts)
	return nil
}

// printExternalEgress lists allow-listed egress to non-pod destinations
// (external FQDNs, CIDRs, entities). Only shown when populated — i.e. when
// --resolve-fqdn or CIDR/entity rules are in scope.
func printExternalEgress(w io.Writer, m *policy.Matrix) {
	if len(m.ExternalEgress) == 0 {
		return
	}
	fmt.Fprintln(w, text.Bold.Sprintf("External egress  (%d allow-listed non-pod destinations)", len(m.ExternalEgress)))
	fmt.Fprintln(w, text.Faint.Sprint("(destinations outside the cluster — FQDNs/CIDRs/entities, not pod-to-pod)"))
	bySource := map[string][]policy.ExternalEgress{}
	order := []string{}
	for _, e := range m.ExternalEgress {
		if _, ok := bySource[e.Source]; !ok {
			order = append(order, e.Source)
		}
		bySource[e.Source] = append(bySource[e.Source], e)
	}
	sort.Strings(order)
	for _, src := range order {
		fmt.Fprintf(w, "  %s\n", src)
		for _, e := range bySource[src] {
			ports := portLabel(e.Ports)
			kind := ""
			if e.Kind != "fqdn" {
				kind = " [" + e.Kind + "]"
			}
			resolved := ""
			if len(e.Resolved) > 0 {
				resolved = text.Faint.Sprintf("  → %s", strings.Join(e.Resolved, ", "))
			}
			fmt.Fprintf(w, "    → %s%s%s%s\n", e.Target, ports, kind, resolved)
		}
	}
	fmt.Fprintln(w)
}

// matrixView is the rendered slice of a matrix — same Cells, narrower axes.
type matrixView struct {
	Rows []policy.Axis
	Cols []policy.Axis
}

func applyNamespaceFilter(m *policy.Matrix) matrixView {
	v := matrixView{Rows: m.Rows, Cols: m.Cols}
	if m.FromNamespace != "" {
		v.Rows = filterAxesByNS(m.Rows, m.FromNamespace)
	}
	if m.ToNamespace != "" {
		v.Cols = filterAxesByNS(m.Cols, m.ToNamespace)
	}
	return v
}

func filterAxesByNS(axes []policy.Axis, ns string) []policy.Axis {
	out := make([]policy.Axis, 0, len(axes))
	for _, a := range axes {
		if a.Namespace == ns {
			out = append(out, a)
		}
	}
	return out
}

func printHeader(w io.Writer, m *policy.Matrix, view matrixView, opts Options) {
	ns := m.Namespace
	if ns == "" {
		ns = "(all namespaces)"
	}
	parts := []string{
		"namespace: " + ns,
		fmt.Sprintf("pods: %d", m.PodCount),
		fmt.Sprintf("standard policies: %d", len(m.Policies)),
		fmt.Sprintf("cilium policies: %d", len(m.CiliumPolicies)+len(m.CiliumClusterwide)),
	}
	if m.Port != 0 {
		parts = append(parts, fmt.Sprintf("port filter: %d", m.Port))
	}
	if m.FromNamespace != "" {
		parts = append(parts, fmt.Sprintf("from ns: %s", m.FromNamespace))
	}
	if m.ToNamespace != "" {
		parts = append(parts, fmt.Sprintf("to ns: %s", m.ToNamespace))
	}
	if opts.DeniesOnly {
		parts = append(parts, "denies-only")
	}
	fmt.Fprintln(w, text.Bold.Sprint("NetworkPolicy reachability"))
	fmt.Fprintln(w, strings.Join(parts, "  •  "))
	if !opts.Verbose {
		fmt.Fprintln(w, text.Faint.Sprint("(use -v for full policy inventory; --show-allowed to include default-allow matrices; --expand-edges for full edge list)"))
	}
}

func printStandardPolicies(w io.Writer, m *policy.Matrix) {
	heading := text.Bold.Sprintf("Standard NetworkPolicies (networking.k8s.io/v1) — %d in scope", len(m.Policies))
	fmt.Fprintln(w, heading)
	if len(m.Policies) == 0 {
		fmt.Fprintln(w, "  (none — all pod-to-pod traffic default-allowed)")
		return
	}
	for _, p := range m.Policies {
		dirs := []string{}
		for _, t := range p.Spec.PolicyTypes {
			dirs = append(dirs, strings.ToLower(string(t)))
		}
		if len(dirs) == 0 {
			dirs = []string{"ingress"}
		}
		fmt.Fprintf(w, "  • %s/%s   selects %s   (%s)\n",
			p.Namespace, p.Name,
			labelSelectorString(p.Spec.PodSelector.MatchLabels),
			strings.Join(dirs, ", "))
	}
}

func printCiliumPolicies(w io.Writer, m *policy.Matrix) {
	total := len(m.CiliumPolicies) + len(m.CiliumClusterwide)
	heading := text.Bold.Sprintf("Cilium NetworkPolicies (cilium.io/v2) — %d in scope", total)
	fmt.Fprintln(w, heading)
	if total == 0 {
		fmt.Fprintln(w, "  (none detected — Cilium CRDs absent, or no Cilium policies present)")
		return
	}
	fmt.Fprintln(w, text.FgGreen.Sprint("  ✓ L4 reachability is evaluated (matchLabels + toPorts + ingressDeny/egressDeny)."))
	fmt.Fprintln(w, text.FgYellow.Sprint("    L7 conditions (HTTP, DNS) are flagged, not evaluated; unresolved FQDNs, toServices and *Requires give UNKNOWN."))
	for _, p := range m.CiliumPolicies {
		fmt.Fprintf(w, "  • %s/%s   kind=CiliumNetworkPolicy   %s\n",
			p.GetNamespace(), p.GetName(),
			ciliumEndpointSummary(p))
	}
	for _, p := range m.CiliumClusterwide {
		fmt.Fprintf(w, "  • %s   kind=CiliumClusterwideNetworkPolicy   %s\n",
			p.GetName(),
			ciliumEndpointSummary(p))
	}
}

// ciliumEndpointSummary returns a short description of what a Cilium policy
// targets and which rule sections it carries (ingress/egress/deny).
func ciliumEndpointSummary(p unstructured.Unstructured) string {
	parts := []string{ciliumSelectorSummary(p)}

	rules := []string{}
	for _, key := range []string{"ingress", "egress", "ingressDeny", "egressDeny"} {
		if list, found, _ := unstructured.NestedSlice(p.Object, "spec", key); found && len(list) > 0 {
			rules = append(rules, fmt.Sprintf("%s×%d", key, len(list)))
		}
	}
	if len(rules) > 0 {
		parts = append(parts, "rules: "+strings.Join(rules, ","))
	}
	return strings.Join(parts, "   ")
}

func ciliumSelectorSummary(p unstructured.Unstructured) string {
	if sel, found, _ := unstructured.NestedMap(p.Object, "spec", "endpointSelector"); found {
		if ml, hasML, _ := unstructured.NestedMap(sel, "matchLabels"); hasML && len(ml) > 0 {
			return "selects endpoints " + mapToSelector(ml)
		}
		return "selects all endpoints"
	}
	if sel, found, _ := unstructured.NestedMap(p.Object, "spec", "nodeSelector"); found {
		if ml, hasML, _ := unstructured.NestedMap(sel, "matchLabels"); hasML && len(ml) > 0 {
			return "selects nodes " + mapToSelector(ml)
		}
		return "selects all nodes"
	}
	return "selects (see manifest)"
}

func mapToSelector(m map[string]interface{}) string {
	if len(m) == 0 {
		return "all endpoints"
	}
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// nameMaxWidth caps how wide a pod name may render in a matrix cell. Names
// longer than this are middle-ellipsised. Full names always appear in the
// "Why?" section so detail isn't lost.
const nameMaxWidth = 18

func printTable(w io.Writer, m *policy.Matrix, view matrixView, opts Options) {
	rowsByNS := groupByNS(view.Rows)
	colsByNS := groupByNS(view.Cols)
	nsSet := map[string]struct{}{}
	for ns := range rowsByNS {
		nsSet[ns] = struct{}{}
	}
	for ns := range colsByNS {
		nsSet[ns] = struct{}{}
	}

	if len(nsSet) <= 1 {
		title := "Reachability matrix  (rows = source, columns = destination)"
		printOneMatrix(w, m, view.Rows, view.Cols, title)
		return
	}

	fmt.Fprintln(w, text.Bold.Sprint("Per-namespace reachability matrices"))
	fmt.Fprintln(w, text.Faint.Sprint("(intra-namespace edges only — cross-namespace edges listed below)"))
	fmt.Fprintln(w)

	nsList := make([]string, 0, len(nsSet))
	for ns := range nsSet {
		nsList = append(nsList, ns)
	}
	sort.Strings(nsList)

	elidedNS := []string{}
	renderedAny := false
	for _, ns := range nsList {
		rows := rowsByNS[ns]
		cols := colsByNS[ns]
		if len(rows) == 0 || len(cols) == 0 {
			continue
		}
		if !opts.ShowAllowed && allCellsAllow(m, rows, cols) {
			elidedNS = append(elidedNS, fmt.Sprintf("%s (%d pods)", ns, len(rows)))
			continue
		}
		if opts.DeniesOnly && !hasDenyOrPartial(m, rows, cols) {
			continue
		}
		title := fmt.Sprintf("Namespace: %s  •  %d source × %d destination", ns, len(rows), len(cols))
		printOneMatrix(w, m, rows, cols, title)
		fmt.Fprintln(w)
		renderedAny = true
	}
	if !renderedAny && !opts.ShowAllowed {
		fmt.Fprintln(w, text.Faint.Sprint("All intra-namespace sub-matrices are default-allow (hidden). Use --show-allowed to see them."))
		fmt.Fprintln(w)
	}
	if len(elidedNS) > 0 {
		fmt.Fprintln(w, text.Faint.Sprintf("Elided sub-matrices (all ALLOW): %s", strings.Join(elidedNS, "; ")))
		fmt.Fprintln(w)
	}

	printCrossNamespace(w, m, view, opts)
}

func printOneMatrix(w io.Writer, m *policy.Matrix, rows, cols []policy.Axis, title string) {
	rowIdx := indexBy(m.Rows)
	colIdx := indexBy(m.Cols)

	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(table.StyleLight)
	t.SetTitle(title)

	header := table.Row{text.Bold.Sprint("source  ↓  /  dest  →")}
	for _, c := range cols {
		header = append(header, text.Bold.Sprint(truncate(c.Short(), nameMaxWidth)))
	}
	t.AppendHeader(header)

	for _, src := range rows {
		si := rowIdx[src.Display()]
		row := table.Row{text.Bold.Sprint(truncate(src.Short(), nameMaxWidth))}
		for _, dst := range cols {
			dj := colIdx[dst.Display()]
			row = append(row, formatCell(m.Cells[si][dj]))
		}
		t.AppendRow(row)
	}
	t.Render()
}

type crossEdge struct {
	src, dst policy.Axis
	cell     policy.Cell
}

func printCrossNamespace(w io.Writer, m *policy.Matrix, view matrixView, opts Options) {
	rowIdx := indexBy(m.Rows)
	colIdx := indexBy(m.Cols)

	var notable []crossEdge
	elided := 0

	for _, src := range view.Rows {
		si, ok := rowIdx[src.Display()]
		if !ok {
			continue
		}
		for _, dst := range view.Cols {
			if src.Namespace == dst.Namespace {
				continue
			}
			dj, ok := colIdx[dst.Display()]
			if !ok {
				continue
			}
			cell := m.Cells[si][dj]
			if cell.IsSelf {
				continue
			}
			if isBoring(cell) {
				elided++
				continue
			}
			if opts.DeniesOnly && cell.Allowed && !cell.Partial {
				continue
			}
			notable = append(notable, crossEdge{src, dst, cell})
		}
	}

	fmt.Fprintln(w, text.Bold.Sprintf(
		"Cross-namespace edges  (%d notable, %d default-allow elided)",
		len(notable), elided))
	if len(notable) == 0 {
		fmt.Fprintln(w, "  (nothing to highlight)")
		return
	}
	sort.SliceStable(notable, func(i, j int) bool {
		a, b := notable[i], notable[j]
		if a.src.Namespace != b.src.Namespace {
			return a.src.Namespace < b.src.Namespace
		}
		if a.src.Short() != b.src.Short() {
			return a.src.Short() < b.src.Short()
		}
		if a.dst.Namespace != b.dst.Namespace {
			return a.dst.Namespace < b.dst.Namespace
		}
		return a.dst.Short() < b.dst.Short()
	})

	if opts.ExpandEdges {
		printCrossEdgesExpanded(w, notable)
		return
	}
	printCrossEdgesCollapsed(w, notable)
}

// printCrossEdgesExpanded renders every (src, dst) edge as one row. This is
// what the tool used to do unconditionally; now opt-in via --expand-edges.
func printCrossEdgesExpanded(w io.Writer, edges []crossEdge) {
	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(table.StyleLight)
	t.AppendHeader(table.Row{
		text.Bold.Sprint("source"),
		text.Bold.Sprint("destination"),
		text.Bold.Sprint("verdict"),
	})
	for _, e := range edges {
		t.AppendRow(table.Row{e.src.Display(), e.dst.Display(), verdictText(e.cell)})
	}
	t.Render()
}

// printCrossEdgesCollapsed groups edges by (source, destination-namespace,
// verdict-category) so that "shop/frontend → kube-system/<each pod> DENY"
// becomes one row instead of 28. Pure DENY collapses across an entire
// destination namespace; ALLOW/PARTIAL retain detail (one row per
// destination workload) since the port set may differ.
func printCrossEdgesCollapsed(w io.Writer, edges []crossEdge) {
	type bucketKey struct {
		srcDisplay string
		dstNS      string
		category   string // "DENY", "ALLOW", "PARTIAL"
	}
	type bucket struct {
		src       policy.Axis
		dstNS     string
		category  string
		count     int
		dstNames  []string
		anyPorts  []string
		anyReason string
	}

	order := []bucketKey{}
	buckets := map[bucketKey]*bucket{}

	category := func(c policy.Cell) string {
		switch {
		case c.Partial:
			return "PARTIAL"
		case !c.Allowed:
			return "DENY"
		default:
			return "ALLOW"
		}
	}

	for _, e := range edges {
		k := bucketKey{e.src.Display(), e.dst.Namespace, category(e.cell)}
		b, ok := buckets[k]
		if !ok {
			b = &bucket{src: e.src, dstNS: e.dst.Namespace, category: k.category}
			buckets[k] = b
			order = append(order, k)
		}
		b.count++
		b.dstNames = append(b.dstNames, e.dst.Short())
		if len(b.anyPorts) == 0 {
			b.anyPorts = e.cell.Ports
		}
		if b.anyReason == "" {
			b.anyReason = e.cell.Reason
		}
	}

	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(table.StyleLight)
	t.AppendHeader(table.Row{
		text.Bold.Sprint("source"),
		text.Bold.Sprint("destination"),
		text.Bold.Sprint("verdict"),
	})
	for _, k := range order {
		b := buckets[k]
		var verdict string
		switch b.category {
		case "DENY":
			verdict = color.RedString("DENY")
		case "PARTIAL":
			verdict = color.YellowString("PARTIAL")
		default:
			if len(b.anyPorts) == 0 || (len(b.anyPorts) == 1 && b.anyPorts[0] == "*") {
				verdict = color.GreenString("ALLOW")
			} else {
				verdict = color.GreenString("ALLOW :" + strings.Join(b.anyPorts, ","))
			}
		}
		dst := fmt.Sprintf("%s/*  (%d %s)", b.dstNS, b.count, pluralize("dest", b.count))
		t.AppendRow(table.Row{b.src.Display(), dst, verdict})
	}
	t.Render()
	fmt.Fprintln(w, text.Faint.Sprint("(edges collapsed by destination namespace — use --expand-edges to list every pair)"))
}

func pluralize(word string, n int) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

func groupByNS(refs []policy.Axis) map[string][]policy.Axis {
	out := map[string][]policy.Axis{}
	for _, r := range refs {
		out[r.Namespace] = append(out[r.Namespace], r)
	}
	return out
}

func indexBy(refs []policy.Axis) map[string]int {
	m := map[string]int{}
	for i, r := range refs {
		m[r.Display()] = i
	}
	return m
}

// truncate shortens s to at most max runes with a middle ellipsis.
// "kube-controller-manager-netpol-map-plane" max=15 → "kube-co…l-plane".
func truncate(s string, max int) string {
	runes := []rune(s)
	if max < 4 || len(runes) <= max {
		return s
	}
	keep := max - 1 // 1 rune for the ellipsis
	head := (keep + 1) / 2
	tail := keep - head
	return string(runes[:head]) + "…" + string(runes[len(runes)-tail:])
}

// isBoring is true for an ALLOW edge where no policy contributed to the
// verdict — the default-allow case, uninteresting at cluster scale. An
// edge that's ALLOW *because* a policy explicitly permits it is not boring
// and stays visible; an UNKNOWN edge is never boring.
func isBoring(c policy.Cell) bool {
	if c.Unknown {
		return false
	}
	return c.Allowed && !c.Partial && !c.PolicyApplied
}

// hasActionableCells reports whether any non-self cell in the rows×cols
// sub-matrix is something other than default-allow.
func hasActionableCells(m *policy.Matrix, rows, cols []policy.Axis) bool {
	rowIdx := indexBy(m.Rows)
	colIdx := indexBy(m.Cols)
	for _, src := range rows {
		si := rowIdx[src.Display()]
		for _, dst := range cols {
			dj := colIdx[dst.Display()]
			cell := m.Cells[si][dj]
			if cell.IsSelf {
				continue
			}
			if !isBoring(cell) {
				return true
			}
		}
	}
	return false
}

// hasDenyOrPartial returns true when at least one non-self cell is a DENY
// or PARTIAL — used to skip sub-matrices entirely in --denies-only mode.
func hasDenyOrPartial(m *policy.Matrix, rows, cols []policy.Axis) bool {
	rowIdx := indexBy(m.Rows)
	colIdx := indexBy(m.Cols)
	for _, src := range rows {
		si, ok := rowIdx[src.Display()]
		if !ok {
			continue
		}
		for _, dst := range cols {
			dj, ok := colIdx[dst.Display()]
			if !ok {
				continue
			}
			cell := m.Cells[si][dj]
			if cell.IsSelf {
				continue
			}
			if cell.Partial || !cell.Allowed {
				return true
			}
		}
	}
	return false
}

// allCellsAllow returns true when every non-self cell in the sub-matrix is
// ALLOW (whether by default or by policy). Used to suppress matrices that
// contribute no signal — there is no DENY or PARTIAL to learn from.
func allCellsAllow(m *policy.Matrix, rows, cols []policy.Axis) bool {
	rowIdx := indexBy(m.Rows)
	colIdx := indexBy(m.Cols)
	for _, src := range rows {
		si, ok := rowIdx[src.Display()]
		if !ok {
			continue
		}
		for _, dst := range cols {
			dj, ok := colIdx[dst.Display()]
			if !ok {
				continue
			}
			cell := m.Cells[si][dj]
			if cell.IsSelf {
				continue
			}
			if !cell.Allowed || cell.Partial {
				return false
			}
		}
	}
	return true
}

func printLegend(w io.Writer, opts Options) {
	unknown := color.New(color.FgHiYellow).Sprint("UNKNOWN")
	if !opts.Verbose {
		fmt.Fprintln(w, text.Faint.Sprintf("Legend: %s = allowed   %s = blocked   %s = mixed   %s = could not be decided (unresolved FQDN, toServices, *Requires)",
			color.GreenString("ALLOW"), color.RedString("DENY"), color.YellowString("PARTIAL"), unknown))
		return
	}
	fmt.Fprintln(w, text.Bold.Sprint("Legend:"))
	fmt.Fprintln(w, "  "+color.GreenString("ALLOW :ports")+"      traffic permitted on the listed port(s)")
	fmt.Fprintln(w, "  "+color.GreenString("ALLOW")+"             traffic permitted on all ports (no port restriction)")
	fmt.Fprintln(w, "  "+color.RedString("DENY")+"              traffic blocked by NetworkPolicies")
	fmt.Fprintln(w, "  "+color.YellowString("PARTIAL A/T")+"       only A of T pod-pairs allowed (workload mode); drill in with --by=pod")
	fmt.Fprintln(w, "  "+unknown+"           verdict depends on a rule the engine can't evaluate (Cilium L7/FQDN/entity/CIDR) — NOT a definitive deny")
	fmt.Fprintln(w, "  "+color.GreenString("ALLOW")+color.New(color.FgHiYellow).Sprint(" (L7)")+"     connection allowed at L4, but the rule also has L7 (HTTP/DNS) conditions not evaluated")
	fmt.Fprintln(w, "  "+text.Faint.Sprint("self")+"              same axis entry (not evaluated)")
}

func printExplanations(w io.Writer, m *policy.Matrix, view matrixView, opts Options) {
	rowIdx := indexBy(m.Rows)
	colIdx := indexBy(m.Cols)
	useShort := allSameNamespace(append(append([]policy.Axis{}, view.Rows...), view.Cols...))

	type row struct {
		src, dst, verdict, reason string
	}
	rows := []row{}
	elided := 0
	maxSrc, maxDst, maxVerdictVisible := 0, 0, 0
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
			if cell.IsSelf {
				continue
			}
			if isBoring(cell) {
				elided++
				continue
			}
			if opts.DeniesOnly && cell.Allowed && !cell.Partial {
				continue
			}
			r := row{
				src:     displayName(src, useShort),
				dst:     displayName(dst, useShort),
				verdict: verdictText(cell),
				reason:  cell.Reason,
			}
			rows = append(rows, r)
			if l := len(r.src); l > maxSrc {
				maxSrc = l
			}
			if l := len(r.dst); l > maxDst {
				maxDst = l
			}
			if l := visibleLen(r.verdict); l > maxVerdictVisible {
				maxVerdictVisible = l
			}
		}
	}
	if !opts.Verbose && len(rows) == 0 {
		return
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].src != rows[j].src {
			return rows[i].src < rows[j].src
		}
		return rows[i].dst < rows[j].dst
	})

	// Aggregate by (verdict, reason). When many edges share the same reason
	// — e.g. "21 edges DENY: src isolated for egress" — print one summary
	// line per group instead of repeating the reason. --full-why opts out.
	if !opts.FullWhy {
		type group struct {
			verdict, reason string
			count           int
			sample          string // "src → dst" of the first edge
		}
		order := []string{}
		groups := map[string]*group{}
		for _, r := range rows {
			key := r.verdict + "\x00" + r.reason
			g, ok := groups[key]
			if !ok {
				g = &group{verdict: r.verdict, reason: r.reason, sample: r.src + " → " + r.dst}
				groups[key] = g
				order = append(order, key)
			}
			g.count++
		}
		if len(groups) < len(rows) {
			fmt.Fprintln(w, text.Bold.Sprintf("Why? — grouped by reason  (%d edges in %d groups, %d default-allow elided)", len(rows), len(groups), elided))
			fmt.Fprintln(w, text.Faint.Sprint("(use --full-why for the per-edge list)"))
			for _, key := range order {
				g := groups[key]
				if g.count == 1 {
					fmt.Fprintf(w, "  %s   1 edge: %s\n     %s\n", g.verdict, g.sample, g.reason)
					continue
				}
				fmt.Fprintf(w, "  %s   %d edges (e.g. %s)\n     %s\n", g.verdict, g.count, g.sample, g.reason)
			}
			return
		}
	}

	fmt.Fprintln(w, text.Bold.Sprintf("Why? — per-edge explanation  (%d notable, %d default-allow elided)", len(rows), elided))
	for _, r := range rows {
		vpad := strings.Repeat(" ", maxVerdictVisible-visibleLen(r.verdict))
		fmt.Fprintf(w, "  %-*s  →  %-*s   %s%s   %s\n",
			maxSrc, r.src, maxDst, r.dst, r.verdict, vpad, r.reason)
	}
}

func verdictText(c policy.Cell) string {
	v := c.Verdict()
	switch {
	case c.Unknown:
		return color.New(color.FgHiYellow).Sprint(v)
	case c.Partial:
		return color.YellowString(v)
	case !c.Allowed:
		return color.RedString(v)
	case c.L7Restricted:
		return color.GreenString(strings.TrimSuffix(v, " (L7)")) + color.New(color.FgHiYellow).Sprint(" (L7)")
	}
	return color.GreenString(v)
}

func formatCell(c policy.Cell) string {
	if c.IsSelf {
		return text.Faint.Sprint("self")
	}
	return verdictText(c)
}

func labelSelectorString(ml map[string]string) string {
	if len(ml) == 0 {
		return "all pods"
	}
	parts := make([]string, 0, len(ml))
	for k, v := range ml {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func allSameNamespace(refs []policy.Axis) bool {
	if len(refs) == 0 {
		return true
	}
	ns := refs[0].Namespace
	for _, r := range refs {
		if r.Namespace != ns {
			return false
		}
	}
	return true
}

func displayName(p policy.Axis, short bool) string {
	if short {
		return p.Short()
	}
	return p.Display()
}

// visibleLen returns the length of s ignoring ANSI escape sequences.
func visibleLen(s string) int {
	out := 0
	inEsc := false
	for _, r := range s {
		if r == '\x1b' {
			inEsc = true
			continue
		}
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		out++
	}
	return out
}

// JSON renders the matrix as a flat edge list, including reasons.
func JSON(w io.Writer, m *policy.Matrix) error {
	type edge struct {
		From         string   `json:"from"`
		To           string   `json:"to"`
		Allowed      bool     `json:"allowed"`
		Partial      bool     `json:"partial,omitempty"`
		Unknown      bool     `json:"unknown,omitempty"`
		Ports        []string `json:"ports,omitempty"`
		Reason       string   `json:"reason,omitempty"`
		AllowedPairs int      `json:"allowedPairs,omitempty"`
		DeniedPairs  int      `json:"deniedPairs,omitempty"`
	}
	type ciliumRef struct {
		Namespace string `json:"namespace,omitempty"`
		Name      string `json:"name"`
		Kind      string `json:"kind"`
	}
	type output struct {
		Namespace        string      `json:"namespace,omitempty"`
		PodCount         int         `json:"podCount"`
		StandardPolicies int         `json:"standardPolicyCount"`
		CiliumPolicies   []ciliumRef `json:"ciliumPolicies"`
		PortFilter       int32       `json:"portFilter,omitempty"`
		Edges            []edge      `json:"edges"`
	}

	out := output{
		Namespace:        m.Namespace,
		PodCount:         m.PodCount,
		StandardPolicies: len(m.Policies),
		PortFilter:       m.Port,
		CiliumPolicies:   []ciliumRef{},
		Edges:            []edge{},
	}
	for _, p := range m.CiliumPolicies {
		out.CiliumPolicies = append(out.CiliumPolicies, ciliumRef{
			Namespace: p.GetNamespace(), Name: p.GetName(), Kind: "CiliumNetworkPolicy",
		})
	}
	for _, p := range m.CiliumClusterwide {
		out.CiliumPolicies = append(out.CiliumPolicies, ciliumRef{
			Name: p.GetName(), Kind: "CiliumClusterwideNetworkPolicy",
		})
	}
	for i, src := range m.Rows {
		for j, dst := range m.Cols {
			cell := m.Cells[i][j]
			if cell.IsSelf {
				continue
			}
			out.Edges = append(out.Edges, edge{
				From:         src.Display(),
				To:           dst.Display(),
				Allowed:      cell.Allowed,
				Partial:      cell.Partial,
				Unknown:      cell.Unknown,
				Ports:        cell.Ports,
				Reason:       cell.Reason,
				AllowedPairs: cell.AllowedPairs,
				DeniedPairs:  cell.DeniedPairs,
			})
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
