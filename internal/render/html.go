package render

import (
	"bytes"
	"fmt"
	"html"
	"io"
	"sort"

	"github.com/aganet/kubectl-netpol-map/internal/policy"
)

// HTML renders a self-contained, shareable audit artifact: a verdict-coloured
// edge table with a per-edge "Why?" you can expand, plus the reachability
// graph rendered client-side from embedded Mermaid source. The only external
// dependency is the Mermaid script loaded from a CDN; the page degrades to a
// readable table if that fails or there's no network.
func HTML(w io.Writer, m *policy.Matrix) error {
	return HTMLWithOptions(w, m, Options{})
}

func HTMLWithOptions(w io.Writer, m *policy.Matrix, opts Options) error {
	view := applyNamespaceFilter(m)

	// Build the per-edge rows (reusing the same filtering as the table view).
	rowIdx := indexBy(m.Rows)
	colIdx := indexBy(m.Cols)
	type edgeRow struct {
		src, dst, verdict, reason, cls string
		ports                          []string
	}
	var rows []edgeRow
	allowN, denyN, partialN, unknownN := 0, 0, 0, 0
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
			var verdict, cls string
			switch {
			case cell.Unknown:
				verdict, cls = "UNKNOWN", "unknown"
				unknownN++
			case cell.Partial:
				verdict, cls = fmt.Sprintf("PARTIAL %d/%d", cell.AllowedPairs, cell.AllowedPairs+cell.DeniedPairs), "partial"
				partialN++
			case !cell.Allowed:
				verdict, cls = "DENY", "deny"
				denyN++
			default:
				verdict, cls = "ALLOW"+portLabel(cell.Ports), "allow"
				allowN++
			}
			rows = append(rows, edgeRow{
				src: src.Display(), dst: dst.Display(),
				verdict: verdict, reason: cell.Reason, cls: cls, ports: cell.Ports,
			})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].src != rows[j].src {
			return rows[i].src < rows[j].src
		}
		return rows[i].dst < rows[j].dst
	})

	// Mermaid source for the embedded graph (no ANSI; uncoloured opts copy).
	var mer bytes.Buffer
	_ = MermaidWithOptions(&mer, m, Options{DeniesOnly: opts.DeniesOnly})

	nsScope := m.Namespace
	if nsScope == "" {
		nsScope = "(all namespaces)"
	}

	fmt.Fprintf(w, htmlHead, html.EscapeString(nsScope), m.PodCount,
		len(m.Policies), len(m.CiliumPolicies)+len(m.CiliumClusterwide),
		allowN, denyN, partialN, unknownN)

	// Graph section.
	fmt.Fprintln(w, `<h2>Reachability graph</h2>`)
	fmt.Fprintln(w, `<div class="mermaid">`)
	fmt.Fprint(w, html.EscapeString(mer.String()))
	fmt.Fprintln(w, `</div>`)

	// Edge table.
	fmt.Fprintln(w, `<h2>Edges</h2>`)
	fmt.Fprintln(w, `<input id="filter" placeholder="filter… (type to narrow rows)" oninput="filterRows()">`)
	fmt.Fprintln(w, `<table id="edges"><thead><tr><th>Source</th><th>Destination</th><th>Verdict</th><th>Why</th></tr></thead><tbody>`)
	for _, r := range rows {
		fmt.Fprintf(w,
			`<tr class="%s"><td>%s</td><td>%s</td><td><span class="badge %s">%s</span></td><td class="why">%s</td></tr>`+"\n",
			r.cls,
			html.EscapeString(r.src), html.EscapeString(r.dst),
			r.cls, html.EscapeString(r.verdict),
			html.EscapeString(r.reason))
	}
	fmt.Fprintln(w, `</tbody></table>`)
	fmt.Fprint(w, htmlTail)
	return nil
}

const htmlHead = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>kubectl-netpol-map reachability</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }
  h1 { margin-bottom: 0.2rem; }
  .meta { color: #555; margin-bottom: 1rem; }
  .counts span { display:inline-block; padding:2px 8px; border-radius:4px; margin-right:6px; font-size:0.85rem; }
  .counts .allow { background:#e6f4ea; color:#2e7d32; }
  .counts .deny { background:#fdecea; color:#c62828; }
  .counts .partial { background:#fff8e1; color:#f9a825; }
  .counts .unknown { background:#fff8e1; color:#9a6a00; border:1px dashed #f9a825; }
  table { border-collapse: collapse; width: 100%%; font-size: 0.9rem; }
  th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #eee; }
  th { position: sticky; top: 0; background: #fafafa; }
  td.why { color:#555; font-size:0.82rem; }
  .badge { padding:2px 6px; border-radius:3px; font-weight:600; font-size:0.8rem; }
  .badge.allow { background:#e6f4ea; color:#2e7d32; }
  .badge.deny { background:#fdecea; color:#c62828; }
  .badge.partial { background:#fff8e1; color:#f9a825; }
  .badge.unknown { background:#fff8e1; color:#9a6a00; border:1px dashed #f9a825; }
  #filter { padding:6px 10px; margin:0.5rem 0 1rem; width: 320px; border:1px solid #ccc; border-radius:4px; }
  .mermaid { background:#fff; }
</style>
</head><body>
<h1>NetworkPolicy reachability</h1>
<div class="meta">namespace: %s &nbsp;•&nbsp; pods: %d &nbsp;•&nbsp; standard policies: %d &nbsp;•&nbsp; cilium policies: %d</div>
<div class="counts"><span class="allow">%d ALLOW</span><span class="deny">%d DENY</span><span class="partial">%d PARTIAL</span><span class="unknown">%d UNKNOWN</span></div>
`

const htmlTail = `
<script type="module">
  import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';
  mermaid.initialize({ startOnLoad: true, securityLevel: 'loose' });
</script>
<script>
  function filterRows() {
    const q = document.getElementById('filter').value.toLowerCase();
    for (const tr of document.querySelectorAll('#edges tbody tr')) {
      tr.style.display = tr.innerText.toLowerCase().includes(q) ? '' : 'none';
    }
  }
</script>
</body></html>
`
