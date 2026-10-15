package render

import (
	"strings"
	"testing"

	"github.com/aganet/kubectl-netpol-map/internal/policy"
)

// sampleMatrix builds a tiny cross-namespace matrix mirroring the
// "shop → orders" shape: one source workload reaching one of two
// destinations on a port, denied to the other.
func sampleMatrix() *policy.Matrix {
	rows := []policy.Axis{
		{Namespace: "shop", Kind: "Deployment", Name: "web-a"},
	}
	cols := []policy.Axis{
		{Namespace: "orders", Kind: "Deployment", Name: "frontend"},
		{Namespace: "orders", Kind: "Deployment", Name: "worker"},
	}
	cells := [][]policy.Cell{{
		{Allowed: true, PolicyApplied: true, Ports: []string{"7233"}, Reason: "Cilium egress: shop/baseline-egress"},
		{Allowed: false, PolicyApplied: true, Reason: "Cilium: src isolated for egress; no Cilium rule matches dst"},
	}}
	return &policy.Matrix{
		Namespace: "",
		Mode:      policy.GroupByWorkload,
		Rows:      rows,
		Cols:      cols,
		Cells:     cells,
		PodCount:  3,
	}
}

func TestMermaidRendersEdges(t *testing.T) {
	var b strings.Builder
	if err := Mermaid(&b, sampleMatrix()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"flowchart LR", "subgraph", "7233", "linkStyle"} {
		if !strings.Contains(out, want) {
			t.Errorf("mermaid output missing %q:\n%s", want, out)
		}
	}
	// The DENY edge must use the dotted arrow.
	if !strings.Contains(out, "-.->") {
		t.Errorf("expected dotted DENY arrow in:\n%s", out)
	}
}

func TestDotRendersEdges(t *testing.T) {
	var b strings.Builder
	if err := Dot(&b, sampleMatrix()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{`digraph "netpol-map"`, "rankdir=LR", "cluster_", "->", "DENY"} {
		if !strings.Contains(out, want) {
			t.Errorf("dot output missing %q:\n%s", want, out)
		}
	}
}

func TestHTMLRendersTableAndGraph(t *testing.T) {
	var b strings.Builder
	if err := HTML(&b, sampleMatrix()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"<!DOCTYPE html>", "class=\"mermaid\"", "ALLOW:7233", "DENY", "1 ALLOW", "1 DENY"} {
		if !strings.Contains(out, want) {
			t.Errorf("html output missing %q", want)
		}
	}
}

func TestWhyAggregates(t *testing.T) {
	// Two DENY edges with the same reason should collapse to one group line.
	rows := []policy.Axis{
		{Namespace: "shop", Kind: "Deployment", Name: "web-a"},
	}
	cols := []policy.Axis{
		{Namespace: "orders", Kind: "Deployment", Name: "worker"},
		{Namespace: "orders", Kind: "Deployment", Name: "history"},
	}
	reason := "Cilium: src isolated for egress; no Cilium rule matches dst"
	cells := [][]policy.Cell{{
		{Allowed: false, PolicyApplied: true, Reason: reason},
		{Allowed: false, PolicyApplied: true, Reason: reason},
	}}
	m := &policy.Matrix{Rows: rows, Cols: cols, Cells: cells, PodCount: 2}

	var b strings.Builder
	if err := MatrixWithOptions(&b, m, Options{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "grouped by reason") {
		t.Errorf("expected aggregated Why? section:\n%s", out)
	}
	if !strings.Contains(out, "2 edges") {
		t.Errorf("expected '2 edges' group count:\n%s", out)
	}
}
