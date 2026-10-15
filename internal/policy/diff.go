package policy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// SplitYAMLDocuments splits a (possibly multi-document) YAML stream into
// individual documents, dropping empty ones.
func SplitYAMLDocuments(data []byte) ([][]byte, error) {
	r := yaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	var docs [][]byte
	for {
		doc, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(doc)) == 0 {
			continue
		}
		docs = append(docs, doc)
	}
	return docs, nil
}

// EdgeKey identifies a directed source→destination edge for diffing.
type EdgeKey struct {
	Src string
	Dst string
}

// EdgeVerdict is a compact verdict for one edge, used on both sides of a diff.
type EdgeVerdict struct {
	Allowed bool
	Partial bool
	Unknown bool
	Ports   []string
	Reason  string
}

// DiffResult is the before/after comparison of two snapshots.
type DiffResult struct {
	// NewlyAllowed: edge was DENY before, ALLOW/PARTIAL after.
	NewlyAllowed []EdgeChange
	// NewlyDenied: edge was ALLOW/PARTIAL before, DENY after.
	NewlyDenied []EdgeChange
	// Changed: still allowed both sides but ports/verdict shifted.
	Changed []EdgeChange
}

// EdgeChange is one edge whose verdict changed across the diff.
type EdgeChange struct {
	Key    EdgeKey
	Before EdgeVerdict
	After  EdgeVerdict
}

// ApplyManifests returns a copy of snap with the given manifests merged in:
// a standard NetworkPolicy or CiliumNetworkPolicy with the same namespace+name
// as an existing one replaces it; otherwise it is added. Pods are unchanged.
func (snap *Snapshot) ApplyManifests(docs [][]byte) (*Snapshot, error) {
	next := snap.shallowCopy()
	for _, doc := range docs {
		kind, err := manifestKind(doc)
		if err != nil {
			return nil, err
		}
		switch kind {
		case "NetworkPolicy":
			var np networkingv1.NetworkPolicy
			if err := yaml.Unmarshal(doc, &np); err != nil {
				return nil, fmt.Errorf("parse NetworkPolicy: %w", err)
			}
			next.Policies = upsertNP(next.Policies, np)
		case "CiliumNetworkPolicy":
			u, err := decodeUnstructured(doc)
			if err != nil {
				return nil, err
			}
			next.CiliumNamespacePolicies = upsertCNP(next.CiliumNamespacePolicies, u)
		case "CiliumClusterwideNetworkPolicy":
			u, err := decodeUnstructured(doc)
			if err != nil {
				return nil, err
			}
			next.CiliumClusterPolicies = upsertCNP(next.CiliumClusterPolicies, u)
		default:
			return nil, fmt.Errorf("unsupported kind %q (want NetworkPolicy, CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy)", kind)
		}
	}
	return next, nil
}

func (snap *Snapshot) shallowCopy() *Snapshot {
	cp := *snap
	cp.Policies = append([]networkingv1.NetworkPolicy(nil), snap.Policies...)
	cp.CiliumNamespacePolicies = append([]unstructured.Unstructured(nil), snap.CiliumNamespacePolicies...)
	cp.CiliumClusterPolicies = append([]unstructured.Unstructured(nil), snap.CiliumClusterPolicies...)
	return &cp
}

func upsertNP(list []networkingv1.NetworkPolicy, np networkingv1.NetworkPolicy) []networkingv1.NetworkPolicy {
	for i, p := range list {
		if p.Namespace == np.Namespace && p.Name == np.Name {
			list[i] = np
			return list
		}
	}
	return append(list, np)
}

func upsertCNP(list []unstructured.Unstructured, u unstructured.Unstructured) []unstructured.Unstructured {
	for i, p := range list {
		if p.GetNamespace() == u.GetNamespace() && p.GetName() == u.GetName() {
			list[i] = u
			return list
		}
	}
	return append(list, u)
}

func manifestKind(doc []byte) (string, error) {
	var meta struct {
		Kind string `json:"kind"`
	}
	if err := yaml.Unmarshal(doc, &meta); err != nil {
		return "", fmt.Errorf("parse manifest kind: %w", err)
	}
	if meta.Kind == "" {
		return "", fmt.Errorf("manifest missing 'kind'")
	}
	return meta.Kind, nil
}

func decodeUnstructured(doc []byte) (unstructured.Unstructured, error) {
	var obj map[string]interface{}
	// k8s util/yaml routes through ToJSON, so nested values come back as the
	// JSON-compatible types unstructured + the Cilium engine expect.
	if err := yaml.Unmarshal(doc, &obj); err != nil {
		return unstructured.Unstructured{}, fmt.Errorf("parse Cilium policy: %w", err)
	}
	return unstructured.Unstructured{Object: obj}, nil
}

// Diff evaluates both snapshots over the same axes and reports the edges that
// changed verdict. Mode/selectors mirror a normal Evaluate call so the diff
// scope matches what the matrix would show.
func Diff(before, after *Snapshot, mode GroupBy, rowSel, colSel string, port int32) (*DiffResult, error) {
	ev := NewBasicEvaluator()
	mb, err := ev.Evaluate(before, mode, rowSel, colSel, port)
	if err != nil {
		return nil, err
	}
	ma, err := ev.Evaluate(after, mode, rowSel, colSel, port)
	if err != nil {
		return nil, err
	}

	beforeEdges := edgeMap(mb)
	afterEdges := edgeMap(ma)

	res := &DiffResult{}
	for key, av := range afterEdges {
		bv, existed := beforeEdges[key]
		if !existed {
			// New axis entry (shouldn't happen — same pods — but be safe).
			bv = EdgeVerdict{Allowed: true, Reason: "no policy in scope (baseline)"}
		}
		bAllow := bv.Allowed || bv.Partial
		aAllow := av.Allowed || av.Partial
		switch {
		case !bAllow && aAllow:
			res.NewlyAllowed = append(res.NewlyAllowed, EdgeChange{key, bv, av})
		case bAllow && !aAllow:
			res.NewlyDenied = append(res.NewlyDenied, EdgeChange{key, bv, av})
		case bAllow && aAllow && !samePorts(bv.Ports, av.Ports):
			res.Changed = append(res.Changed, EdgeChange{key, bv, av})
		}
	}
	return res, nil
}

func edgeMap(m *Matrix) map[EdgeKey]EdgeVerdict {
	out := map[EdgeKey]EdgeVerdict{}
	for i, src := range m.Rows {
		for j, dst := range m.Cols {
			c := m.Cells[i][j]
			if c.IsSelf {
				continue
			}
			out[EdgeKey{src.Display(), dst.Display()}] = EdgeVerdict{
				Allowed: c.Allowed, Partial: c.Partial, Unknown: c.Unknown, Ports: c.Ports, Reason: c.Reason,
			}
		}
	}
	return out
}

func samePorts(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, x := range a {
		seen[x]++
	}
	for _, x := range b {
		seen[x]--
	}
	for _, v := range seen {
		if v != 0 {
			return false
		}
	}
	return true
}
