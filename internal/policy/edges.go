package policy

import (
	corev1 "k8s.io/api/core/v1"
)

// Edge is one evaluated workload → workload verdict, in the shape the web UI
// and the terminal UI both display.
type Edge struct {
	From    WorkloadRef `json:"from"`
	To      WorkloadRef `json:"to"`
	Status  string      `json:"status"` // allow | deny | partial | unknown
	Verdict string      `json:"verdict"`
	Ports   []string    `json:"ports,omitempty"`
	Reason  string      `json:"reason"`
}

// Edges evaluates workload reachability with the source limited to fromNS
// and the destination to toNS (either may be empty for any namespace). Only
// pods that can appear on an axis are evaluated. Default-allow edges, where
// no policy had a say, are counted in hidden and left out unless
// includeDefault is set.
func Edges(snap *Snapshot, fromNS, toNS string, port int32, includeDefault bool) ([]Edge, int, error) {
	scoped := *snap
	scoped.Pods = []corev1.Pod{}
	for _, p := range snap.Pods {
		if fromNS == "" || toNS == "" || p.Namespace == fromNS || p.Namespace == toNS {
			scoped.Pods = append(scoped.Pods, p)
		}
	}
	m, err := NewBasicEvaluator().Evaluate(&scoped, GroupByWorkload, "", "", port)
	if err != nil {
		return nil, 0, err
	}
	out := []Edge{}
	hidden := 0
	for i, src := range m.Rows {
		if fromNS != "" && src.Namespace != fromNS {
			continue
		}
		for j, dst := range m.Cols {
			if toNS != "" && dst.Namespace != toNS {
				continue
			}
			c := m.Cells[i][j]
			if c.IsSelf {
				continue
			}
			if !c.PolicyApplied && !includeDefault {
				hidden++
				continue
			}
			status := "allow"
			switch {
			case c.Unknown:
				status = "unknown"
			case c.Partial:
				status = "partial"
			case !c.Allowed:
				status = "deny"
			}
			out = append(out, Edge{
				From:   WorkloadRef{Namespace: src.Namespace, Kind: src.Kind, Name: src.Name, Pods: len(src.Pods)},
				To:     WorkloadRef{Namespace: dst.Namespace, Kind: dst.Kind, Name: dst.Name, Pods: len(dst.Pods)},
				Status: status, Verdict: c.Verdict(), Ports: DisplayPorts(c.Ports), Reason: c.Reason,
			})
		}
	}
	return out, hidden, nil
}
