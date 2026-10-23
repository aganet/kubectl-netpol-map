package policy

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// PolicyView is one policy explained: what it selects, which directions it
// isolates, and every rule with its peers resolved to the workloads they
// match in the cluster. It is what a UI draws.
type PolicyView struct {
	Key             string        `json:"key"`
	Kind            string        `json:"kind"`
	Namespace       string        `json:"namespace,omitempty"`
	Name            string        `json:"name"`
	Selector        string        `json:"selector"`
	Selected        []WorkloadRef `json:"selected"`
	IsolatesIngress bool          `json:"isolatesIngress"`
	IsolatesEgress  bool          `json:"isolatesEgress"`
	Ingress         []RuleView    `json:"ingress"`
	Egress          []RuleView    `json:"egress"`
	// Rejected is why Cilium refused the policy (status Valid=False); it is
	// then not enforced and ignored by every verdict.
	Rejected string `json:"rejected,omitempty"`
}

// WorkloadRef identifies a workload and how many pods it has.
type WorkloadRef struct {
	Namespace string `json:"ns"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Pods      int    `json:"pods"`
}

// RuleView is one allow or deny rule.
type RuleView struct {
	Deny  bool       `json:"deny,omitempty"`
	Peers []PeerView `json:"peers"`
	Ports []string   `json:"ports"` // "8080/TCP", "any"
	L7    bool       `json:"l7,omitempty"`
}

// PeerView is one peer of a rule: who may talk (ingress) or be talked to
// (egress). Type is pods | namespace | cidr | entity | fqdn | service | any.
type PeerView struct {
	Type    string        `json:"type"`
	Label   string        `json:"label"`
	Matches []WorkloadRef `json:"matches,omitempty"`
}

// Coverage summarises which workloads any policy touches.
type Coverage struct {
	Workloads       int           `json:"workloads"`
	Unprotected     []WorkloadRef `json:"unprotected"`
	IsolatedIngress int           `json:"isolatedIngress"`
	IsolatedEgress  int           `json:"isolatedEgress"`
}

// Describe explains every policy in the snapshot and the coverage they add
// up to.
func Describe(snap *Snapshot) ([]PolicyView, Coverage) {
	ctx := newEvalContext(snap)
	workloads := snap.Workloads()
	views := []PolicyView{}
	for _, np := range snap.Policies {
		views = append(views, describeStandard(ctx, np, workloads))
	}
	for _, p := range append(append([]unstructured.Unstructured{}, snap.CiliumNamespacePolicies...), snap.CiliumClusterPolicies...) {
		views = append(views, describeCilium(p, workloads))
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Key < views[j].Key })

	cov := Coverage{Workloads: len(workloads), Unprotected: []WorkloadRef{}}
	for _, w := range workloads {
		rep := *w.Pods[0]
		in, out := false, false
		for _, np := range snap.Policies {
			if np.Namespace == rep.Namespace && selects(np.Spec.PodSelector, rep) {
				in = in || hasType(np, networkingv1.PolicyTypeIngress)
				out = out || hasType(np, networkingv1.PolicyTypeEgress)
			}
		}
		for _, p := range append(append([]unstructured.Unstructured{}, ctx.cnps...), ctx.ccnps...) {
			if selectsForCilium(p, rep) {
				in = in || policyHasSection(p, "ingress")
				out = out || policyHasSection(p, "egress")
			}
		}
		if in {
			cov.IsolatedIngress++
		}
		if out {
			cov.IsolatedEgress++
		}
		if !in && !out {
			cov.Unprotected = append(cov.Unprotected, workloadRef(w))
		}
	}
	return views, cov
}

func workloadRef(w Workload) WorkloadRef {
	return WorkloadRef{Namespace: w.Namespace, Kind: w.Kind, Name: w.Name, Pods: len(w.Pods)}
}

// matchingWorkloads returns the workloads with at least one pod the
// predicate accepts.
func matchingWorkloads(workloads []Workload, accept func(corev1.Pod) bool) []WorkloadRef {
	out := []WorkloadRef{}
	for _, w := range workloads {
		for _, p := range w.Pods {
			if accept(*p) {
				out = append(out, workloadRef(w))
				break
			}
		}
	}
	return out
}

func describeStandard(ctx evalContext, np networkingv1.NetworkPolicy, workloads []Workload) PolicyView {
	v := PolicyView{
		Key: "NetworkPolicy/" + np.Namespace + "/" + np.Name, Kind: "NetworkPolicy",
		Namespace: np.Namespace, Name: np.Name,
		Selector:        selectorText(metav1.FormatLabelSelector(&np.Spec.PodSelector)),
		IsolatesIngress: hasType(np, networkingv1.PolicyTypeIngress),
		IsolatesEgress:  hasType(np, networkingv1.PolicyTypeEgress),
		Ingress:         []RuleView{}, Egress: []RuleView{},
	}
	v.Selected = matchingWorkloads(workloads, func(p corev1.Pod) bool {
		return p.Namespace == np.Namespace && selects(np.Spec.PodSelector, p)
	})
	peers := func(ps []networkingv1.NetworkPolicyPeer) []PeerView {
		if len(ps) == 0 {
			return []PeerView{{Type: "any", Label: "any source or destination"}}
		}
		out := []PeerView{}
		for _, peer := range ps {
			if peer.IPBlock != nil {
				label := peer.IPBlock.CIDR
				if len(peer.IPBlock.Except) > 0 {
					label += " except " + strings.Join(peer.IPBlock.Except, ", ")
				}
				out = append(out, PeerView{Type: "cidr", Label: label})
				continue
			}
			pv := PeerView{Type: "pods"}
			switch {
			case peer.NamespaceSelector == nil:
				pv.Label = fmt.Sprintf("pods %s in namespace %s", selectorText(metav1.FormatLabelSelector(peer.PodSelector)), np.Namespace)
			case peer.PodSelector == nil:
				pv.Type = "namespace"
				pv.Label = "all pods in namespaces " + selectorText(metav1.FormatLabelSelector(peer.NamespaceSelector))
			default:
				pv.Label = fmt.Sprintf("pods %s in namespaces %s", selectorText(metav1.FormatLabelSelector(peer.PodSelector)), selectorText(metav1.FormatLabelSelector(peer.NamespaceSelector)))
			}
			one := []networkingv1.NetworkPolicyPeer{peer}
			pv.Matches = matchingWorkloads(workloads, func(p corev1.Pod) bool { return peersMatch(ctx, one, p, np.Namespace) })
			out = append(out, pv)
		}
		return out
	}
	for _, r := range np.Spec.Ingress {
		v.Ingress = append(v.Ingress, RuleView{Peers: peers(r.From), Ports: standardPorts(r.Ports)})
	}
	for _, r := range np.Spec.Egress {
		v.Egress = append(v.Egress, RuleView{Peers: peers(r.To), Ports: standardPorts(r.Ports)})
	}
	return v
}

func standardPorts(ports []networkingv1.NetworkPolicyPort) []string {
	if len(ports) == 0 {
		return []string{"any"}
	}
	out := []string{}
	for _, p := range ports {
		proto := "TCP"
		if p.Protocol != nil {
			proto = string(*p.Protocol)
		}
		if p.Port == nil {
			out = append(out, "any/"+proto)
			continue
		}
		s := p.Port.String()
		if p.EndPort != nil {
			s += fmt.Sprintf("-%d", *p.EndPort)
		}
		out = append(out, s+"/"+proto)
	}
	return out
}

// selectorText turns FormatLabelSelector's output into prose-friendly text.
func selectorText(s string) string {
	switch s {
	case "", "<none>":
		return "(all)"
	case "<error>":
		return "(invalid selector)"
	}
	return s
}

func describeCilium(p unstructured.Unstructured, workloads []Workload) PolicyView {
	rejected, isRejected := CiliumRejected(p)
	v := PolicyView{
		Key: p.GetKind() + "/" + ciliumPolicyKey(p), Kind: p.GetKind(),
		Namespace: p.GetNamespace(), Name: p.GetName(),
		IsolatesIngress: !isRejected && policyHasSection(p, "ingress"),
		IsolatesEgress:  !isRejected && policyHasSection(p, "egress"),
		Ingress:         []RuleView{}, Egress: []RuleView{},
	}
	v.Rejected = rejected
	sel, _, _ := unstructured.NestedMap(p.Object, "spec", "endpointSelector", "matchLabels")
	v.Selector = selectorText(ciliumLabelsText(sel))
	v.Selected = matchingWorkloads(workloads, func(pod corev1.Pod) bool { return selectsForCilium(p, pod) })

	endpointPeers := func(raw []interface{}) []PeerView {
		out := []PeerView{}
		for _, e := range raw {
			m, ok := e.(map[string]interface{})
			if !ok {
				continue
			}
			ml, _, _ := unstructured.NestedMap(m, "matchLabels")
			one := []interface{}{m}
			out = append(out, PeerView{Type: "pods", Label: "pods " + selectorText(ciliumLabelsText(ml)),
				Matches: matchingWorkloads(workloads, func(pod corev1.Pod) bool { return anyEndpointMatches(one, pod, p.GetNamespace()) })})
		}
		return out
	}
	rules := func(key, dir string) []RuleView {
		raw, _, _ := unstructured.NestedSlice(p.Object, "spec", key)
		out := []RuleView{}
		for _, r := range raw {
			rule, ok := r.(map[string]interface{})
			if !ok {
				continue
			}
			rv := RuleView{Deny: strings.HasSuffix(key, "Deny"), Ports: ciliumPorts(rule), Peers: []PeerView{}}
			rv.L7, _ = ruleHasL7(rule)
			eps, _, _ := unstructured.NestedSlice(rule, dir+"Endpoints")
			rv.Peers = append(rv.Peers, endpointPeers(eps)...)
			for _, e := range stringList(rule, dir+"Entities") {
				rv.Peers = append(rv.Peers, PeerView{Type: "entity", Label: "entity " + e})
			}
			if dir == "to" {
				for _, c := range cidrTargets(rule) {
					rv.Peers = append(rv.Peers, PeerView{Type: "cidr", Label: c})
				}
				names, patterns := fqdnNames(rule)
				for _, n := range append(names, patterns...) {
					rv.Peers = append(rv.Peers, PeerView{Type: "fqdn", Label: n})
				}
				if svcs, _, _ := unstructured.NestedSlice(rule, "toServices"); len(svcs) > 0 {
					rv.Peers = append(rv.Peers, PeerView{Type: "service", Label: fmt.Sprintf("%d Kubernetes Service(s) (toServices)", len(svcs))})
				}
			} else {
				for _, c := range append(stringList(rule, "fromCIDR"), cidrSetList(rule, "fromCIDRSet")...) {
					rv.Peers = append(rv.Peers, PeerView{Type: "cidr", Label: c})
				}
			}
			if len(rv.Peers) == 0 {
				rv.Peers = []PeerView{{Type: "any", Label: "any source or destination"}}
			}
			out = append(out, rv)
		}
		return out
	}
	v.Ingress = append(rules("ingress", "from"), rules("ingressDeny", "from")...)
	v.Egress = append(rules("egress", "to"), rules("egressDeny", "to")...)
	return v
}

func ciliumLabelsText(ml map[string]interface{}) string {
	if len(ml) == 0 {
		return ""
	}
	parts := []string{}
	for k, v := range stripCiliumLabelPrefixes(normalizeStringMap(ml)) {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func ciliumPorts(rule map[string]interface{}) []string {
	blocks, _, _ := unstructured.NestedSlice(rule, "toPorts")
	out := []string{}
	for _, raw := range blocks {
		block, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		ports, _, _ := unstructured.NestedSlice(block, "ports")
		for _, praw := range ports {
			pm, ok := praw.(map[string]interface{})
			if !ok {
				continue
			}
			port, _, _ := unstructured.NestedString(pm, "port")
			proto, _, _ := unstructured.NestedString(pm, "protocol")
			if proto == "" {
				proto = "ANY"
			}
			out = append(out, port+"/"+proto)
		}
	}
	if len(out) == 0 {
		return []string{"any"}
	}
	return out
}

func stringList(m map[string]interface{}, key string) []string {
	raw, _, _ := unstructured.NestedSlice(m, key)
	out := []string{}
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func cidrSetList(m map[string]interface{}, key string) []string {
	raw, _, _ := unstructured.NestedSlice(m, key)
	out := []string{}
	for _, v := range raw {
		if cm, ok := v.(map[string]interface{}); ok {
			if s, ok := cm["cidr"].(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
