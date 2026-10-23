package policy

import (
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
)

// ciliumVerdict is what the Cilium policies say about one pair: an
// explicit deny, which wins over everything, or what they isolate and
// open in each direction, to be unioned with the standard policies.
type ciliumVerdict struct {
	Denied  bool
	Reason  string // for Denied
	Egress  side
	Ingress side
}

// evaluateCilium reads the namespaced and cluster-wide Cilium policies that
// select src or dst.
func evaluateCilium(ctx evalContext, src, dst corev1.Pod, port int32) ciliumVerdict {
	applicable := []unstructured.Unstructured{}
	for _, p := range ctx.cnps {
		if p.GetNamespace() == src.Namespace || p.GetNamespace() == dst.Namespace {
			applicable = append(applicable, p)
		}
	}
	applicable = append(applicable, ctx.ccnps...)

	var v ciliumVerdict
	for _, p := range applicable {
		if selectsForCilium(ctx, p, src) {
			if matched, _ := ruleMatchesEgress(ctx, p, src, dst, port, "egressDeny"); matched {
				return ciliumVerdict{Denied: true, Reason: fmt.Sprintf("egress denied by %s (egressDeny)", ciliumPolicyKey(p))}
			}
		}
		if selectsForCilium(ctx, p, dst) {
			if matched, _ := ruleMatchesIngress(ctx, p, src, dst, port, "ingressDeny"); matched {
				return ciliumVerdict{Denied: true, Reason: fmt.Sprintf("ingress denied by %s (ingressDeny)", ciliumPolicyKey(p))}
			}
		}
	}
	for _, p := range applicable {
		if selectsForCilium(ctx, p, src) && ciliumIsolates(p, "egress") {
			v.Egress.isolated = true
			v.Egress.isolatedBy = append(v.Egress.isolatedBy, ciliumPolicyKey(p))
			matched, ports, skipped, l7 := ruleMatchesEgressWithPorts(ctx, p, src, dst, port, "egress")
			v.Egress.skipped += skipped
			if matched {
				v.Egress.ports = append(v.Egress.ports, ports...)
				v.Egress.allowedBy = append(v.Egress.allowedBy, ciliumPolicyKey(p))
				v.Egress.l7 = v.Egress.l7 || l7
			}
		}
		if selectsForCilium(ctx, p, dst) && ciliumIsolates(p, "ingress") {
			v.Ingress.isolated = true
			v.Ingress.isolatedBy = append(v.Ingress.isolatedBy, ciliumPolicyKey(p))
			matched, ports, skipped, l7 := ruleMatchesIngressWithPorts(ctx, p, src, dst, port, "ingress")
			v.Ingress.skipped += skipped
			if matched {
				v.Ingress.ports = append(v.Ingress.ports, ports...)
				v.Ingress.allowedBy = append(v.Ingress.allowedBy, ciliumPolicyKey(p))
				v.Ingress.l7 = v.Ingress.l7 || l7
			}
		}
	}
	return v
}

// selectsForCilium reports whether the policy's endpointSelector matches the
// pod. A CiliumNetworkPolicy's endpointSelector always applies to its own
// namespace only; a cluster-wide policy considers every namespace. A policy
// with a nodeSelector instead is a host policy and selects no pod.
func selectsForCilium(ctx evalContext, p unstructured.Unstructured, pod corev1.Pod) bool {
	if p.GetKind() == "CiliumNetworkPolicy" && p.GetNamespace() != pod.Namespace {
		return false
	}
	sel, found, _ := unstructured.NestedMap(p.Object, "spec", "endpointSelector")
	if !found {
		return false
	}
	s, _, ok := ciliumSelector(sel)
	return ok && s.Matches(ciliumLabels(pod, ctx.nsLabels[pod.Namespace]))
}

const (
	ciliumNamespaceKey          = "io.kubernetes.pod.namespace"
	ciliumNamespaceLabelsPrefix = "io.cilium.k8s.namespace.labels."
)

// ciliumLabels is the label set Cilium matches selectors against for a pod:
// its own labels plus the namespace, the namespace's labels and the service
// account, as Cilium derives them. Source prefixes ("k8s:") are absent here
// and stripped from the selector side instead.
func ciliumLabels(pod corev1.Pod, nsLabels map[string]string) labels.Set {
	set := labels.Set{}
	for k, v := range pod.Labels {
		set[k] = v
	}
	set[ciliumNamespaceKey] = pod.Namespace
	if sa := pod.Spec.ServiceAccountName; sa != "" {
		set["io.cilium.k8s.policy.serviceaccount"] = sa
	}
	for k, v := range nsLabels {
		set[ciliumNamespaceLabelsPrefix+k] = v
	}
	return set
}

// parseCiliumSelector reads an endpoint selector (matchLabels and
// matchExpressions) with its keys normalised to the plain pod label keys.
func parseCiliumSelector(sel map[string]interface{}) (*metav1.LabelSelector, error) {
	var ls metav1.LabelSelector
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(sel, &ls); err != nil {
		return nil, err
	}
	ml := make(map[string]string, len(ls.MatchLabels))
	for k, v := range ls.MatchLabels {
		ml[stripCiliumPrefix(k)] = v
	}
	ls.MatchLabels = ml
	for i := range ls.MatchExpressions {
		ls.MatchExpressions[i].Key = stripCiliumPrefix(ls.MatchExpressions[i].Key)
	}
	return &ls, nil
}

// ciliumSelector compiles an endpoint selector. namespaced reports whether
// it constrains the namespace itself (by name or namespace labels), which
// switches off the implicit same-namespace match of a CiliumNetworkPolicy
// peer. ok is false for a malformed selector, which then matches nothing.
func ciliumSelector(sel map[string]interface{}) (s labels.Selector, namespaced bool, ok bool) {
	ls, err := parseCiliumSelector(sel)
	if err != nil {
		return nil, false, false
	}
	for k := range ls.MatchLabels {
		namespaced = namespaced || namesNamespace(k)
	}
	for _, e := range ls.MatchExpressions {
		namespaced = namespaced || namesNamespace(e.Key)
	}
	s, err = metav1.LabelSelectorAsSelector(ls)
	if err != nil {
		return nil, false, false
	}
	return s, namespaced, true
}

func namesNamespace(key string) bool {
	return key == ciliumNamespaceKey || strings.HasPrefix(key, ciliumNamespaceLabelsPrefix)
}

// ciliumSelectorText renders a selector as "k=v,k2 in (a,b)" for display.
func ciliumSelectorText(sel map[string]interface{}) string {
	ls, err := parseCiliumSelector(sel)
	if err != nil {
		return "<error>"
	}
	return metav1.FormatLabelSelector(ls)
}

// stripCiliumPrefix drops the label source ("k8s:", "any:") so a selector
// key compares with the plain pod label. A "reserved:" label names a Cilium
// identity (world, host, ...) that no pod carries; it is kept under a key no
// pod has, so In/Exists never match a pod and NotIn/DoesNotExist always do.
func stripCiliumPrefix(k string) string {
	for _, p := range []string{"k8s:", "any:"} {
		if strings.HasPrefix(k, p) {
			return k[len(p):]
		}
	}
	if strings.HasPrefix(k, "reserved:") {
		return "reserved.cilium.io/" + k[len("reserved:"):]
	}
	return k
}

// CiliumRejected reports whether Cilium refused to import the policy
// (status condition Valid=False, the VALID column of kubectl get cnp) and
// why. A rejected policy is not enforced at all, so it is listed but takes
// no part in verdicts. Manifests read offline carry no status and count as
// enforced.
func CiliumRejected(p unstructured.Unstructured) (string, bool) {
	conds, _, _ := unstructured.NestedSlice(p.Object, "status", "conditions")
	for _, c := range conds {
		m, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		if m["type"] == "Valid" && m["status"] == "False" {
			msg, _ := m["message"].(string)
			if msg == "" {
				msg = "status condition Valid=False"
			}
			return msg, true
		}
	}
	return "", false
}

// enforcedCilium drops the policies Cilium rejected.
func enforcedCilium(ps []unstructured.Unstructured) []unstructured.Unstructured {
	out := ps[:0:0]
	for _, p := range ps {
		if _, rejected := CiliumRejected(p); !rejected {
			out = append(out, p)
		}
	}
	return out
}

func policyHasSection(p unstructured.Unstructured, key string) bool {
	list, found, _ := unstructured.NestedSlice(p.Object, "spec", key)
	return found && len(list) > 0
}

// ciliumIsolates reports whether the policy puts the endpoints it selects
// into default-deny for dir ("ingress" or "egress"). Any rule in that
// direction counts, deny rules included (a policy with only egressDeny
// still isolates egress), unless spec.enableDefaultDeny.<dir> is false.
func ciliumIsolates(p unstructured.Unstructured, dir string) bool {
	if enabled, found, _ := unstructured.NestedBool(p.Object, "spec", "enableDefaultDeny", dir); found && !enabled {
		return false
	}
	return policyHasSection(p, dir) || policyHasSection(p, dir+"Deny")
}

// ruleMatchesIngress returns true if any rule in spec.<key> permits traffic
// from src to dst (used for "ingress" and "ingressDeny" variants).
func ruleMatchesIngress(ctx evalContext, p unstructured.Unstructured, src, dst corev1.Pod, port int32, key string) (bool, int) {
	matched, _, skipped, _ := ruleMatchesIngressWithPorts(ctx, p, src, dst, port, key)
	return matched, skipped
}

func ruleMatchesEgress(ctx evalContext, p unstructured.Unstructured, src, dst corev1.Pod, port int32, key string) (bool, int) {
	matched, _, skipped, _ := ruleMatchesEgressWithPorts(ctx, p, src, dst, port, key)
	return matched, skipped
}

// peerMatch is the outcome of matching one rule's peer selectors against a
// pod. A rule counts as skipped (and the verdict as UNKNOWN) only when it
// cannot be decided for pod-to-pod traffic: an unresolved or wildcard FQDN,
// or a toServices/fromRequires/toRequires clause. Everything else is a
// plain yes or no.
type peerMatch struct {
	matched   bool
	undecided bool
}

// entitiesMatchPods reports whether an entity list can match in-cluster
// pods. Per Cilium's entity definitions "all" and "cluster" cover every
// endpoint in the cluster; world, host, remote-node, kube-apiserver, ingress,
// init, health and unmanaged name things that are not pods.
func entitiesMatchPods(ents []string) bool {
	for _, e := range ents {
		if e == "all" || e == "cluster" {
			return true
		}
	}
	return false
}

// matchEgressPeers decides whether an egress rule's to* selectors cover dst,
// following Cilium semantics for pod-to-pod traffic:
//   - the selector lists of one rule each allow independently;
//   - toCIDR/toCIDRSet apply only to destinations outside the cluster, so
//     they never match a pod, whatever its IP;
//   - toFQDNs matches a pod only if a name resolves to that pod's IP; names
//     that all resolve elsewhere are a decided non-match, unresolved names
//     or wildcard patterns are undecided;
//   - toServices and toRequires are not evaluated.
func matchEgressPeers(ctx evalContext, rule map[string]interface{}, dst corev1.Pod, policyNS string) peerMatch {
	var m peerMatch
	to, _, _ := unstructured.NestedSlice(rule, "toEndpoints")
	if len(to) > 0 && anyEndpointMatches(ctx, to, dst, policyNS) {
		m.matched = true
	}
	if entitiesMatchPods(entityTargets(rule)) {
		m.matched = true
	}
	if _, has := rule["toFQDNs"]; has {
		switch {
		case fqdnRuleMatchesPod(ctx, rule, dst):
			m.matched = true
		case !fqdnDecidable(ctx, rule):
			m.undecided = true
		}
	}
	if hasFields(rule, "toServices", "toRequires") {
		m.undecided = true
	}
	if !hasFields(rule, "toEndpoints", "toEntities", "toFQDNs", "toCIDR", "toCIDRSet", "toServices", "toRequires") {
		m.matched = true // no selector at all: every destination
	}
	return m
}

// matchIngressPeers is the ingress counterpart: fromCIDR/fromCIDRSet apply
// only to sources outside the cluster and never match a pod.
func matchIngressPeers(ctx evalContext, rule map[string]interface{}, src corev1.Pod, policyNS string) peerMatch {
	var m peerMatch
	from, _, _ := unstructured.NestedSlice(rule, "fromEndpoints")
	if len(from) > 0 && anyEndpointMatches(ctx, from, src, policyNS) {
		m.matched = true
	}
	if entitiesMatchPods(stringList(rule, "fromEntities")) {
		m.matched = true
	}
	if hasFields(rule, "fromRequires") {
		m.undecided = true
	}
	if !hasFields(rule, "fromEndpoints", "fromEntities", "fromCIDR", "fromCIDRSet", "fromRequires") {
		m.matched = true
	}
	return m
}

// matchRules walks spec.<key> and returns the first rule whose peers and
// ports cover the pair. L7 conditions on a matching rule are reported, not
// evaluated; rules that could not be decided are counted in skipped.
func matchRules(rules []interface{}, port int32, dst corev1.Pod, peers func(map[string]interface{}) peerMatch) (matched bool, ports []string, skipped int, l7 bool) {
	for _, r := range rules {
		rule, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		m := peers(rule)
		if !m.matched {
			if m.undecided {
				skipped++
			}
			continue
		}
		rulePorts, portsMatch := evaluateToPorts(rule, port, dst)
		if !portsMatch {
			continue
		}
		return true, rulePorts, skipped, ruleHasL7(rule)
	}
	return false, nil, skipped, false
}

func ruleMatchesIngressWithPorts(ctx evalContext, p unstructured.Unstructured, src, dst corev1.Pod, port int32, key string) (bool, []string, int, bool) {
	rules, _, _ := unstructured.NestedSlice(p.Object, "spec", key)
	return matchRules(rules, port, dst, func(rule map[string]interface{}) peerMatch {
		return matchIngressPeers(ctx, rule, src, p.GetNamespace())
	})
}

func ruleMatchesEgressWithPorts(ctx evalContext, p unstructured.Unstructured, src, dst corev1.Pod, port int32, key string) (bool, []string, int, bool) {
	rules, _, _ := unstructured.NestedSlice(p.Object, "spec", key)
	return matchRules(rules, port, dst, func(rule map[string]interface{}) peerMatch { return matchEgressPeers(ctx, rule, dst, p.GetNamespace()) })
}

// anyEndpointMatches reports whether a fromEndpoints/toEndpoints list covers
// the pod. In a CiliumNetworkPolicy (policyNS set) a peer selector that does
// not name a namespace is implicitly limited to the policy's own namespace.
func anyEndpointMatches(ctx evalContext, peers []interface{}, pod corev1.Pod, policyNS string) bool {
	for _, raw := range peers {
		m, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		s, namespaced, ok := ciliumSelector(m)
		if !ok || (policyNS != "" && !namespaced && pod.Namespace != policyNS) {
			continue
		}
		if s.Matches(ciliumLabels(pod, ctx.nsLabels[pod.Namespace])) {
			return true
		}
	}
	return false
}

// evaluateToPorts reads what a rule opens at L4 and whether that covers the
// filtered port (0 = any). Cilium's protocol defaults to ANY, endPort gives
// a range, a named port resolves against dst and matches nothing when no
// container declares it, and a rule with only icmps opens no L4 port.
func evaluateToPorts(rule map[string]interface{}, filter int32, dst corev1.Pod) ([]string, bool) {
	blocks, _, _ := unstructured.NestedSlice(rule, "toPorts")
	_, hasICMP, _ := unstructured.NestedSlice(rule, "icmps")
	if len(blocks) == 0 && !hasICMP {
		return []string{"*"}, true
	}
	out := []string{}
	if hasICMP {
		out = append(out, "ICMP")
	}
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
			portStr, _, _ := unstructured.NestedString(pm, "port")
			spec := portSpec{proto: "ANY"}
			if proto, _, _ := unstructured.NestedString(pm, "protocol"); proto != "" {
				spec.proto = strings.ToUpper(proto)
			}
			if n, err := strconv.Atoi(portStr); err == nil {
				spec.lo = int32(n)
			} else if portStr != "" {
				spec.lo = containerPortByName(dst, portStr)
				if spec.lo == 0 {
					continue
				}
			}
			spec.hi = spec.lo
			if end, found, _ := unstructured.NestedInt64(pm, "endPort"); found && end > 0 {
				spec.hi = int32(end)
			}
			if filter != 0 && !spec.covers(filter, "") {
				continue
			}
			out = append(out, spec.String())
		}
	}
	if filter != 0 {
		return out, portsCover(out, filter, "")
	}
	for _, s := range out {
		if s != "ICMP" {
			return out, true
		}
	}
	return out, false
}

// ruleHasL7 detects rules that reference Layer 7 features so we can flag
// (not evaluate) them — they apply on top of L4 in real Cilium, but our
// engine only handles L4.
func ruleHasL7(rule map[string]interface{}) bool {
	blocks, _, _ := unstructured.NestedSlice(rule, "toPorts")
	for _, raw := range blocks {
		block, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		rules, found, _ := unstructured.NestedMap(block, "rules")
		if found && len(rules) > 0 {
			return true
		}
	}
	return false
}

func hasFields(m map[string]interface{}, fields ...string) bool {
	for _, f := range fields {
		if _, ok := m[f]; ok {
			return true
		}
	}
	return false
}

func ciliumPolicyKey(p unstructured.Unstructured) string {
	if p.GetNamespace() == "" {
		return p.GetKind() + "/" + p.GetName()
	}
	return p.GetNamespace() + "/" + p.GetName()
}

func normalizeStringMap(in map[string]interface{}) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		switch x := v.(type) {
		case string:
			out[k] = x
		default:
			out[k] = fmt.Sprintf("%v", x)
		}
	}
	return out
}
