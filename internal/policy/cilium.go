package policy

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
)

// ciliumVerdict captures what Cilium policies imply for one edge, kept
// separate from the standard NP verdict so we can compose them at decision
// time.
type ciliumVerdict struct {
	// HasPolicy is true if at least one Cilium policy applies to src or dst
	// (i.e., this edge falls under some Cilium endpointSelector). When false
	// the Cilium layer is silent — only the standard NP verdict matters.
	HasPolicy bool
	// Allowed is true when an applicable Cilium policy permits the edge
	// (or no applicable policy denies it).
	Allowed bool
	// Denied is true when a Cilium deny rule (ingressDeny/egressDeny) matches.
	// Deny overrides any allow on the same edge.
	Denied bool
	// Ports is the union of allowed Cilium ports for this edge (empty = all).
	Ports []string
	// Reason describes the Cilium-side decision in one line.
	Reason string
	// Skipped is the count of rules that referenced features we don't
	// evaluate (HTTP, DNS, FQDN, toEntities, toServices). Surfaced to the
	// user so they know the verdict is L4-only.
	Skipped int
	// Uncertain is true when this verdict is a deny that rests on incomplete
	// information: the endpoint is isolated, no evaluated rule matched, but
	// one or more skipped (L7/FQDN/entity/CIDR) rules might have allowed the
	// edge. The caller should surface this as UNKNOWN, not DENY.
	Uncertain bool
	// L7Restricted is true when the edge is allowed at L4 but the matching
	// allow rule also carries L7 conditions this engine does not evaluate.
	L7Restricted bool
}

// evaluateCilium decides what the Cilium layer says about src→dst.
// Both namespaced CNPs and cluster-wide CCNPs are considered.
func evaluateCilium(
	ctx evalContext,
	src, dst corev1.Pod,
	port int32,
) ciliumVerdict {
	cnps := ctx.cnps
	ccnps := ctx.ccnps
	v := ciliumVerdict{Allowed: true} // optimistic until proven otherwise

	// All applicable policies (CNPs filtered by namespace, CCNPs always).
	applicable := []unstructured.Unstructured{}
	for _, p := range cnps {
		if p.GetNamespace() == src.Namespace || p.GetNamespace() == dst.Namespace {
			applicable = append(applicable, p)
		}
	}
	applicable = append(applicable, ccnps...)

	// Pass 1: explicit denies always win.
	for _, p := range applicable {
		if selectsForCilium(ctx, p, src) {
			if matched, skipped := ruleMatchesEgress(ctx, p, src, dst, port, "egressDeny"); matched {
				v.Denied = true
				v.HasPolicy = true
				v.Reason = fmt.Sprintf("egress denied by %s (egressDeny)", ciliumPolicyKey(p))
				v.Skipped += skipped
				return v
			}
		}
		if selectsForCilium(ctx, p, dst) {
			if matched, skipped := ruleMatchesIngress(ctx, p, src, dst, port, "ingressDeny"); matched {
				v.Denied = true
				v.HasPolicy = true
				v.Reason = fmt.Sprintf("ingress denied by %s (ingressDeny)", ciliumPolicyKey(p))
				v.Skipped += skipped
				return v
			}
		}
	}

	// Pass 2: allow rules. Cilium semantics — if any policy selects the
	// endpoint for a direction, that direction becomes isolated and only an
	// explicit allow rule lets traffic through.
	srcIsolated := false
	dstIsolated := false
	srcAllowed := false
	dstAllowed := false
	allowReasons := []string{}
	portSet := map[string]bool{}

	for _, p := range applicable {
		if selectsForCilium(ctx, p, src) && policyHasSection(p, "egress") {
			srcIsolated = true
			v.HasPolicy = true
			matched, ports, skipped, l7 := ruleMatchesEgressWithPorts(ctx, p, src, dst, port, "egress")
			v.Skipped += skipped
			if matched {
				srcAllowed = true
				if l7 {
					v.L7Restricted = true
				}
				allowReasons = append(allowReasons, "egress: "+ciliumPolicyKey(p))
				for _, pp := range ports {
					portSet[pp] = true
				}
			}
		}
		if selectsForCilium(ctx, p, dst) && policyHasSection(p, "ingress") {
			dstIsolated = true
			v.HasPolicy = true
			matched, ports, skipped, l7 := ruleMatchesIngressWithPorts(ctx, p, src, dst, port, "ingress")
			v.Skipped += skipped
			if matched {
				dstAllowed = true
				if l7 {
					v.L7Restricted = true
				}
				allowReasons = append(allowReasons, "ingress: "+ciliumPolicyKey(p))
				for _, pp := range ports {
					portSet[pp] = true
				}
			}
		}
	}

	if srcIsolated && !srcAllowed {
		v.Allowed = false
		if v.Skipped > 0 {
			v.Uncertain = true
			v.Reason = fmt.Sprintf("Cilium: src isolated for egress; no evaluated rule matches dst, but %d L7/FQDN/CIDR rule(s) were not evaluated", v.Skipped)
		} else {
			v.Reason = "Cilium: src isolated for egress; no Cilium rule matches dst"
		}
		return v
	}
	if dstIsolated && !dstAllowed {
		v.Allowed = false
		if v.Skipped > 0 {
			v.Uncertain = true
			v.Reason = fmt.Sprintf("Cilium: dst isolated for ingress; no evaluated rule allows src, but %d L7/FQDN/CIDR rule(s) were not evaluated", v.Skipped)
		} else {
			v.Reason = "Cilium: dst isolated for ingress; no Cilium rule allows src"
		}
		return v
	}

	if v.HasPolicy {
		v.Ports = sortedKeys(portSet)
		if len(allowReasons) > 0 {
			v.Reason = "Cilium " + strings.Join(allowReasons, "; ")
		} else {
			v.Reason = "Cilium: no policy restricts this edge"
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
func matchRules(rules []interface{}, port int32, peers func(map[string]interface{}) peerMatch) (matched bool, ports []string, skipped int, l7 bool) {
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
		rulePorts, portsMatch, skippedPorts := evaluateToPorts(rule, port)
		if !portsMatch {
			continue
		}
		_, hasL7 := ruleHasL7(rule)
		return true, rulePorts, skipped + skippedPorts, hasL7
	}
	return false, nil, skipped, false
}

func ruleMatchesIngressWithPorts(ctx evalContext, p unstructured.Unstructured, src, dst corev1.Pod, port int32, key string) (bool, []string, int, bool) {
	rules, _, _ := unstructured.NestedSlice(p.Object, "spec", key)
	return matchRules(rules, port, func(rule map[string]interface{}) peerMatch {
		return matchIngressPeers(ctx, rule, src, p.GetNamespace())
	})
}

func ruleMatchesEgressWithPorts(ctx evalContext, p unstructured.Unstructured, src, dst corev1.Pod, port int32, key string) (bool, []string, int, bool) {
	rules, _, _ := unstructured.NestedSlice(p.Object, "spec", key)
	return matchRules(rules, port, func(rule map[string]interface{}) peerMatch { return matchEgressPeers(ctx, rule, dst, p.GetNamespace()) })
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

// evaluateToPorts inspects rule.toPorts. Returns the matching port strings
// (e.g. "80", "5432"), whether the port filter matched, and how many port
// blocks were skipped because of unsupported features (e.g. http/dns rules).
func evaluateToPorts(rule map[string]interface{}, filter int32) ([]string, bool, int) {
	blocks, found, _ := unstructured.NestedSlice(rule, "toPorts")
	if !found || len(blocks) == 0 {
		return []string{"*"}, true, 0
	}
	skipped := 0
	out := []string{}
	matched := false
	for _, raw := range blocks {
		block, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if _, hasHTTP, _ := unstructured.NestedSlice(block, "rules", "http"); hasHTTP {
			skipped++
		}
		if _, hasDNS, _ := unstructured.NestedSlice(block, "rules", "dns"); hasDNS {
			skipped++
		}
		ports, _, _ := unstructured.NestedSlice(block, "ports")
		for _, praw := range ports {
			pm, ok := praw.(map[string]interface{})
			if !ok {
				continue
			}
			portStr, _, _ := unstructured.NestedString(pm, "port")
			if portStr == "" {
				continue
			}
			if filter != 0 && portStr != intToStr(filter) {
				continue
			}
			out = append(out, portStr)
			matched = true
		}
	}
	if !matched {
		return nil, false, skipped
	}
	return out, true, skipped
}

// ruleHasL7 detects rules that reference Layer 7 features so we can flag
// (not evaluate) them — they apply on top of L4 in real Cilium, but our
// engine only handles L4.
func ruleHasL7(rule map[string]interface{}) (bool, bool) {
	blocks, _, _ := unstructured.NestedSlice(rule, "toPorts")
	for _, raw := range blocks {
		block, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		rules, found, _ := unstructured.NestedMap(block, "rules")
		if found && len(rules) > 0 {
			return true, true
		}
	}
	return false, false
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

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func intToStr(i int32) string {
	return fmt.Sprintf("%d", i)
}
