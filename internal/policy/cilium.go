package policy

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
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
		if selectsForCilium(p, src) {
			if matched, skipped := ruleMatchesEgress(ctx, p, src, dst, port, "egressDeny"); matched {
				v.Denied = true
				v.HasPolicy = true
				v.Reason = fmt.Sprintf("egress denied by %s (egressDeny)", ciliumPolicyKey(p))
				v.Skipped += skipped
				return v
			}
		}
		if selectsForCilium(p, dst) {
			if matched, skipped := ruleMatchesIngress(p, src, dst, port, "ingressDeny"); matched {
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
		if selectsForCilium(p, src) && policyHasSection(p, "egress") {
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
		if selectsForCilium(p, dst) && policyHasSection(p, "ingress") {
			dstIsolated = true
			v.HasPolicy = true
			matched, ports, skipped, l7 := ruleMatchesIngressWithPorts(p, src, dst, port, "ingress")
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
// given pod. Cluster-wide policies (CCNP) consider every namespace; namespaced
// policies (CNP) only their own.
func selectsForCilium(p unstructured.Unstructured, pod corev1.Pod) bool {
	if p.GetKind() == "CiliumNetworkPolicy" && p.GetNamespace() != pod.Namespace {
		return false
	}
	sel, found, _ := unstructured.NestedMap(p.Object, "spec", "endpointSelector")
	if !found {
		return false
	}
	ml, _, _ := unstructured.NestedMap(sel, "matchLabels")
	if len(ml) == 0 {
		return true // empty selector matches all endpoints
	}
	mlStr := stripCiliumLabelPrefixes(normalizeStringMap(ml))
	s := labels.SelectorFromSet(labels.Set(mlStr))
	return s.Matches(labels.Set(pod.Labels))
}

func policyHasSection(p unstructured.Unstructured, key string) bool {
	list, found, _ := unstructured.NestedSlice(p.Object, "spec", key)
	return found && len(list) > 0
}

// ruleMatchesIngress returns true if any rule in spec.<key> permits traffic
// from src to dst (used for "ingress" and "ingressDeny" variants).
func ruleMatchesIngress(p unstructured.Unstructured, src, dst corev1.Pod, port int32, key string) (bool, int) {
	matched, _, skipped, _ := ruleMatchesIngressWithPorts(p, src, dst, port, key)
	return matched, skipped
}

func ruleMatchesEgress(ctx evalContext, p unstructured.Unstructured, src, dst corev1.Pod, port int32, key string) (bool, int) {
	matched, _, skipped, _ := ruleMatchesEgressWithPorts(ctx, p, src, dst, port, key)
	return matched, skipped
}

func ruleMatchesIngressWithPorts(p unstructured.Unstructured, src, dst corev1.Pod, port int32, key string) (matched bool, ports []string, skipped int, l7 bool) {
	rules, _, _ := unstructured.NestedSlice(p.Object, "spec", key)
	for _, r := range rules {
		ruleMap, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		from, _, _ := unstructured.NestedSlice(ruleMap, "fromEndpoints")
		_, hasL7 := ruleHasL7(ruleMap)
		if hasL7 {
			skipped++
		}
		hasUnsupported := hasFields(ruleMap, "fromFQDNs", "fromEntities", "fromCIDR", "fromCIDRSet", "fromRequires", "fromServices")
		if hasUnsupported {
			skipped++
			continue
		}
		// Match peer.
		if len(from) == 0 {
			// No fromEndpoints = match all sources (Cilium semantics)
		} else if !anyEndpointMatches(from, src, p.GetNamespace()) {
			continue
		}
		rulePorts, portsMatch, skippedPorts := evaluateToPorts(ruleMap, port)
		skipped += skippedPorts
		if !portsMatch {
			continue
		}
		// Matched at L4; report whether this rule also carried L7 conditions.
		return true, rulePorts, skipped, hasL7
	}
	return false, nil, skipped, false
}

func ruleMatchesEgressWithPorts(ctx evalContext, p unstructured.Unstructured, src, dst corev1.Pod, port int32, key string) (matched bool, ports []string, skipped int, l7 bool) {
	rules, _, _ := unstructured.NestedSlice(p.Object, "spec", key)
	for _, r := range rules {
		ruleMap, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		to, _, _ := unstructured.NestedSlice(ruleMap, "toEndpoints")
		_, hasL7 := ruleHasL7(ruleMap)
		if hasL7 {
			skipped++
		}

		// toFQDNs: resolve names and see if the destination pod's IP is one of
		// them. If so the rule matches as a real edge; if the FQDN resolves
		// only to external IPs (or can't be resolved), treat it as a skipped
		// rule so the verdict stays UNKNOWN rather than a false DENY.
		if _, hasFQDN := ruleMap["toFQDNs"]; hasFQDN {
			if fqdnRuleMatchesPod(ctx, ruleMap, dst) {
				rulePorts, portsMatch, skippedPorts := evaluateToPorts(ruleMap, port)
				skipped += skippedPorts
				if portsMatch {
					return true, rulePorts, skipped, hasL7
				}
			}
			skipped++
			continue
		}

		hasUnsupported := hasFields(ruleMap, "toEntities", "toCIDR", "toCIDRSet", "toRequires", "toServices")
		if hasUnsupported {
			skipped++
			continue
		}
		if len(to) == 0 {
			// no toEndpoints = match all destinations
		} else if !anyEndpointMatches(to, dst, p.GetNamespace()) {
			continue
		}
		rulePorts, portsMatch, skippedPorts := evaluateToPorts(ruleMap, port)
		skipped += skippedPorts
		if !portsMatch {
			continue
		}
		return true, rulePorts, skipped, hasL7
	}
	return false, nil, skipped, false
}

func anyEndpointMatches(peers []interface{}, pod corev1.Pod, policyNS string) bool {
	for _, raw := range peers {
		m, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		ml, _, _ := unstructured.NestedMap(m, "matchLabels")
		mlStr := normalizeStringMap(ml)
		// Cilium uses k8s:io.kubernetes.pod.namespace as a special label.
		// If absent in the selector, default to the policy's own namespace
		// (matching CNP convention).
		nsKey1 := "k8s:io.kubernetes.pod.namespace"
		nsKey2 := "io.kubernetes.pod.namespace"
		expectedNS := policyNS
		if v, ok := mlStr[nsKey1]; ok {
			expectedNS = v
			delete(mlStr, nsKey1)
		} else if v, ok := mlStr[nsKey2]; ok {
			expectedNS = v
			delete(mlStr, nsKey2)
		}
		if expectedNS != "" && pod.Namespace != expectedNS {
			continue
		}
		// Cilium label keys carry a source prefix ("k8s:", "any:", "reserved:")
		// that pod labels don't have. Strip it before matching so a selector
		// `k8s:app.kubernetes.io/name=api` matches a pod label
		// `app.kubernetes.io/name=api`.
		s := labels.SelectorFromSet(labels.Set(stripCiliumLabelPrefixes(mlStr)))
		if s.Matches(labels.Set(pod.Labels)) {
			return true
		}
	}
	return false
}

// stripCiliumLabelPrefixes normalizes selector keys to plain Kubernetes
// label keys for matching against pod.Labels. Cilium prefixes label keys
// with their source ("k8s:", "any:", "reserved:"); only the "k8s:" and
// "any:" sources correspond to keys that live on pod.Labels. A "reserved:"
// label (e.g. reserved:world, reserved:host) names a Cilium identity that
// no Pod object has, so we mark such selectors unmatchable by injecting a
// sentinel key. Keys without a recognised source prefix pass through.
func stripCiliumLabelPrefixes(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		switch {
		case strings.HasPrefix(k, "k8s:"):
			out[k[len("k8s:"):]] = v
		case strings.HasPrefix(k, "k8s."):
			out[k[len("k8s."):]] = v
		case strings.HasPrefix(k, "any:"):
			out[k[len("any:"):]] = v
		case strings.HasPrefix(k, "any."):
			out[k[len("any."):]] = v
		case strings.HasPrefix(k, "reserved:"):
			out["__cilium_reserved_"+k[len("reserved:"):]] = v
		default:
			out[k] = v
		}
	}
	return out
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
