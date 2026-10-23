package policy

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// externalTarget is a destination outside the cluster: a host name, an IP
// or CIDR, or the internet at large ("internet").
type externalTarget struct {
	raw     string
	host    string       // DNS name, when given as one
	addrs   []netip.Addr // the IP given, or what host resolved to
	prefix  netip.Prefix // set when given as a CIDR
	generic bool         // any public address
}

// parseExternal recognises "internet", an IP, a CIDR, or a DNS name with
// three or more labels whose third label is not "svc" (that form is an
// in-cluster Service name).
func parseExternal(s string) (externalTarget, bool) {
	t := externalTarget{raw: s}
	switch {
	case strings.EqualFold(s, "internet"):
		t.generic = true
	case isCIDR(s):
		t.prefix = netip.MustParsePrefix(s)
	case isAddr(s):
		t.addrs = []netip.Addr{netip.MustParseAddr(s)}
	default:
		parts := strings.Split(s, ".")
		if len(parts) < 3 || parts[2] == "svc" {
			return t, false
		}
		t.host = normalizeFQDN(s)
	}
	return t, true
}

func isCIDR(s string) bool { _, err := netip.ParsePrefix(s); return err == nil }
func isAddr(s string) bool { _, err := netip.ParseAddr(s); return err == nil }

// externalLayers walks the chain for a destination outside the cluster.
func externalLayers(ctx evalContext, snap *Snapshot, srcPods []corev1.Pod, t externalTarget, port int32) []Layer {
	var layers []Layer
	if t.host != "" {
		layers = append(layers, dnsEgressLayer(ctx, snap, srcPods))
		for _, ip := range ctx.resolver.Resolve(t.host) {
			if a, err := netip.ParseAddr(ip); err == nil {
				t.addrs = append(t.addrs, a)
			}
		}
	}
	layers = append(layers, egressPolicyLayer(ctx, srcPods, t, port), externalMeshLayer(srcPods))
	return layers
}

// externalVerdict is one source pod's egress verdict toward the target.
type externalVerdict struct {
	status   LayerStatus
	reason   string
	ports    []string
	limited  []string // for "internet": the only destinations rules open
	fix      string
	isolated bool // some policy of this kind restricts the source's egress
	denied   bool // a Cilium egressDeny covers the target
}

func egressPolicyLayer(ctx evalContext, srcPods []corev1.Pod, t externalTarget, port int32) Layer {
	byStatus := map[LayerStatus][]externalVerdict{}
	for _, p := range srcPods {
		v := decideExternal(ctx, p, t, port)
		byStatus[v.status] = append(byStatus[v.status], v)
	}
	l := Layer{Name: "Egress policy"}
	if len(byStatus) > 1 {
		l.Status = LayerWarn
		parts := []string{}
		for _, s := range []LayerStatus{LayerPass, LayerWarn, LayerFail} {
			if n := len(byStatus[s]); n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, s))
			}
		}
		l.Summary = "mixed across the source pods: " + strings.Join(parts, ", ")
		for _, s := range []LayerStatus{LayerFail, LayerWarn, LayerPass} {
			for _, v := range byStatus[s] {
				l.Detail = append(l.Detail, string(s)+": "+v.reason)
			}
		}
		return l
	}
	for s, vs := range byStatus {
		v := vs[0]
		l.Status, l.Summary, l.Fix = s, v.reason, v.fix
		if len(vs) > 1 {
			l.Summary += fmt.Sprintf(" (all %d source pods)", len(vs))
		}
		if len(v.limited) > 0 {
			l.Detail = append(l.Detail, "reachable: "+strings.Join(v.limited, ", "))
		}
	}
	return l
}

// decideExternal composes the standard and Cilium egress verdicts for one
// source pod toward an external target. Cilium enforces both kinds from one
// pool: a deny wins, otherwise a rule of either kind opens the target and
// a policy of either kind isolates the source.
func decideExternal(ctx evalContext, src corev1.Pod, t externalTarget, port int32) externalVerdict {
	std := standardExternalEgress(ctx, src, t, port)
	if len(ctx.cnps)+len(ctx.ccnps) == 0 {
		return std
	}
	cil := ciliumExternalEgress(ctx, src, t, port)
	if cil.denied {
		return cil
	}
	if !std.isolated && !cil.isolated {
		return externalVerdict{status: LayerPass, ports: []string{"*"}, reason: "no policy restricts egress"}
	}
	out := externalVerdict{isolated: true, limited: append(append([]string{}, std.limited...), cil.limited...)}
	sort.Strings(out.limited)
	var reasons []string
	for _, v := range []externalVerdict{std, cil} {
		if v.isolated && v.status == LayerPass {
			out.ports = append(out.ports, v.ports...)
			reasons = append(reasons, v.reason)
		}
	}
	if len(out.ports) > 0 {
		out.status, out.ports, out.reason = LayerPass, unique(out.ports), strings.Join(reasons, "; ")
		if !(len(out.ports) == 1 && out.ports[0] == "*") {
			out.reason += " (ports " + strings.Join(DisplayPorts(out.ports), ",") + ")"
		}
		return out
	}
	// Closed by every kind that isolates: a caveat from either keeps the
	// verdict a warning, otherwise it is a fail with both explanations.
	out.status = LayerFail
	for _, v := range []externalVerdict{std, cil} {
		if !v.isolated {
			continue
		}
		if v.status == LayerWarn {
			out.status, out.reason, out.fix = LayerWarn, v.reason, v.fix
			return out
		}
		reasons = append(reasons, v.reason)
		if out.fix == "" {
			out.fix = v.fix
		}
	}
	out.reason = strings.Join(reasons, "; ")
	return out
}

func standardExternalEgress(ctx evalContext, src corev1.Pod, t externalTarget, port int32) externalVerdict {
	var isolating []networkingv1.NetworkPolicy
	for _, p := range ctx.policies {
		if p.Namespace == src.Namespace && selects(p.Spec.PodSelector, src) && hasType(p, networkingv1.PolicyTypeEgress) {
			isolating = append(isolating, p)
		}
	}
	if len(isolating) == 0 {
		return externalVerdict{status: LayerPass, ports: []string{"*"}, reason: "no NetworkPolicy restricts egress"}
	}
	v := externalVerdict{isolated: true}
	matched := []string{}
	for _, p := range isolating {
		for _, rule := range p.Spec.Egress {
			ports, _ := rulePorts(rule.Ports, port, corev1.Pod{}) // a named port never matches a non-pod destination
			if len(ports) == 0 {
				continue
			}
			if len(rule.To) == 0 {
				v.ports = append(v.ports, ports...)
				matched = append(matched, p.Namespace+"/"+p.Name+" (to anywhere)")
				continue
			}
			for _, peer := range rule.To {
				if peer.IPBlock == nil {
					continue
				}
				cidr, except := peer.IPBlock.CIDR, peer.IPBlock.Except
				switch {
				case t.generic && coversEverything(cidr):
					v.ports = append(v.ports, ports...)
					matched = append(matched, p.Namespace+"/"+p.Name+" (ipBlock "+cidr+")")
				case t.generic:
					v.limited = append(v.limited, cidr)
				case cidrCovers(cidr, except, t):
					v.ports = append(v.ports, ports...)
					matched = append(matched, p.Namespace+"/"+p.Name+" (ipBlock "+cidr+")")
				}
			}
		}
	}
	switch {
	case len(matched) > 0:
		v.status, v.reason = LayerPass, "egress allowed by "+strings.Join(unique(matched), ", ")
	case len(v.limited) > 0:
		v.status = LayerWarn
		v.reason = fmt.Sprintf("src isolated for egress by %s; only specific CIDRs are opened, not the whole internet", policyNames(isolating))
	case t.host != "" && len(t.addrs) == 0 && hasIPBlockRules(isolating):
		v.status = LayerWarn
		v.reason = fmt.Sprintf("src isolated for egress by %s with ipBlock rules, but %q was not resolved so they cannot be matched (use --resolve-fqdn)", policyNames(isolating), t.host)
	default:
		v.status = LayerFail
		v.reason = fmt.Sprintf("src isolated for egress by %s; no ipBlock rule covers %s", policyNames(isolating), t.raw)
		v.fix = "add an egress rule with `to: [{ipBlock: {cidr: 0.0.0.0/0, except: [<cluster and node CIDRs>]}}]`\n" +
			"  (plus UDP/TCP 53 to kube-dns) to the source's NetworkPolicy"
	}
	return v
}

func hasIPBlockRules(ps []networkingv1.NetworkPolicy) bool {
	for _, p := range ps {
		for _, r := range p.Spec.Egress {
			for _, peer := range r.To {
				if peer.IPBlock != nil {
					return true
				}
			}
		}
	}
	return false
}

func ciliumExternalEgress(ctx evalContext, src corev1.Pod, t externalTarget, port int32) externalVerdict {
	var applicable []unstructured.Unstructured
	for _, p := range ctx.cnps {
		if p.GetNamespace() == src.Namespace && selectsForCilium(ctx, p, src) {
			applicable = append(applicable, p)
		}
	}
	for _, p := range ctx.ccnps {
		if selectsForCilium(ctx, p, src) {
			applicable = append(applicable, p)
		}
	}
	v := externalVerdict{}
	isolated := false
	skipped := 0
	matched := []string{}
	isolatingNames := []string{}
	for _, p := range applicable {
		if m, name := ciliumRulesCover(p, "egressDeny", t, port); m {
			return externalVerdict{status: LayerFail, denied: true, isolated: true, reason: fmt.Sprintf("egress denied by %s (egressDeny %s)", ciliumPolicyKey(p), name)}
		}
		if !ciliumIsolates(p, "egress") {
			continue
		}
		isolated = true
		isolatingNames = append(isolatingNames, ciliumPolicyKey(p))
		rules, _, _ := unstructured.NestedSlice(p.Object, "spec", "egress")
		for _, r := range rules {
			rule, ok := r.(map[string]interface{})
			if !ok {
				continue
			}
			ports, portsMatch := evaluateToPorts(rule, port, corev1.Pod{}) // a named port never matches a non-pod destination
			if !portsMatch {
				continue
			}
			how, limited, unknown := ciliumRuleReaches(rule, t)
			v.limited = append(v.limited, limited...)
			if unknown {
				skipped++
			}
			if how != "" {
				v.ports = append(v.ports, ports...)
				matched = append(matched, ciliumPolicyKey(p)+" ("+how+")")
			}
		}
	}
	v.isolated = isolated
	switch {
	case !isolated:
		return externalVerdict{status: LayerPass, ports: []string{"*"}, reason: "no Cilium policy restricts egress"}
	case len(matched) > 0:
		v.status, v.reason = LayerPass, "Cilium egress allowed by "+strings.Join(unique(matched), ", ")
	case len(v.limited) > 0:
		v.status = LayerWarn
		v.reason = fmt.Sprintf("Cilium: src isolated for egress by %s; only specific FQDNs/CIDRs are opened, not the whole internet", strings.Join(isolatingNames, ", "))
	case skipped > 0:
		v.status = LayerWarn
		v.reason = fmt.Sprintf("Cilium: src isolated for egress by %s; no evaluated rule covers %s, but %d toServices rule(s) were not evaluated", strings.Join(isolatingNames, ", "), t.raw, skipped)
	default:
		v.status = LayerFail
		v.reason = fmt.Sprintf("Cilium: src isolated for egress by %s; no toEntities/toCIDR/toFQDNs rule covers %s", strings.Join(isolatingNames, ", "), t.raw)
		v.fix = "add a Cilium egress rule: `toEntities: [world]`, a `toCIDRSet` covering the address, or\n" +
			"  `toFQDNs: [{matchName: <host>}]` together with a DNS rule to kube-dns"
	}
	return v
}

// ciliumRulesCover reports whether any rule in spec.<key> reaches the
// target (used for egressDeny).
func ciliumRulesCover(p unstructured.Unstructured, key string, t externalTarget, port int32) (bool, string) {
	rules, _, _ := unstructured.NestedSlice(p.Object, "spec", key)
	for _, r := range rules {
		rule, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		if _, portsMatch := evaluateToPorts(rule, port, corev1.Pod{}); !portsMatch {
			continue
		}
		if how, _, _ := ciliumRuleReaches(rule, t); how != "" {
			return true, how
		}
	}
	return false, ""
}

// ciliumRuleReaches decides whether one egress rule reaches the target.
// It returns how (empty = no), the destinations it opens instead when the
// target is the whole internet, and whether something could not be decided.
func ciliumRuleReaches(rule map[string]interface{}, t externalTarget) (how string, limited []string, unknown bool) {
	for _, e := range entityTargets(rule) {
		if e == "world" || e == "all" {
			return "toEntities " + e, nil, false
		}
	}
	for _, c := range cidrTargets(rule) {
		cidr, except, _ := strings.Cut(c, " except ")
		switch {
		case t.generic && coversEverything(cidr):
			return "toCIDR " + cidr, nil, false
		case t.generic:
			limited = append(limited, cidr)
		case cidrCovers(cidr, strings.Split(except, ","), t):
			return "toCIDR " + cidr, nil, false
		}
	}
	names, patterns := fqdnNames(rule)
	for _, n := range names {
		switch {
		case t.generic:
			limited = append(limited, n)
		case t.host != "" && normalizeFQDN(n) == t.host:
			return "toFQDNs " + n, nil, false
		}
	}
	for _, p := range patterns {
		switch {
		case t.generic:
			limited = append(limited, p)
		case t.host != "" && fqdnPatternMatches(p, t.host):
			return "toFQDNs pattern " + p, nil, false
		}
	}
	if hasFields(rule, "toServices") {
		unknown = true
	}
	if !hasFields(rule, "toEndpoints", "toEntities", "toCIDR", "toCIDRSet", "toFQDNs", "toServices", "toRequires") {
		return "to anywhere", nil, false
	}
	return "", limited, unknown
}

// fqdnPatternMatches applies Cilium's matchPattern glob: "*" matches any
// run of DNS characters other than ".".
func fqdnPatternMatches(pattern, host string) bool {
	re := "^" + strings.ReplaceAll(regexp.QuoteMeta(strings.ToLower(strings.TrimSuffix(pattern, "."))), `\*`, `[-a-z0-9_]*`) + "$"
	ok, _ := regexp.MatchString(re, host)
	return ok
}

func coversEverything(cidr string) bool {
	p, err := netip.ParsePrefix(cidr)
	return err == nil && p.Bits() == 0
}

// cidrCovers reports whether the target (an address, or a CIDR that must be
// entirely inside) falls in cidr and outside every except.
func cidrCovers(cidr string, except []string, t externalTarget) bool {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	inside := func(a netip.Addr) bool {
		if !p.Contains(a) {
			return false
		}
		for _, e := range except {
			if ep, err := netip.ParsePrefix(strings.TrimSpace(e)); err == nil && ep.Contains(a) {
				return false
			}
		}
		return true
	}
	if t.prefix.IsValid() {
		return p.Bits() <= t.prefix.Bits() && inside(t.prefix.Addr())
	}
	for _, a := range t.addrs {
		if inside(a) {
			return true
		}
	}
	return false
}

func externalMeshLayer(srcPods []corev1.Pod) Layer {
	mesh, n := sidecars(srcPods)
	switch mesh {
	case "istio":
		return Layer{Name: "Mesh", Status: LayerWarn,
			Summary: fmt.Sprintf("Istio sidecar on %d/%d source pods: external hosts are reachable only if meshConfig.outboundTrafficPolicy is ALLOW_ANY or a ServiceEntry exists (not evaluated)", n, len(srcPods)),
			Fix:     "check with: istioctl proxy-config cluster <pod> -n <ns> | grep <host>"}
	case "linkerd":
		return Layer{Name: "Mesh", Status: LayerPass, Summary: "Linkerd proxy on the source passes external traffic through"}
	}
	return Layer{Name: "Mesh", Status: LayerSkip, Summary: "no sidecar on the source"}
}

// ExternalTargets lists every FQDN and CIDR the policies in the snapshot
// mention, so a UI can offer them as destinations.
func (s *Snapshot) ExternalTargets() []string {
	seen := map[string]bool{}
	for _, np := range s.Policies {
		for _, r := range np.Spec.Egress {
			for _, peer := range r.To {
				if peer.IPBlock != nil {
					seen[peer.IPBlock.CIDR] = true
				}
			}
		}
	}
	for _, p := range append(append([]unstructured.Unstructured{}, s.CiliumNamespacePolicies...), s.CiliumClusterPolicies...) {
		rules, _, _ := unstructured.NestedSlice(p.Object, "spec", "egress")
		for _, r := range rules {
			rule, ok := r.(map[string]interface{})
			if !ok {
				continue
			}
			names, _ := fqdnNames(rule)
			for _, n := range names {
				seen[normalizeFQDN(n)] = true
			}
			for _, c := range cidrTargets(rule) {
				cidr, _, _ := strings.Cut(c, " except ")
				seen[cidr] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
