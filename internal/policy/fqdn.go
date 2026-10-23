package policy

import (
	"net"
	"sort"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Resolver maps a DNS name to a set of IP addresses. It is injectable so the
// FQDN-evaluation path can be exercised offline in tests and so callers can
// opt out of network access entirely (NopResolver).
type Resolver interface {
	Resolve(name string) []string
}

// NetResolver resolves via the host's DNS using net.LookupHost. Results are
// cached for the lifetime of the resolver to avoid repeated lookups across
// the O(pods²) evaluation loop. It is safe for concurrent use: the web UI
// evaluates several requests at once against one shared snapshot.
type NetResolver struct {
	mu    sync.Mutex
	cache map[string][]string
}

func NewNetResolver() *NetResolver { return &NetResolver{cache: map[string][]string{}} }

func (r *NetResolver) Resolve(name string) []string {
	r.mu.Lock()
	if r.cache == nil {
		r.cache = map[string][]string{}
	}
	v, ok := r.cache[name]
	r.mu.Unlock()
	if ok {
		return v
	}
	ips, err := net.LookupHost(name)
	if err != nil {
		ips = nil
	}
	sort.Strings(ips)
	r.mu.Lock()
	r.cache[name] = ips
	r.mu.Unlock()
	return ips
}

// NopResolver resolves nothing — used when FQDN evaluation is disabled, so
// toFQDNs rules continue to surface as UNKNOWN rather than silently matching.
type NopResolver struct{}

func (NopResolver) Resolve(string) []string { return nil }

// MapResolver is a fixed name→IPs map for tests.
type MapResolver map[string][]string

func (m MapResolver) Resolve(name string) []string { return m[name] }

// fqdnNames extracts the matchName entries from a rule's toFQDNs list.
// matchPattern entries (wildcards) are returned separately since they can't
// be resolved to a fixed address.
func fqdnNames(rule map[string]interface{}) (names []string, patterns []string) {
	raw, ok := rule["toFQDNs"].([]interface{})
	if !ok {
		return nil, nil
	}
	for _, e := range raw {
		m, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		if n, ok := m["matchName"].(string); ok && n != "" {
			names = append(names, n)
		}
		if p, ok := m["matchPattern"].(string); ok && p != "" {
			patterns = append(patterns, p)
		}
	}
	return names, patterns
}

// podIPIndex maps a pod IP to the pod's "namespace/name" for reverse lookup.
func podIPIndex(pods []podRef) map[string]string {
	idx := map[string]string{}
	for _, p := range pods {
		if p.ip != "" {
			idx[p.ip] = p.ns + "/" + p.name
		}
	}
	return idx
}

type podRef struct {
	ns, name, ip string
}

// ExternalEgress is one allowed external destination for a source workload,
// derived from a toFQDNs / toCIDR rule that does not resolve to an in-cluster
// pod. Surfaced in a dedicated report section since it has no matrix cell.
type ExternalEgress struct {
	Source   string   // "ns/Kind/Name" or "ns/pod"
	Target   string   // FQDN, pattern, or CIDR
	Kind     string   // "fqdn", "fqdn-pattern", "cidr", "entity"
	Ports    []string // allowed ports ("*" = all)
	Resolved []string // resolved IPs, if any (FQDN only)
}

// normalizeFQDN lowercases and strips a trailing dot for stable comparison.
func normalizeFQDN(s string) string {
	return strings.TrimSuffix(strings.ToLower(s), ".")
}

// fqdnRuleMatchesPod reports whether any matchName in the rule's toFQDNs
// resolves to the destination pod's IP. matchPattern entries are not
// resolved (they're wildcards), so a pattern-only rule never matches a pod
// here — it falls through to UNKNOWN. Returns false when the destination has
// no IP or the resolver is a no-op.
func fqdnRuleMatchesPod(ctx evalContext, rule map[string]interface{}, dst corev1.Pod) bool {
	if dst.Status.PodIP == "" || ctx.resolver == nil {
		return false
	}
	names, _ := fqdnNames(rule)
	for _, n := range names {
		for _, ip := range ctx.resolver.Resolve(normalizeFQDN(n)) {
			if ip == dst.Status.PodIP {
				return true
			}
		}
	}
	return false
}

// collectExternalEgress walks each source axis's egress rules and records the
// allowed external destinations (FQDNs that don't resolve to an in-cluster
// pod, plus toCIDR / toEntities targets). These are reported separately since
// they have no pod×pod matrix cell.
func collectExternalEgress(ctx evalContext, rows []Axis, resolver Resolver) []ExternalEgress {
	var out []ExternalEgress
	seen := map[string]bool{}

	add := func(src, target, kind string, ports []string, resolved []string) {
		key := src + "|" + kind + "|" + target
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, ExternalEgress{Source: src, Target: target, Kind: kind, Ports: ports, Resolved: resolved})
	}

	for _, axis := range rows {
		if len(axis.Pods) == 0 {
			continue
		}
		rep := axis.Pods[0] // representative pod for selector matching

		// Standard NetworkPolicy egress ipBlock peers — external CIDRs that
		// have no pod cell. Reported so "can this reach this CIDR" is visible.
		for _, np := range ctx.policies {
			if np.Namespace != rep.Namespace || !selects(np.Spec.PodSelector, *rep) {
				continue
			}
			if !hasType(np, networkingv1.PolicyTypeEgress) {
				continue
			}
			for _, rule := range np.Spec.Egress {
				ports := rulePorts(rule.Ports, 0, corev1.Pod{}) // CIDR peers have no pod to resolve named ports on
				for _, peer := range rule.To {
					if peer.IPBlock == nil {
						continue
					}
					target := peer.IPBlock.CIDR
					if len(peer.IPBlock.Except) > 0 {
						target += " except " + strings.Join(peer.IPBlock.Except, ",")
					}
					add(axis.Display(), target, "cidr", ports, nil)
				}
			}
		}

		for _, p := range append(append([]unstructured.Unstructured{}, ctx.cnps...), ctx.ccnps...) {
			if !selectsForCilium(p, *rep) || !policyHasSection(p, "egress") {
				continue
			}
			rules, _, _ := unstructured.NestedSlice(p.Object, "spec", "egress")
			for _, r := range rules {
				ruleMap, ok := r.(map[string]interface{})
				if !ok {
					continue
				}
				ports, _, _ := evaluateToPorts(ruleMap, 0)
				// FQDNs.
				if names, patterns := fqdnNames(ruleMap); len(names)+len(patterns) > 0 {
					for _, n := range names {
						resolved := resolver.Resolve(normalizeFQDN(n))
						if externalOnly(resolved, ctx.podIPs) {
							add(axis.Display(), n, "fqdn", ports, resolved)
						}
					}
					for _, pat := range patterns {
						add(axis.Display(), pat, "fqdn-pattern", ports, nil)
					}
				}
				// CIDRs.
				for _, c := range cidrTargets(ruleMap) {
					add(axis.Display(), c, "cidr", ports, nil)
				}
				// Entities (world, host, ...).
				for _, e := range entityTargets(ruleMap) {
					add(axis.Display(), e, "entity", ports, nil)
				}
			}
		}
	}
	return out
}

// externalOnly is true when none of the resolved IPs belong to an in-cluster
// pod (so the FQDN is a genuinely external destination). An empty/unresolved
// set is treated as external (we can't prove it points inside).
func externalOnly(resolved []string, podIPs map[string]string) bool {
	for _, ip := range resolved {
		if _, ok := podIPs[ip]; ok {
			return false
		}
	}
	return true
}

// fqdnDecidable reports whether a toFQDNs rule can be settled for pods: all
// its names resolved (so a non-match means the rule points elsewhere) and it
// carries no wildcard pattern.
func fqdnDecidable(ctx evalContext, rule map[string]interface{}) bool {
	names, patterns := fqdnNames(rule)
	if len(patterns) > 0 || ctx.resolver == nil {
		return false
	}
	for _, n := range names {
		if len(ctx.resolver.Resolve(normalizeFQDN(n))) == 0 {
			return false
		}
	}
	return true
}

func cidrTargets(rule map[string]interface{}) []string {
	return cidrEntries(rule, "toCIDR", "toCIDRSet")
}

// cidrEntries lists the CIDRs of a rule's plain list and set fields; set
// entries carry their except list as "<cidr> except <a>,<b>", the same form
// the standard ipBlock report uses.
func cidrEntries(rule map[string]interface{}, listKey, setKey string) []string {
	var out []string
	if v, ok := rule[listKey].([]interface{}); ok {
		for _, c := range v {
			if s, ok := c.(string); ok {
				out = append(out, s)
			}
		}
	}
	if v, ok := rule[setKey].([]interface{}); ok {
		for _, c := range v {
			m, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			s, ok := m["cidr"].(string)
			if !ok {
				continue
			}
			var except []string
			if ex, ok := m["except"].([]interface{}); ok {
				for _, e := range ex {
					if es, ok := e.(string); ok {
						except = append(except, es)
					}
				}
			}
			if len(except) > 0 {
				s += " except " + strings.Join(except, ",")
			}
			out = append(out, s)
		}
	}
	return out
}

func entityTargets(rule map[string]interface{}) []string {
	var out []string
	if v, ok := rule["toEntities"].([]interface{}); ok {
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
