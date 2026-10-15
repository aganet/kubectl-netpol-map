// Package lint inspects a policy Snapshot and reports issues a human should
// review: stale selectors, all-deny holes, redundant overlap, suspect
// "allow-all" rules. Findings are advisory — the tool reports, never edits.
package lint

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/aganet/kubectl-netpol-map/internal/policy"
)

// Severity classifies how seriously a user should treat a finding.
type Severity string

const (
	SevError   Severity = "error"
	SevWarning Severity = "warning"
	SevInfo    Severity = "info"
)

// Finding is a single lint result attached to a NetworkPolicy or pair.
type Finding struct {
	Code     string   // stable identifier, e.g. "L001"
	Severity Severity // error | warning | info
	Subject  string   // e.g. "demo/default-deny-ingress"
	Message  string   // one-line human-readable
	Hint     string   // optional suggested action
}

// Run executes every rule against the snapshot and returns findings sorted
// for stable display.
func Run(snap *policy.Snapshot) []Finding {
	out := []Finding{}
	for _, rule := range allRules {
		out = append(out, rule(snap)...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return severityRank(out[i].Severity) < severityRank(out[j].Severity)
		}
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

func severityRank(s Severity) int {
	switch s {
	case SevError:
		return 0
	case SevWarning:
		return 1
	case SevInfo:
		return 2
	}
	return 3
}

type rule func(*policy.Snapshot) []Finding

// allRules is the list of registered rule implementations.
var allRules = []rule{
	ruleL001StaleSelector,
	ruleL002EmptyPolicy,
	ruleL003AllowFromAnywhere,
	ruleL004IsolationOverlap,
	ruleL005StandardCiliumOverlap,
}

// L001: a NetworkPolicy's podSelector matches zero pods in its namespace.
// Usually means stale labels or a typo in the policy.
func ruleL001StaleSelector(snap *policy.Snapshot) []Finding {
	out := []Finding{}
	for _, p := range snap.Policies {
		if countSelected(p.Spec.PodSelector, p.Namespace, snap.Pods) > 0 {
			continue
		}
		out = append(out, Finding{
			Code:     "L001",
			Severity: SevWarning,
			Subject:  policyKey(p),
			Message:  "podSelector matches zero pods in this namespace — stale or unused?",
			Hint:     "verify the matchLabels against current pod labels or delete the policy",
		})
	}
	return out
}

// L002: a policy declares a policyType but lists no rules. That's actually a
// valid "deny-all" pattern, but worth flagging at info level so people
// notice when it's unintentional.
func ruleL002EmptyPolicy(snap *policy.Snapshot) []Finding {
	out := []Finding{}
	for _, p := range snap.Policies {
		hasIngressType := containsPolicyType(p.Spec.PolicyTypes, networkingv1.PolicyTypeIngress) ||
			len(p.Spec.PolicyTypes) == 0
		hasEgressType := containsPolicyType(p.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)

		if hasIngressType && len(p.Spec.Ingress) == 0 {
			out = append(out, Finding{
				Code:     "L002",
				Severity: SevInfo,
				Subject:  policyKey(p),
				Message:  "declares Ingress policyType with no rules — denies all ingress for selected pods",
				Hint:     "if intentional (deny-all baseline) ignore; otherwise add ingress rules",
			})
		}
		if hasEgressType && len(p.Spec.Egress) == 0 {
			out = append(out, Finding{
				Code:     "L002",
				Severity: SevInfo,
				Subject:  policyKey(p),
				Message:  "declares Egress policyType with no rules — denies all egress for selected pods",
				Hint:     "if intentional ignore; otherwise add egress rules",
			})
		}
	}
	return out
}

// L003: a rule has an empty from/to peer list, which means "from anywhere".
// Sometimes desired (public service); often a footgun.
func ruleL003AllowFromAnywhere(snap *policy.Snapshot) []Finding {
	out := []Finding{}
	for _, p := range snap.Policies {
		for i, r := range p.Spec.Ingress {
			if len(r.From) == 0 {
				out = append(out, Finding{
					Code:     "L003",
					Severity: SevWarning,
					Subject:  fmt.Sprintf("%s ingress[%d]", policyKey(p), i),
					Message:  "ingress rule has empty 'from' — accepts traffic from anywhere in cluster",
					Hint:     "add a 'from:' selector unless this pod is intentionally public",
				})
			}
		}
		for i, r := range p.Spec.Egress {
			if len(r.To) == 0 {
				out = append(out, Finding{
					Code:     "L003",
					Severity: SevWarning,
					Subject:  fmt.Sprintf("%s egress[%d]", policyKey(p), i),
					Message:  "egress rule has empty 'to' — permits egress to anywhere",
					Hint:     "add a 'to:' selector unless egress is intentionally unrestricted",
				})
			}
		}
	}
	return out
}

// L004: more than one isolating policy with overlapping selectors on the
// same pod set. Doesn't mean wrong, but redundant or accidentally additive.
func ruleL004IsolationOverlap(snap *policy.Snapshot) []Finding {
	out := []Finding{}
	// Group policies by the pod set they select within a namespace.
	byTarget := map[string][]networkingv1.NetworkPolicy{}
	for _, p := range snap.Policies {
		pods := podsSelected(p.Spec.PodSelector, p.Namespace, snap.Pods)
		if len(pods) == 0 {
			continue
		}
		key := p.Namespace + "|" + podKey(pods)
		byTarget[key] = append(byTarget[key], p)
	}
	for _, ps := range byTarget {
		if len(ps) < 2 {
			continue
		}
		names := []string{}
		for _, p := range ps {
			names = append(names, p.Name)
		}
		sort.Strings(names)
		out = append(out, Finding{
			Code:     "L004",
			Severity: SevInfo,
			Subject:  ps[0].Namespace + "/" + strings.Join(names, ","),
			Message:  fmt.Sprintf("%d policies select the same %d pod(s) — review for redundancy", len(ps), len(podsSelected(ps[0].Spec.PodSelector, ps[0].Namespace, snap.Pods))),
			Hint:     "consolidate rules into a single policy if they describe one logical intent",
		})
	}
	return out
}

// L005: a standard NetworkPolicy and a CiliumNetworkPolicy both select the
// same pod. Cilium evaluates after standard NP in some setups, and the
// interaction is easy to get wrong.
func ruleL005StandardCiliumOverlap(snap *policy.Snapshot) []Finding {
	if len(snap.CiliumNamespacePolicies) == 0 {
		return nil
	}
	out := []Finding{}
	// Build pod label set per (ns,name) for the standard policy targets.
	for _, std := range snap.Policies {
		stdPods := podsSelected(std.Spec.PodSelector, std.Namespace, snap.Pods)
		if len(stdPods) == 0 {
			continue
		}
		stdNames := podNameSet(stdPods)
		for _, cnp := range snap.CiliumNamespacePolicies {
			if cnp.GetNamespace() != std.Namespace {
				continue
			}
			cnpLabels, _, _ := nestedStringMap(cnp.Object, "spec", "endpointSelector", "matchLabels")
			if len(cnpLabels) == 0 {
				continue // matches everything — skip noise
			}
			cnpPods := podsByLabels(cnpLabels, std.Namespace, snap.Pods)
			if intersectsAny(stdNames, cnpPods) {
				out = append(out, Finding{
					Code:     "L005",
					Severity: SevInfo,
					Subject:  fmt.Sprintf("%s ⇄ %s/%s (CNP)", policyKey(std), cnp.GetNamespace(), cnp.GetName()),
					Message:  "standard NetworkPolicy and CiliumNetworkPolicy select overlapping pods",
					Hint:     "verify combined semantics: both engines must allow traffic for it to pass",
				})
			}
		}
	}
	return out
}

// ---- helpers ----

func policyKey(p networkingv1.NetworkPolicy) string {
	return p.Namespace + "/" + p.Name
}

func containsPolicyType(types []networkingv1.PolicyType, want networkingv1.PolicyType) bool {
	for _, t := range types {
		if t == want {
			return true
		}
	}
	return false
}

func countSelected(sel metav1.LabelSelector, ns string, pods []corev1.Pod) int {
	return len(podsSelected(sel, ns, pods))
}

func podsSelected(sel metav1.LabelSelector, ns string, pods []corev1.Pod) []corev1.Pod {
	s, err := metav1.LabelSelectorAsSelector(&sel)
	if err != nil {
		return nil
	}
	out := []corev1.Pod{}
	for _, p := range pods {
		if p.Namespace != ns {
			continue
		}
		if s.Matches(labels.Set(p.Labels)) {
			out = append(out, p)
		}
	}
	return out
}

func podsByLabels(matchLabels map[string]string, ns string, pods []corev1.Pod) []corev1.Pod {
	sel := labels.SelectorFromSet(labels.Set(matchLabels))
	out := []corev1.Pod{}
	for _, p := range pods {
		if p.Namespace != ns {
			continue
		}
		if sel.Matches(labels.Set(p.Labels)) {
			out = append(out, p)
		}
	}
	return out
}

func podKey(pods []corev1.Pod) string {
	names := make([]string, 0, len(pods))
	for _, p := range pods {
		names = append(names, p.Name)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

func podNameSet(pods []corev1.Pod) map[string]bool {
	m := map[string]bool{}
	for _, p := range pods {
		m[p.Name] = true
	}
	return m
}

func intersectsAny(set map[string]bool, pods []corev1.Pod) bool {
	for _, p := range pods {
		if set[p.Name] {
			return true
		}
	}
	return false
}

// nestedStringMap is a typed wrapper around unstructured nested-field
// lookups, returning a string-string map (Cilium's matchLabels shape).
func nestedStringMap(obj map[string]interface{}, fields ...string) (map[string]string, bool, error) {
	cur := obj
	for i, f := range fields {
		v, ok := cur[f]
		if !ok {
			return nil, false, nil
		}
		if i == len(fields)-1 {
			ml, ok := v.(map[string]interface{})
			if !ok {
				return nil, false, fmt.Errorf("field %q is not a map", f)
			}
			out := map[string]string{}
			for k, vv := range ml {
				if s, ok := vv.(string); ok {
					out[k] = s
				}
			}
			return out, true, nil
		}
		next, ok := v.(map[string]interface{})
		if !ok {
			return nil, false, fmt.Errorf("intermediate field %q is not a map", f)
		}
		cur = next
	}
	return nil, false, nil
}
