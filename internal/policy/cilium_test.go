package policy

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func cnp(ns string, egress ...map[string]interface{}) unstructured.Unstructured {
	rules := make([]interface{}, 0, len(egress))
	for _, r := range egress {
		rules = append(rules, r)
	}
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
		"metadata": map[string]interface{}{"namespace": ns, "name": "egress"},
		"spec":     map[string]interface{}{"endpointSelector": map[string]interface{}{}, "egress": rules},
	}}
}

func ports(p string) map[string]interface{} {
	return map[string]interface{}{"ports": []interface{}{map[string]interface{}{"port": p, "protocol": "TCP"}}}
}

// The common real-world Cilium egress policy: DNS to kube-dns with an L7
// DNS rule, plus toFQDNs to external names. A name outside the cluster DNS
// domain cannot name a pod, so every other pod is a definite DENY even
// without a resolver; only a name inside it stays UNKNOWN until resolved.
// kube-dns itself is an ALLOW flagged L7.
func TestCiliumResolvedFQDNAndDNSRuleAreDecidable(t *testing.T) {
	dns := readyPod("kube-system", "coredns-1", map[string]string{"k8s-app": "kube-dns"}, map[string]int32{"dns": 53})
	src := pod("shop", "worker-1", map[string]string{"app": "worker"})
	other := readyPod("payments", "api-1", map[string]string{"app": "api"}, nil)
	policy := cnp("shop",
		map[string]interface{}{
			"toEndpoints": []interface{}{map[string]interface{}{"matchLabels": map[string]interface{}{"k8s:io.kubernetes.pod.namespace": "kube-system", "k8s-app": "kube-dns"}}},
			"toPorts": []interface{}{map[string]interface{}{
				"ports": []interface{}{map[string]interface{}{"port": "53", "protocol": "ANY"}},
				"rules": map[string]interface{}{"dns": []interface{}{map[string]interface{}{"matchPattern": "*"}}},
			}},
		},
		map[string]interface{}{
			"toFQDNs": []interface{}{map[string]interface{}{"matchName": "api.stripe.com"}},
			"toPorts": []interface{}{ports("443")},
		},
	)
	snap := &Snapshot{Pods: []corev1.Pod{src, dns, other}, CiliumNamespacePolicies: []unstructured.Unstructured{policy}}

	res, err := ExplainPath(snap, "", "shop/worker-1", "payments/api-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Cell.Allowed || res.Cell.Unknown {
		t.Errorf("an external name cannot name a pod, resolver or not: expected DENY, got %+v", res.Cell)
	}
	// A cluster-internal name could be the destination pod: undecided until
	// resolved, the same for a pattern that could match one.
	for _, entry := range []map[string]interface{}{{"matchName": "api.payments.svc.cluster.local"}, {"matchPattern": "*.cluster.local"}, {"matchPattern": "*"}} {
		policy.Object["spec"].(map[string]interface{})["egress"].([]interface{})[1].(map[string]interface{})["toFQDNs"] = []interface{}{entry}
		res, err = ExplainPath(snap, "", "shop/worker-1", "payments/api-1", "")
		if err != nil {
			t.Fatal(err)
		}
		if !res.Cell.Unknown {
			t.Errorf("%v could name a pod: expected UNKNOWN, got %+v", entry, res.Cell)
		}
	}
	policy.Object["spec"].(map[string]interface{})["egress"].([]interface{})[1].(map[string]interface{})["toFQDNs"] = []interface{}{map[string]interface{}{"matchName": "api.stripe.com"}, map[string]interface{}{"matchPattern": "*.amazonaws.com"}}

	snap.Resolver = MapResolver{"api.stripe.com": {"203.0.113.10"}}
	res, err = ExplainPath(snap, "", "shop/worker-1", "payments/api-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Cell.Allowed || res.Cell.Unknown {
		t.Errorf("resolved external FQDN cannot match a pod: expected DENY, got %+v", res.Cell)
	}
	res, err = ExplainPath(snap, "", "shop/worker-1", "kube-system/coredns-1", "53")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cell.Allowed || !res.Cell.L7Restricted {
		t.Errorf("DNS rule must ALLOW kube-dns:53 flagged L7, got %+v", res.Cell)
	}
}

// Selectors follow Cilium's matching: matchExpressions are evaluated, a
// CNP peer without a namespace key is limited to the policy namespace, and
// namespace labels select across namespaces (also in a CCNP endpointSelector).
func TestCiliumSelectorsNamespacesAndExpressions(t *testing.T) {
	src := pod("shop", "worker-1", map[string]string{"app": "worker"})
	dst := readyPod("payments", "api-1", map[string]string{"app": "api"}, nil)
	other := readyPod("ops", "api-1", map[string]string{"app": "api"}, nil)
	nsLabels := map[string]map[string]string{"shop": {"team": "web"}, "payments": {"team": "money"}, "ops": {}}
	verdict := func(snap *Snapshot, to string) Cell {
		snap.NamespaceLabels = nsLabels
		res, err := ExplainPath(snap, "", "shop/worker-1", to, "")
		if err != nil {
			t.Fatal(err)
		}
		return res.Cell
	}
	api := map[string]interface{}{"matchLabels": map[string]interface{}{"k8s:app": "api"}}
	snap := &Snapshot{Pods: []corev1.Pod{src, dst}, CiliumNamespacePolicies: []unstructured.Unstructured{cnp("shop",
		map[string]interface{}{"toEndpoints": []interface{}{api}})}}
	if c := verdict(snap, "payments/api-1"); c.Allowed {
		t.Errorf("a CNP peer without a namespace key stays in the policy namespace: expected DENY, got %+v", c)
	}
	inPayments := map[string]interface{}{"matchLabels": map[string]interface{}{"k8s:app": "api"}, "matchExpressions": []interface{}{
		map[string]interface{}{"key": "k8s:io.kubernetes.pod.namespace", "operator": "In", "values": []interface{}{"payments"}}}}
	snap = &Snapshot{Pods: []corev1.Pod{src, dst}, CiliumNamespacePolicies: []unstructured.Unstructured{cnp("shop",
		map[string]interface{}{"toEndpoints": []interface{}{inPayments}})}}
	if c := verdict(snap, "payments/api-1"); !c.Allowed {
		t.Errorf("matchExpressions on the namespace key must select payments: got %+v", c)
	}
	byNSLabel := map[string]interface{}{"matchLabels": map[string]interface{}{"k8s:io.cilium.k8s.namespace.labels.team": "money"}}
	snap = &Snapshot{Pods: []corev1.Pod{src, dst, other}, CiliumNamespacePolicies: []unstructured.Unstructured{cnp("shop",
		map[string]interface{}{"toEndpoints": []interface{}{byNSLabel}})}}
	if c := verdict(snap, "payments/api-1"); !c.Allowed {
		t.Errorf("namespace labels must select payments: got %+v", c)
	}
	if c := verdict(snap, "ops/api-1"); c.Allowed {
		t.Errorf("namespace labels must not select ops: got %+v", c)
	}
	// A cluster-wide policy selecting by namespace label isolates shop only.
	ccnp := cnp("", map[string]interface{}{"toEntities": []interface{}{"world"}})
	ccnp.Object["kind"] = "CiliumClusterwideNetworkPolicy"
	ccnp.Object["metadata"] = map[string]interface{}{"name": "web-egress"}
	ccnp.Object["spec"].(map[string]interface{})["endpointSelector"] = map[string]interface{}{"matchLabels": map[string]interface{}{"io.cilium.k8s.namespace.labels.team": "web"}}
	snap = &Snapshot{Pods: []corev1.Pod{src, dst, other}, CiliumClusterPolicies: []unstructured.Unstructured{ccnp}}
	if c := verdict(snap, "payments/api-1"); c.Allowed {
		t.Errorf("CCNP selecting namespace team=web must isolate shop: expected DENY, got %+v", c)
	}
	snap.NamespaceLabels = nsLabels
	res, err := ExplainPath(snap, "", "ops/api-1", "payments/api-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cell.Allowed {
		t.Errorf("CCNP must not select ops: expected ALLOW, got %+v", res.Cell)
	}
	if views, _ := Describe(snap); views[0].Selector != "io.cilium.k8s.namespace.labels.team=web" || len(views[0].Selected) != 1 {
		t.Errorf("unexpected CCNP view: %+v", views[0])
	}
}

// Cilium ports: protocol defaults to ANY, endPort gives a range, a named
// port resolves on the destination, and an icmps-only rule opens no L4 port.
func TestCiliumPortsProtocolRangeNamedICMP(t *testing.T) {
	src := pod("shop", "worker-1", map[string]string{"app": "worker"})
	dst := readyPod("payments", "api-1", map[string]string{"app": "api"}, map[string]int32{"http": 8000})
	api := map[string]interface{}{"toEndpoints": []interface{}{map[string]interface{}{"matchLabels": map[string]interface{}{"k8s:io.kubernetes.pod.namespace": "payments", "app": "api"}}}}
	mk := func(extra map[string]interface{}) *Snapshot {
		rule := map[string]interface{}{}
		for k, v := range api {
			rule[k] = v
		}
		for k, v := range extra {
			rule[k] = v
		}
		return &Snapshot{Pods: []corev1.Pod{src, dst}, CiliumNamespacePolicies: []unstructured.Unstructured{cnp("shop", rule)}}
	}
	verdict := func(snap *Snapshot, port string) Cell {
		res, err := ExplainPath(snap, "", "shop/worker-1", "payments/api-1"+port, "")
		if err != nil {
			t.Fatal(err)
		}
		return res.Cell
	}
	rng := map[string]interface{}{"toPorts": []interface{}{map[string]interface{}{"ports": []interface{}{map[string]interface{}{"port": "8000", "endPort": int64(8100), "protocol": "UDP"}}}}}
	if c := verdict(mk(rng), ":8050"); !c.Allowed || c.Ports[0] != "8000-8100/UDP" {
		t.Errorf("port in a UDP range must be allowed as such: %+v", c)
	}
	if c := verdict(mk(rng), ":9000"); c.Allowed {
		t.Errorf("port outside the range must be denied: %+v", c)
	}
	named := map[string]interface{}{"toPorts": []interface{}{map[string]interface{}{"ports": []interface{}{map[string]interface{}{"port": "http"}}}}}
	if c := verdict(mk(named), ":8000"); !c.Allowed || c.Ports[0] != "8000/ANY" {
		t.Errorf("named port must resolve on the destination with protocol ANY: %+v", c)
	}
	if c := verdict(mk(named), ":8080"); c.Allowed {
		t.Errorf("named port http is 8000, not 8080: %+v", c)
	}
	icmp := map[string]interface{}{"icmps": []interface{}{map[string]interface{}{"fields": []interface{}{map[string]interface{}{"type": int64(8)}}}}}
	if c := verdict(mk(icmp), ""); c.Allowed || c.Unknown {
		t.Errorf("an icmps-only rule opens no L4 port: expected DENY, got %+v", c)
	}
}

// Cilium enforces standard and Cilium policies from one pool (verified on
// Cilium 1.20: a pair denied by the standard policies became reachable when
// Cilium rules alone opened it). A rule of either kind opens the traffic.
func TestCiliumUnionsWithStandardPolicies(t *testing.T) {
	src := pod("shop", "worker-1", map[string]string{"app": "worker"})
	dst := readyPod("payments", "api-1", map[string]string{"app": "api"}, nil)
	// A standard policy isolates the worker's egress and opens nothing to api.
	egressOnlyDNS := networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "worker-egress"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "worker"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress:      []networkingv1.NetworkPolicyEgressRule{{To: []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "none"}}}}}},
		},
	}
	toAPI := cnp("shop", map[string]interface{}{"toEndpoints": []interface{}{map[string]interface{}{"matchLabels": map[string]interface{}{"k8s:io.kubernetes.pod.namespace": "payments", "app": "api"}}}})
	snap := &Snapshot{Pods: []corev1.Pod{src, dst}, Policies: []networkingv1.NetworkPolicy{egressOnlyDNS}}
	res, err := ExplainPath(snap, "", "shop/worker-1", "payments/api-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Cell.Allowed {
		t.Errorf("standard policy alone must deny: %+v", res.Cell)
	}
	snap.CiliumNamespacePolicies = []unstructured.Unstructured{toAPI}
	res, err = ExplainPath(snap, "", "shop/worker-1", "payments/api-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cell.Allowed || !strings.Contains(res.Cell.Reason, "egress allowed by shop/egress") {
		t.Errorf("a Cilium rule opens what the standard policy left closed: %+v", res.Cell)
	}
	// The other way round too: a standard allow is not narrowed by a Cilium
	// policy that opens something else.
	snap.Policies[0].Spec.Egress[0].To[0].PodSelector.MatchLabels["app"] = "api"
	snap.Policies[0].Spec.Egress[0].To[0].NamespaceSelector = &metav1.LabelSelector{}
	snap.CiliumNamespacePolicies = []unstructured.Unstructured{cnp("shop", map[string]interface{}{"toEntities": []interface{}{"world"}})}
	res, err = ExplainPath(snap, "", "shop/worker-1", "payments/api-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cell.Allowed || !strings.Contains(res.Cell.Reason, "egress allowed by shop/worker-egress") {
		t.Errorf("a standard rule opens what the Cilium policy left closed: %+v", res.Cell)
	}
}

// A policy with only deny rules still puts the pods it selects into
// default-deny (verified against Cilium 1.20: a cluster-wide egressDeny
// isolated every endpoint), unless enableDefaultDeny turns that off.
func TestCiliumDenyOnlyPolicyIsolates(t *testing.T) {
	src := pod("shop", "worker-1", map[string]string{"app": "worker"})
	dst := readyPod("payments", "api-1", map[string]string{"app": "api"}, nil)
	denyOnly := cnp("", map[string]interface{}{})
	denyOnly.Object["kind"] = "CiliumClusterwideNetworkPolicy"
	denyOnly.Object["metadata"] = map[string]interface{}{"name": "deny-metadata"}
	spec := denyOnly.Object["spec"].(map[string]interface{})
	delete(spec, "egress")
	spec["egressDeny"] = []interface{}{map[string]interface{}{"toCIDR": []interface{}{"169.254.169.254/32"}}}
	snap := &Snapshot{Pods: []corev1.Pod{src, dst}, CiliumClusterPolicies: []unstructured.Unstructured{denyOnly}}

	res, err := ExplainPath(snap, "", "shop/worker-1", "payments/api-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Cell.Allowed || res.Cell.Unknown {
		t.Errorf("a deny-only policy isolates egress: expected DENY, got %+v", res.Cell)
	}
	if views, cov := Describe(snap); !views[0].IsolatesEgress || cov.IsolatedEgress != 2 {
		t.Errorf("deny-only policy must count as isolating: %+v %+v", views[0], cov)
	}

	spec["enableDefaultDeny"] = map[string]interface{}{"egress": false}
	res, err = ExplainPath(snap, "", "shop/worker-1", "payments/api-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cell.Allowed {
		t.Errorf("enableDefaultDeny.egress=false must not isolate: got %+v", res.Cell)
	}
	if views, _ := Describe(snap); views[0].IsolatesEgress {
		t.Errorf("enableDefaultDeny.egress=false must not count as isolating: %+v", views[0])
	}
}

// A policy Cilium refused to import (status Valid=False) is not enforced:
// verdicts ignore it, it isolates nothing, and the view says why.
func TestCiliumRejectedPolicyIsNotEnforced(t *testing.T) {
	src := pod("shop", "worker-1", map[string]string{"app": "worker"})
	dst := readyPod("payments", "api-1", map[string]string{"app": "api"}, nil)
	policy := cnp("shop", map[string]interface{}{"toEntities": []interface{}{"world"}})
	policy.Object["status"] = map[string]interface{}{"conditions": []interface{}{
		map[string]interface{}{"type": "Valid", "status": "False", "message": "Invalid CiliumNetworkPolicy spec: empty egress rule"},
	}}
	snap := &Snapshot{Pods: []corev1.Pod{src, dst}, CiliumNamespacePolicies: []unstructured.Unstructured{policy}}

	res, err := ExplainPath(snap, "", "shop/worker-1", "payments/api-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cell.Allowed || res.Cell.Unknown {
		t.Errorf("a rejected policy must not affect the verdict: expected ALLOW, got %+v", res.Cell)
	}
	views, cov := Describe(snap)
	if len(views) != 1 || views[0].Rejected == "" || views[0].IsolatesEgress {
		t.Errorf("view must carry the rejection and isolate nothing: %+v", views)
	}
	if cov.IsolatedEgress != 0 || len(cov.Unprotected) != 2 {
		t.Errorf("rejected policy must not count as coverage: %+v", cov)
	}
}

// Entities and CIDRs follow Cilium's definitions: "cluster"/"all" cover
// pods, "world" does not, and CIDR rules apply only outside the cluster, so
// a CIDR that happens to cover a pod's IP still does not allow pod traffic.
func TestCiliumEntitiesAndCIDRs(t *testing.T) {
	src := pod("shop", "worker-1", map[string]string{"app": "worker"})
	dst := readyPod("payments", "api-1", map[string]string{"app": "api"}, nil)
	dst.Status.PodIP = "10.244.1.7"
	mk := func(rule map[string]interface{}) *Snapshot {
		return &Snapshot{Pods: []corev1.Pod{src, dst}, CiliumNamespacePolicies: []unstructured.Unstructured{cnp("shop", rule)}}
	}
	verdict := func(snap *Snapshot) Cell {
		res, err := ExplainPath(snap, "", "shop/worker-1", "payments/api-1", "")
		if err != nil {
			t.Fatal(err)
		}
		return res.Cell
	}

	if c := verdict(mk(map[string]interface{}{"toEntities": []interface{}{"cluster"}})); !c.Allowed {
		t.Errorf("toEntities cluster must allow pod-to-pod, got %+v", c)
	}
	if c := verdict(mk(map[string]interface{}{"toEntities": []interface{}{"world"}})); c.Allowed || c.Unknown {
		t.Errorf("toEntities world cannot match a pod: expected DENY, got %+v", c)
	}
	if c := verdict(mk(map[string]interface{}{"toCIDR": []interface{}{"10.244.0.0/16"}})); c.Allowed || c.Unknown {
		t.Errorf("toCIDR never applies to in-cluster pods: expected DENY, got %+v", c)
	}
	if c := verdict(mk(map[string]interface{}{"toServices": []interface{}{map[string]interface{}{"k8sService": map[string]interface{}{"serviceName": "api", "namespace": "payments"}}}})); !c.Unknown {
		t.Errorf("toServices is not evaluated: expected UNKNOWN, got %+v", c)
	}
}
