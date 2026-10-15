package policy

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func egressPolicy(ns string, podLabels map[string]string, to []networkingv1.NetworkPolicyPeer) networkingv1.NetworkPolicy {
	return networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "egress"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: podLabels},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress:      []networkingv1.NetworkPolicyEgressRule{{To: to}},
		},
	}
}

func ciliumEgress(ns string, rule map[string]interface{}) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata":   map[string]interface{}{"namespace": ns, "name": "egress"},
		"spec": map[string]interface{}{
			"endpointSelector": map[string]interface{}{},
			"egress":           []interface{}{rule},
		},
	}}
}

func TestExternalUnrestricted(t *testing.T) {
	snap := &Snapshot{Pods: []corev1.Pod{pod("shop", "frontend-1", map[string]string{"app": "frontend"})}}
	res, err := ExplainPath(snap, "", "shop/frontend-1", "internet", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.External != "internet" || res.Verdict() != "REACHABLE" {
		t.Errorf("no policies: expected REACHABLE to the internet, got %q (%+v)", res.Verdict(), res.Layers)
	}
	if len(res.Layers) != 2 || res.Layers[0].Name != "Egress policy" {
		t.Errorf("a generic target needs no DNS layer; got %+v", res.Layers)
	}
}

func TestExternalDeniedByStandardPolicy(t *testing.T) {
	snap := &Snapshot{
		Pods: []corev1.Pod{pod("shop", "frontend-1", map[string]string{"app": "frontend"})},
		Policies: []networkingv1.NetworkPolicy{egressPolicy("shop", map[string]string{"app": "frontend"},
			[]networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{}}})},
	}
	res, err := ExplainPath(snap, "", "shop/frontend-1", "1.1.1.1:443", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict() != "BLOCKED at Egress policy" {
		t.Errorf("pod-only egress rule cannot reach the internet: got %q", res.Verdict())
	}
	if l := findLayer(res, "Egress policy"); !strings.Contains(l.Fix, "ipBlock") {
		t.Errorf("expected an ipBlock fix hint, got %q", l.Fix)
	}
}

func TestExternalIPBlockWithExcept(t *testing.T) {
	snap := &Snapshot{
		Pods: []corev1.Pod{pod("shop", "frontend-1", map[string]string{"app": "frontend"})},
		Policies: []networkingv1.NetworkPolicy{egressPolicy("shop", map[string]string{"app": "frontend"},
			[]networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0", Except: []string{"10.0.0.0/8"}}}})},
	}
	ok, err := ExplainPath(snap, "", "shop/frontend-1", "internet", "")
	if err != nil {
		t.Fatal(err)
	}
	if ok.Verdict() != "REACHABLE" {
		t.Errorf("0.0.0.0/0 opens the internet: got %q", ok.Verdict())
	}
	blocked, err := ExplainPath(snap, "", "shop/frontend-1", "10.1.2.3", "")
	if err != nil {
		t.Fatal(err)
	}
	if blocked.Verdict() != "BLOCKED at Egress policy" {
		t.Errorf("10.1.2.3 is in the except list: got %q", blocked.Verdict())
	}
}

func TestExternalCiliumFQDNOnlyIsLimited(t *testing.T) {
	snap := &Snapshot{
		Pods: []corev1.Pod{
			pod("shop", "frontend-1", map[string]string{"app": "frontend"}),
			readyPod("kube-system", "coredns-1", map[string]string{"k8s-app": "kube-dns"}, nil),
		},
		CiliumNamespacePolicies: []unstructured.Unstructured{ciliumEgress("shop", map[string]interface{}{
			"toFQDNs": []interface{}{
				map[string]interface{}{"matchName": "api.stripe.com"},
				map[string]interface{}{"matchPattern": "*.openai.com"},
			},
		})},
	}
	// An FQDN policy always comes with a DNS rule, or nothing resolves.
	spec := snap.CiliumNamespacePolicies[0].Object["spec"].(map[string]interface{})
	spec["egress"] = append(spec["egress"].([]interface{}), map[string]interface{}{
		"toEndpoints": []interface{}{map[string]interface{}{"matchLabels": map[string]interface{}{
			"k8s:io.kubernetes.pod.namespace": "kube-system", "k8s-app": "kube-dns",
		}}},
		"toPorts": []interface{}{map[string]interface{}{"ports": []interface{}{map[string]interface{}{"port": "53", "protocol": "ANY"}}}},
	})
	// The whole internet: only two names are opened.
	limited, err := ExplainPath(snap, "", "shop/frontend-1", "internet", "")
	if err != nil {
		t.Fatal(err)
	}
	if l := findLayer(limited, "Egress policy"); l.Status != LayerWarn || len(l.Detail) == 0 || !strings.Contains(l.Detail[0], "api.stripe.com") {
		t.Errorf("expected a warn listing the opened names, got %+v", l)
	}
	// A listed name: allowed, and the DNS egress layer is part of the chain.
	ok, err := ExplainPath(snap, "", "shop/frontend-1", "api.stripe.com:443", "")
	if err != nil {
		t.Fatal(err)
	}
	if ok.Verdict() != "REACHABLE" || ok.Layers[0].Name != "DNS egress" {
		t.Errorf("api.stripe.com is allowed by matchName: got %q, layers %+v", ok.Verdict(), ok.Layers)
	}
	// A pattern match.
	pat, err := ExplainPath(snap, "", "shop/frontend-1", "api.openai.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if pat.Verdict() != "REACHABLE" {
		t.Errorf("api.openai.com matches *.openai.com: got %q", pat.Verdict())
	}
	// An unlisted name is denied.
	no, err := ExplainPath(snap, "", "shop/frontend-1", "example.org", "")
	if err != nil {
		t.Fatal(err)
	}
	if no.Verdict() != "BLOCKED at Egress policy" {
		t.Errorf("example.org is not opened: got %q", no.Verdict())
	}
}

func TestExternalCiliumWorldAndDeny(t *testing.T) {
	world := ciliumEgress("shop", map[string]interface{}{"toEntities": []interface{}{"world"}})
	snap := &Snapshot{
		Pods:                    []corev1.Pod{pod("shop", "frontend-1", map[string]string{"app": "frontend"})},
		CiliumNamespacePolicies: []unstructured.Unstructured{world},
	}
	res, err := ExplainPath(snap, "", "shop/frontend-1", "internet", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict() != "REACHABLE" {
		t.Errorf("toEntities world: got %q", res.Verdict())
	}
	world.Object["spec"].(map[string]interface{})["egressDeny"] = []interface{}{
		map[string]interface{}{"toCIDR": []interface{}{"203.0.113.0/24"}},
	}
	res, err = ExplainPath(snap, "", "shop/frontend-1", "203.0.113.7", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict() != "BLOCKED at Egress policy" {
		t.Errorf("egressDeny toCIDR must win: got %q", res.Verdict())
	}
}

// A two-label name is a Service in a namespace when that namespace exists,
// and an external host otherwise.
func TestTwoLabelNameFallsBackToExternal(t *testing.T) {
	snap := shopSnapshot()
	res, err := ExplainPath(snap, "", "shop/frontend", "example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.External != "example.com" {
		t.Errorf("no namespace \"com\": expected an external host, got %+v", res)
	}
	res, err = ExplainPath(snap, "", "shop/frontend", "api.payments", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Service == nil {
		t.Errorf("namespace payments exists: expected the Service, got %+v", res)
	}
}
