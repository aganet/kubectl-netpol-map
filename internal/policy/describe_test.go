package policy

import (
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
)

func TestDescribeResolvesPeersAndCoverage(t *testing.T) {
	snap := shopSnapshot()
	snap.NamespaceLabels = map[string]map[string]string{"shop": {"team": "web"}, "payments": {}, "kube-system": {}}
	snap.Policies = []networkingv1.NetworkPolicy{ingressFromNamespaceLabel("payments", "allow-web", map[string]string{"app": "api"}, "team", "web")}
	snap.CiliumNamespacePolicies = append(snap.CiliumNamespacePolicies, ciliumSnapshot().CiliumNamespacePolicies...)

	views, cov := Describe(snap)
	if len(views) != 2 {
		t.Fatalf("expected 2 policy views, got %d", len(views))
	}
	// Sorted by key: "CiliumNetworkPolicy/…" before "NetworkPolicy/…".
	cnp, np := views[0], views[1]
	if np.Key != "NetworkPolicy/payments/allow-web" || !np.IsolatesIngress || np.IsolatesEgress {
		t.Errorf("unexpected standard view: %+v", np)
	}
	// api-1 and api-2 are bare pods, so each is its own workload.
	if len(np.Selected) != 2 || np.Selected[0].Kind != "Pod" {
		t.Errorf("allow-web should select both api pods: %+v", np.Selected)
	}
	if len(np.Ingress) != 1 || len(np.Ingress[0].Peers) != 1 || np.Ingress[0].Peers[0].Type != "namespace" {
		t.Fatalf("expected one namespace peer, got %+v", np.Ingress)
	}
	if m := np.Ingress[0].Peers[0].Matches; len(m) != 1 || m[0].Namespace != "shop" {
		t.Errorf("namespace team=web should resolve to the shop workload, got %+v", m)
	}
	if np.Ingress[0].Ports[0] != "any" {
		t.Errorf("no ports means any, got %v", np.Ingress[0].Ports)
	}
	if cnp.Kind != "CiliumNetworkPolicy" || cnp.Selector != "(all)" || !cnp.IsolatesEgress || len(cnp.Egress) != 1 {
		t.Errorf("unexpected cilium view: %+v", cnp)
	}
	if ports := cnp.Egress[0].Ports; len(ports) != 1 || ports[0] != "7233/TCP" {
		t.Errorf("expected 7233/TCP, got %v", ports)
	}
	// 4 workloads: frontend-1, api-1, api-2, coredns-1. The two api pods are
	// isolated for ingress; the Cilium policy lives in another namespace.
	if cov.Workloads != 4 || cov.IsolatedIngress != 2 || cov.IsolatedEgress != 0 || len(cov.Unprotected) != 2 {
		t.Errorf("coverage: %+v", cov)
	}
}
