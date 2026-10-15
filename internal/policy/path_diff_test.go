package policy

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func pod(ns, name string, labels map[string]string) corev1.Pod {
	return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels}}
}

// ingressFromNamespaceLabel builds a NetworkPolicy in ns that selects pods
// matching podLabels and allows ingress from any namespace carrying nsKey=nsVal.
func ingressFromNamespaceLabel(ns, name string, podLabels map[string]string, nsKey, nsVal string) networkingv1.NetworkPolicy {
	return networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: podLabels},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{nsKey: nsVal}},
				}},
			}},
		},
	}
}

// snapshot: an "agents" pod under a Cilium egress policy that only allows
// reaching temporal-frontend on 7233, plus two temporal pods.
func ciliumSnapshot() *Snapshot {
	cnp := unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata":   map[string]interface{}{"namespace": "agents", "name": "baseline-egress"},
		"spec": map[string]interface{}{
			"endpointSelector": map[string]interface{}{},
			"egress": []interface{}{
				map[string]interface{}{
					"toEndpoints": []interface{}{
						map[string]interface{}{"matchLabels": map[string]interface{}{
							"k8s:io.kubernetes.pod.namespace": "temporal",
							"k8s:app":                         "temporal",
							"k8s:component":                   "frontend",
						}},
					},
					"toPorts": []interface{}{
						map[string]interface{}{"ports": []interface{}{
							map[string]interface{}{"port": "7233", "protocol": "TCP"},
						}},
					},
				},
			},
		},
	}}
	return &Snapshot{
		Namespace: "",
		Pods: []corev1.Pod{
			pod("agents", "agent-a-123", map[string]string{"agent": "a"}),
			pod("temporal", "temporal-frontend-1", map[string]string{"app": "temporal", "component": "frontend"}),
			pod("temporal", "temporal-worker-1", map[string]string{"app": "temporal", "component": "worker"}),
		},
		CiliumNamespacePolicies: []unstructured.Unstructured{cnp},
	}
}

func TestExplainPathAllowAndDeny(t *testing.T) {
	snap := ciliumSnapshot()

	allow, err := ExplainPath(snap, "", "agents/agent-a-123", "temporal/temporal-frontend-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if !allow.Cell.Allowed {
		t.Errorf("expected ALLOW to frontend, got reason %q", allow.Cell.Reason)
	}
	if allow.Verdict() != "REACHABLE" {
		t.Errorf("expected REACHABLE, got %q", allow.Verdict())
	}

	deny, err := ExplainPath(snap, "", "agents/agent-a-123", "temporal/temporal-worker-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if deny.Cell.Allowed {
		t.Errorf("expected DENY to worker, got ALLOW")
	}
	if deny.Verdict() != "BLOCKED at NetworkPolicy" {
		t.Errorf("expected BLOCKED at NetworkPolicy, got %q", deny.Verdict())
	}
	if l := findLayer(deny, "NetworkPolicy"); l.Fix == "" {
		t.Errorf("expected a how-to-allow suggestion for a denied edge")
	}
}

func TestResolveRefByLabel(t *testing.T) {
	snap := ciliumSnapshot()
	res, err := ExplainPath(snap, "", "agents:agent=a", "temporal/temporal-frontend-1", "7233")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SrcPods) != 1 || res.SrcPods[0] != "agents/agent-a-123" {
		t.Errorf("label selector resolved to %v", res.SrcPods)
	}
	if !res.Cell.Allowed {
		t.Errorf("expected ALLOW on 7233, got %q", res.Cell.Reason)
	}
}

// A source isolated by an egress policy whose ONLY matching rule is a
// toFQDNs rule (which the engine can't evaluate) must yield UNKNOWN, not a
// false DENY. This is the agents→external-FQDN case.
func TestFQDNOnlyEgressIsUnknownNotDeny(t *testing.T) {
	cnp := unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata":   map[string]interface{}{"namespace": "agents", "name": "fqdn-egress"},
		"spec": map[string]interface{}{
			"endpointSelector": map[string]interface{}{},
			"egress": []interface{}{
				map[string]interface{}{
					"toFQDNs": []interface{}{
						map[string]interface{}{"matchName": "login.microsoftonline.com"},
					},
					"toPorts": []interface{}{
						map[string]interface{}{"ports": []interface{}{
							map[string]interface{}{"port": "443", "protocol": "TCP"},
						}},
					},
				},
			},
		},
	}}
	snap := &Snapshot{
		Pods: []corev1.Pod{
			pod("agents", "agent-a-123", map[string]string{"agent": "a"}),
			pod("other", "some-pod-1", map[string]string{"app": "x"}),
		},
		CiliumNamespacePolicies: []unstructured.Unstructured{cnp},
	}

	res, err := ExplainPath(snap, "", "agents/agent-a-123", "other/some-pod-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Cell.Allowed {
		t.Fatalf("did not expect ALLOW; FQDN rule is not evaluated")
	}
	if !res.Cell.Unknown {
		t.Errorf("expected UNKNOWN (isolated + skipped FQDN rule), got DENY with reason %q", res.Cell.Reason)
	}
}

// With a resolver, a toFQDNs rule whose name resolves to an in-cluster pod
// IP becomes a real ALLOW edge; a name resolving externally lands in the
// ExternalEgress report instead.
func TestFQDNResolutionMatchesPodAndReportsExternal(t *testing.T) {
	dstPod := pod("temporal", "frontend-1", map[string]string{"app": "temporal"})
	dstPod.Status.PodIP = "10.0.3.7"

	cnp := unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata":   map[string]interface{}{"namespace": "agents", "name": "fqdn-egress"},
		"spec": map[string]interface{}{
			"endpointSelector": map[string]interface{}{},
			"egress": []interface{}{
				map[string]interface{}{
					"toFQDNs": []interface{}{
						map[string]interface{}{"matchName": "internal.svc.example"},
						map[string]interface{}{"matchName": "api.stripe.com"},
					},
					"toPorts": []interface{}{
						map[string]interface{}{"ports": []interface{}{
							map[string]interface{}{"port": "443", "protocol": "TCP"},
						}},
					},
				},
			},
		},
	}}
	snap := &Snapshot{
		Pods:                    []corev1.Pod{pod("agents", "agent-a-1", map[string]string{"agent": "a"}), dstPod},
		CiliumNamespacePolicies: []unstructured.Unstructured{cnp},
		Resolver: MapResolver{
			"internal.svc.example": {"10.0.3.7"},        // points at the pod
			"api.stripe.com":    {"160.79.104.10"},   // external
		},
	}

	res, err := ExplainPath(snap, "", "agents/agent-a-1", "temporal/frontend-1", "443")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cell.Allowed {
		t.Errorf("FQDN internal.svc.example resolves to the dst pod IP — expected ALLOW, got %q", res.Cell.Reason)
	}

	ev := NewBasicEvaluator()
	m, err := ev.Evaluate(snap, GroupByPod, "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	foundExternal := false
	for _, e := range m.ExternalEgress {
		if e.Target == "api.stripe.com" {
			foundExternal = true
		}
		if e.Target == "internal.svc.example" {
			t.Errorf("internal.svc.example resolves to a pod — should NOT be listed as external egress")
		}
	}
	if !foundExternal {
		t.Errorf("expected api.stripe.com in ExternalEgress; got %+v", m.ExternalEgress)
	}
}

// An egress rule that matches at L4 but also carries an HTTP rule should
// yield ALLOW with L7Restricted set, not a plain ALLOW.
func TestL7RestrictedAllow(t *testing.T) {
	dst := pod("svc", "api-1", map[string]string{"app": "api"})
	cnp := unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata":   map[string]interface{}{"namespace": "agents", "name": "l7-egress"},
		"spec": map[string]interface{}{
			"endpointSelector": map[string]interface{}{},
			"egress": []interface{}{
				map[string]interface{}{
					"toEndpoints": []interface{}{
						map[string]interface{}{"matchLabels": map[string]interface{}{
							"k8s:io.kubernetes.pod.namespace": "svc",
							"k8s:app":                         "api",
						}},
					},
					"toPorts": []interface{}{
						map[string]interface{}{
							"ports": []interface{}{map[string]interface{}{"port": "8080", "protocol": "TCP"}},
							"rules": map[string]interface{}{
								"http": []interface{}{map[string]interface{}{"method": "GET", "path": "/healthz"}},
							},
						},
					},
				},
			},
		},
	}}
	snap := &Snapshot{
		Pods:                    []corev1.Pod{pod("agents", "agent-a-1", map[string]string{"agent": "a"}), dst},
		CiliumNamespacePolicies: []unstructured.Unstructured{cnp},
	}
	res, err := ExplainPath(snap, "", "agents/agent-a-1", "svc/api-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cell.Allowed {
		t.Fatalf("expected ALLOW (L4 match), got %q", res.Cell.Reason)
	}
	if !res.Cell.L7Restricted {
		t.Errorf("expected L7Restricted=true for a rule with http conditions")
	}
}

// A standard NetworkPolicy ingress rule using a namespaceSelector must match
// a source whose namespace carries the selected label.
func TestNamespaceSelectorMatching(t *testing.T) {
	// dst in "prod" isolated for ingress, allows from namespaces labeled team=blue.
	np := ingressFromNamespaceLabel("prod", "allow-blue", map[string]string{"app": "db"},
		"team", "blue")
	snap := &Snapshot{
		Pods: []corev1.Pod{
			pod("prod", "db-1", map[string]string{"app": "db"}),
			pod("blue-ns", "client-1", map[string]string{"app": "client"}),
			pod("red-ns", "client-2", map[string]string{"app": "client"}),
		},
		Policies: []networkingv1.NetworkPolicy{np},
		NamespaceLabels: map[string]map[string]string{
			"blue-ns": {"team": "blue"},
			"red-ns":  {"team": "red"},
			"prod":    {},
		},
	}
	allow, err := ExplainPath(snap, "", "blue-ns/client-1", "prod/db-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if !allow.Cell.Allowed {
		t.Errorf("blue-ns is labeled team=blue — expected ALLOW, got %q", allow.Cell.Reason)
	}
	deny, err := ExplainPath(snap, "", "red-ns/client-2", "prod/db-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if deny.Cell.Allowed {
		t.Errorf("red-ns is not team=blue — expected DENY")
	}
}

func TestResolveRefMissing(t *testing.T) {
	snap := ciliumSnapshot()
	if _, err := ExplainPath(snap, "", "agents/nope", "temporal/temporal-frontend-1", ""); err == nil {
		t.Errorf("expected error for unknown source pod")
	}
}

func findLayer(r *PathResult, name string) Layer {
	for _, l := range r.Layers {
		if l.Name == name {
			return l
		}
	}
	return Layer{}
}

func TestDiffNewlyAllowed(t *testing.T) {
	// Before: the worker is denied. After: add a rule allowing worker:7233.
	before := ciliumSnapshot()
	newPolicy := []byte(`
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  namespace: agents
  name: baseline-egress
spec:
  endpointSelector: {}
  egress:
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: temporal
            k8s:app: temporal
            k8s:component: frontend
      toPorts:
        - ports:
            - port: "7233"
              protocol: TCP
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: temporal
            k8s:app: temporal
            k8s:component: worker
      toPorts:
        - ports:
            - port: "7233"
              protocol: TCP
`)
	docs, err := SplitYAMLDocuments(newPolicy)
	if err != nil {
		t.Fatal(err)
	}
	after, err := before.ApplyManifests(docs)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Diff(before, after, GroupByPod, "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range d.NewlyAllowed {
		if c.Key.Src == "agents/agent-a-123" && c.Key.Dst == "temporal/temporal-worker-1" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected worker edge to become newly allowed; got %+v", d.NewlyAllowed)
	}
	if len(d.NewlyDenied) != 0 {
		t.Errorf("did not expect any newly denied edges; got %+v", d.NewlyDenied)
	}
}
