package policy

import (
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/aganet/kubectl-netpol-map/internal/kube"
)

func cr(apiVersion, kind, ns, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": apiVersion, "kind": kind,
		"metadata": map[string]interface{}{"namespace": ns, "name": name},
		"spec":     map[string]interface{}{},
	}}
}

func fakeClients(t *testing.T, objs []runtime.Object, crs ...*unstructured.Unstructured) *kube.Clients {
	t.Helper()
	kc := fake.NewClientset(objs...)
	listKinds := map[schema.GroupVersionResource]string{
		cnpGVR:  "CiliumNetworkPolicyList",
		ccnpGVR: "CiliumClusterwideNetworkPolicyList",
		{Group: "security.istio.io", Version: "v1", Resource: "peerauthentications"}: "PeerAuthenticationList",
	}
	for _, k := range unevaluatedKinds {
		listKinds[k.gvr] = strings.ReplaceAll(k.kind, " ", "") + "List"
	}
	dyn := make([]runtime.Object, 0, len(crs))
	for _, c := range crs {
		dyn = append(dyn, c)
	}
	dc := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, dyn...)
	return &kube.Clients{Kube: kc, Dynamic: dc}
}

func TestFetchListsEverythingClusterWide(t *testing.T) {
	c := fakeClients(t, []runtime.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "shop", Labels: map[string]string{"team": "web"}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "frontend-1"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api-1"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "frontend-abc"}},
		&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "deny-all"}},
	}, cr("cilium.io/v2", "CiliumNetworkPolicy", "shop", "egress"), cr("cilium.io/v2", "CiliumClusterwideNetworkPolicy", "", "baseline"),
		cr("policy.networking.k8s.io/v1alpha1", "AdminNetworkPolicy", "", "cluster-baseline"))

	snap, err := Fetch(context.Background(), c, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Unevaluated) != 1 || snap.Unevaluated[0] != "AdminNetworkPolicy ×1" {
		t.Errorf("policy kinds the tool ignores must be reported: %v", snap.Unevaluated)
	}
	if len(snap.Pods) != 2 || len(snap.Services) != 1 || len(snap.ReplicaSets) != 1 || len(snap.Policies) != 1 {
		t.Errorf("unexpected counts: pods %d services %d rs %d policies %d", len(snap.Pods), len(snap.Services), len(snap.ReplicaSets), len(snap.Policies))
	}
	if snap.NamespaceLabels["shop"]["team"] != "web" {
		t.Errorf("namespace labels not fetched: %v", snap.NamespaceLabels)
	}
	if len(snap.CiliumNamespacePolicies) != 1 || len(snap.CiliumClusterPolicies) != 1 {
		t.Errorf("cilium CRs: cnp %d ccnp %d", len(snap.CiliumNamespacePolicies), len(snap.CiliumClusterPolicies))
	}

	scoped, err := Fetch(context.Background(), c, "payments")
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped.Pods) != 1 || len(scoped.CiliumNamespacePolicies) != 0 || len(scoped.CiliumClusterPolicies) != 1 {
		t.Errorf("namespace scoping: pods %d cnp %d ccnp %d", len(scoped.Pods), len(scoped.CiliumNamespacePolicies), len(scoped.CiliumClusterPolicies))
	}
}

// FetchMesh must discover the served API version instead of guessing it,
// and stay empty (not fail) when the mesh CRDs are absent.
func TestFetchMeshDiscoversVersions(t *testing.T) {
	c := fakeClients(t, nil, cr("security.istio.io/v1", "PeerAuthentication", "payments", "default"))
	disc := c.Kube.Discovery().(*fakediscovery.FakeDiscovery)
	disc.Resources = []*metav1.APIResourceList{{
		GroupVersion: "security.istio.io/v1",
		APIResources: []metav1.APIResource{{Name: "peerauthentications", Kind: "PeerAuthentication", Namespaced: true}},
	}}
	m := FetchMesh(context.Background(), c)
	if m == nil || len(m.PeerAuthentications) != 1 || len(m.AuthorizationPolicies) != 0 {
		t.Fatalf("expected one PeerAuthentication via discovery, got %+v", m)
	}

	bare := fakeClients(t, nil)
	if m := FetchMesh(context.Background(), bare); m == nil || len(m.PeerAuthentications) != 0 {
		t.Errorf("no mesh CRDs: expected an empty snapshot, got %+v", m)
	}
}
