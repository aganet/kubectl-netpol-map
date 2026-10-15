package policy

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/aganet/kubectl-npmap/internal/kube"
)

// Snapshot is the cluster state we evaluate against.
type Snapshot struct {
	Namespace string
	Pods      []corev1.Pod
	// ReplicaSets are used to walk owner refs: Pod→ReplicaSet→Deployment.
	ReplicaSets []appsv1.ReplicaSet
	// Policies are standard Kubernetes networking.k8s.io/v1 NetworkPolicies.
	Policies []networkingv1.NetworkPolicy
	// CiliumNamespacePolicies are CiliumNetworkPolicy (cilium.io/v2) CRs.
	CiliumNamespacePolicies []unstructured.Unstructured
	// CiliumClusterPolicies are CiliumClusterwideNetworkPolicy CRs.
	CiliumClusterPolicies []unstructured.Unstructured
	// Services let `path` follow a destination given as a Service through its
	// selector and port mapping.
	Services []corev1.Service
	// NamespaceLabels maps namespace name → its labels, used to evaluate peer
	// namespaceSelector matching across namespaces.
	NamespaceLabels map[string]map[string]string
	// Mesh holds service-mesh policy objects for the `path` Mesh layer. Nil
	// unless the caller ran FetchMesh.
	Mesh *MeshSnapshot
	// Resolver resolves toFQDNs names to IPs so an FQDN egress rule pointing
	// back into the cluster becomes a real edge. Nil means FQDN rules are not
	// resolved (they remain UNKNOWN). Set by the caller, not by Fetch.
	Resolver Resolver
}

var (
	cnpGVR = schema.GroupVersionResource{
		Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies",
	}
	ccnpGVR = schema.GroupVersionResource{
		Group: "cilium.io", Version: "v2", Resource: "ciliumclusterwidenetworkpolicies",
	}
)

// Fetch lists everything the evaluator needs from the cluster. Cilium CRDs
// are listed best-effort — if the CRDs aren't installed, the corresponding
// slices are simply empty.
func Fetch(ctx context.Context, c *kube.Clients, namespace string) (*Snapshot, error) {
	pods, err := c.Kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	nps, err := c.Kube.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	// ReplicaSets and Services are best-effort — workload grouping degrades
	// gracefully (Pods owned by an RS fall back to the RS itself) and Service
	// references simply fail to resolve if listing is forbidden.
	var rs []appsv1.ReplicaSet
	if rsList, err := c.Kube.AppsV1().ReplicaSets(namespace).List(ctx, metav1.ListOptions{}); err == nil {
		rs = rsList.Items
	}
	var svcs []corev1.Service
	if svcList, err := c.Kube.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{}); err == nil {
		svcs = svcList.Items
	}

	// Namespace labels are cluster-scoped and best-effort: needed to evaluate
	// peer namespaceSelector matching. If RBAC forbids listing namespaces the
	// map is empty and cross-namespace selectors fall back to conservative
	// behaviour.
	nsLabels := map[string]map[string]string{}
	if nsList, err := c.Kube.CoreV1().Namespaces().List(ctx, metav1.ListOptions{}); err == nil {
		for _, n := range nsList.Items {
			nsLabels[n.Name] = n.Labels
		}
	}

	return &Snapshot{
		Namespace:               namespace,
		Pods:                    pods.Items,
		ReplicaSets:             rs,
		Services:                svcs,
		Policies:                nps.Items,
		NamespaceLabels:         nsLabels,
		CiliumNamespacePolicies: listDynamic(ctx, c.Dynamic, cnpGVR, namespace),
		CiliumClusterPolicies:   listDynamic(ctx, c.Dynamic, ccnpGVR, ""),
	}, nil
}

// listDynamic lists a CRD silently — returns nil on any error (CRD missing,
// RBAC denied, etc.) so the rest of the tool keeps working.
func listDynamic(ctx context.Context, dc dynamic.Interface, gvr schema.GroupVersionResource, namespace string) []unstructured.Unstructured {
	var (
		list *unstructured.UnstructuredList
		err  error
	)
	if namespace == "" {
		list, err = dc.Resource(gvr).List(ctx, metav1.ListOptions{})
	} else {
		list, err = dc.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
	}
	if err != nil || list == nil {
		return nil
	}
	return list.Items
}
