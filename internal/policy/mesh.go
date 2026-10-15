package policy

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"

	"github.com/aganet/kubectl-netpol-map/internal/kube"
)

// MeshSnapshot holds the service-mesh policy objects the `path` Mesh layer
// inspects. Istio mTLS mode is evaluated; the rest is detected and flagged.
type MeshSnapshot struct {
	PeerAuthentications          []unstructured.Unstructured // security.istio.io
	AuthorizationPolicies        []unstructured.Unstructured // security.istio.io
	LinkerdServers               []unstructured.Unstructured // policy.linkerd.io
	LinkerdAuthorizationPolicies []unstructured.Unstructured // policy.linkerd.io
}

// Istio's root namespace, where mesh-wide policies live.
const istioRootNamespace = "istio-system"

// FetchMesh lists mesh policy CRs best-effort. The served API versions differ
// between Istio and Linkerd releases, so they are discovered rather than
// hardcoded; a group that is not installed costs one discovery call.
func FetchMesh(ctx context.Context, c *kube.Clients) *MeshSnapshot {
	disc := c.Kube.Discovery()
	groups, err := disc.ServerGroups()
	if err != nil {
		return nil
	}
	m := &MeshSnapshot{}
	for _, want := range []struct {
		group, resource string
		into            *[]unstructured.Unstructured
	}{
		{"security.istio.io", "peerauthentications", &m.PeerAuthentications},
		{"security.istio.io", "authorizationpolicies", &m.AuthorizationPolicies},
		{"policy.linkerd.io", "servers", &m.LinkerdServers},
		{"policy.linkerd.io", "authorizationpolicies", &m.LinkerdAuthorizationPolicies},
	} {
		if gvr, ok := servedGVR(disc, groups, want.group, want.resource); ok {
			*want.into = listDynamic(ctx, c.Dynamic, gvr, "")
		}
	}
	return m
}

func servedGVR(disc discovery.DiscoveryInterface, groups *metav1.APIGroupList, group, resource string) (schema.GroupVersionResource, bool) {
	for _, g := range groups.Groups {
		if g.Name != group {
			continue
		}
		for _, v := range g.Versions {
			list, err := disc.ServerResourcesForGroupVersion(v.GroupVersion)
			if err != nil {
				continue
			}
			for _, r := range list.APIResources {
				if r.Name == resource {
					return schema.GroupVersionResource{Group: group, Version: v.Version, Resource: resource}, true
				}
			}
		}
	}
	return schema.GroupVersionResource{}, false
}

// meshLayer reports what a service mesh adds on top of NetworkPolicy for
// this edge. Only Istio's PeerAuthentication mTLS mode is decided here (a
// STRICT destination rejects a sidecar-less source); authorization policies
// are listed so the user knows another engine has a say.
func meshLayer(snap *Snapshot, src, dst []corev1.Pod, port int32) Layer {
	srcMesh, srcN := sidecars(src)
	dstMesh, dstN := sidecars(dst)
	ambient := false
	for _, p := range dst {
		if snap.NamespaceLabels[p.Namespace]["istio.io/dataplane-mode"] == "ambient" {
			ambient = true
		}
	}
	if srcMesh == "" && dstMesh == "" && !ambient {
		return Layer{Name: "Mesh", Status: LayerSkip, Summary: "no Istio/Linkerd sidecar on either side"}
	}

	l := Layer{Name: "Mesh", Status: LayerPass, Detail: []string{
		fmt.Sprintf("source: %s", describeSidecar(srcMesh, srcN, len(src))),
		fmt.Sprintf("destination: %s", describeSidecar(dstMesh, dstN, len(dst))),
	}}
	mesh := snap.Mesh
	if mesh == nil {
		mesh = &MeshSnapshot{}
	}

	switch {
	case ambient:
		l.Status = LayerWarn
		l.Summary = "destination namespace is in Istio ambient mode; ztunnel/waypoint policy is not evaluated"
	case dstMesh == "istio":
		mode, by := istioMTLSMode(mesh, dst, port)
		if mode == "STRICT" && srcMesh != "istio" {
			l.Status = LayerFail
			l.Summary = fmt.Sprintf("destination requires mTLS (%s: STRICT) but the source has no Istio sidecar", by)
			l.Fix = "inject the sidecar into the source (label its namespace istio-injection=enabled and restart the\n" +
				"  workload), or set that PeerAuthentication to mode PERMISSIVE"
		} else {
			l.Summary = fmt.Sprintf("Istio sidecar on the destination; mTLS %s (%s)", mode, by)
		}
		if authz := istioAuthzFor(mesh, dst); len(authz) > 0 {
			if l.Status == LayerPass {
				l.Status = LayerWarn
			}
			l.Detail = append(l.Detail, fmt.Sprintf("%d AuthorizationPolicy apply to the destination and are not evaluated: %s",
				len(authz), strings.Join(authz, ", ")))
			if l.Fix == "" {
				l.Fix = fmt.Sprintf("check them with: istioctl x authz check %s -n %s", dst[0].Name, dst[0].Namespace)
			}
		}
	case dstMesh == "linkerd":
		if servers := linkerdServersFor(mesh, dst); len(servers) > 0 {
			l.Status = LayerWarn
			l.Summary = fmt.Sprintf("Linkerd Server(s) select the destination; their authorization is not evaluated: %s",
				strings.Join(servers, ", "))
			l.Fix = fmt.Sprintf("check with: linkerd viz authz -n %s po/%s", dst[0].Namespace, dst[0].Name)
		} else {
			l.Summary = "Linkerd proxy on the destination; no Server selects it, so the default inbound policy applies"
		}
	default:
		l.Summary = "sidecar on the source only; the destination accepts plaintext"
	}
	return l
}

// sidecars reports which mesh proxy the pods carry and on how many of them.
func sidecars(pods []corev1.Pod) (mesh string, n int) {
	for _, p := range pods {
		for _, c := range append(p.Spec.InitContainers, p.Spec.Containers...) {
			switch c.Name {
			case "istio-proxy":
				mesh = "istio"
			case "linkerd-proxy":
				mesh = "linkerd"
			default:
				continue
			}
			n++
			break
		}
	}
	return mesh, n
}

func describeSidecar(mesh string, n, total int) string {
	if mesh == "" {
		return "no sidecar"
	}
	return fmt.Sprintf("%s sidecar on %d/%d pods", mesh, n, total)
}

// istioMTLSMode returns the effective PeerAuthentication mode for the
// destination pods and the policy that set it, following Istio precedence:
// workload selector > namespace-wide > mesh-wide (root namespace). A
// port-level override for the evaluated port wins within a policy.
func istioMTLSMode(m *MeshSnapshot, dst []corev1.Pod, port int32) (mode, by string) {
	ns := dst[0].Namespace
	var workload, nsWide, meshWide []unstructured.Unstructured
	for _, pa := range m.PeerAuthentications {
		sel, _, _ := unstructured.NestedMap(pa.Object, "spec", "selector", "matchLabels")
		switch {
		case pa.GetNamespace() == ns && len(sel) > 0:
			if anyPodMatches(dst, labels.SelectorFromSet(normalizeStringMap(sel))) {
				workload = append(workload, pa)
			}
		case pa.GetNamespace() == ns:
			nsWide = append(nsWide, pa)
		case pa.GetNamespace() == istioRootNamespace && len(sel) == 0:
			meshWide = append(meshWide, pa)
		}
	}
	for _, tier := range [][]unstructured.Unstructured{workload, nsWide, meshWide} {
		for _, pa := range tier {
			key := "PeerAuthentication " + pa.GetNamespace() + "/" + pa.GetName()
			if port != 0 {
				if pm, _, _ := unstructured.NestedString(pa.Object, "spec", "portLevelMtls", strconv.Itoa(int(port)), "mode"); pm != "" {
					return pm, key + " port " + strconv.Itoa(int(port))
				}
			}
			if mm, _, _ := unstructured.NestedString(pa.Object, "spec", "mtls", "mode"); mm != "" && mm != "UNSET" {
				return mm, key
			}
		}
	}
	return "PERMISSIVE", "Istio default"
}

// istioAuthzFor lists AuthorizationPolicies that apply to the destination:
// in its namespace with a matching (or absent) selector, or mesh-wide.
func istioAuthzFor(m *MeshSnapshot, dst []corev1.Pod) []string {
	ns := dst[0].Namespace
	out := []string{}
	for _, ap := range m.AuthorizationPolicies {
		sel, _, _ := unstructured.NestedMap(ap.Object, "spec", "selector", "matchLabels")
		switch {
		case ap.GetNamespace() == ns && len(sel) > 0:
			if !anyPodMatches(dst, labels.SelectorFromSet(normalizeStringMap(sel))) {
				continue
			}
		case ap.GetNamespace() == ns:
		case ap.GetNamespace() == istioRootNamespace && len(sel) == 0:
		default:
			continue
		}
		out = append(out, ap.GetNamespace()+"/"+ap.GetName())
	}
	sort.Strings(out)
	return out
}

// linkerdServersFor lists Linkerd Servers whose podSelector matches the
// destination pods.
func linkerdServersFor(m *MeshSnapshot, dst []corev1.Pod) []string {
	out := []string{}
	for _, s := range m.LinkerdServers {
		if s.GetNamespace() != dst[0].Namespace {
			continue
		}
		raw, found, _ := unstructured.NestedMap(s.Object, "spec", "podSelector")
		if !found {
			continue
		}
		var ls metav1.LabelSelector
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(raw, &ls); err != nil {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(&ls)
		if err != nil || !anyPodMatches(dst, sel) {
			continue
		}
		out = append(out, s.GetNamespace()+"/"+s.GetName())
	}
	sort.Strings(out)
	return out
}

func anyPodMatches(pods []corev1.Pod, sel labels.Selector) bool {
	for _, p := range pods {
		if sel.Matches(labels.Set(p.Labels)) {
			return true
		}
	}
	return false
}
