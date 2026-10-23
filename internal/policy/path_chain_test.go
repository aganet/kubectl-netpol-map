package policy

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// readyPod is a Running, Ready pod with one container declaring the given
// named ports.
func readyPod(ns, name string, lbl map[string]string, ports map[string]int32) corev1.Pod {
	p := pod(ns, name, lbl)
	c := corev1.Container{Name: "app"}
	for n, v := range ports {
		c.Ports = append(c.Ports, corev1.ContainerPort{Name: n, ContainerPort: v})
	}
	p.Spec.Containers = []corev1.Container{c}
	p.Status.Phase = corev1.PodRunning
	p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	return p
}

func crashingPod(ns, name string, lbl map[string]string) corev1.Pod {
	p := pod(ns, name, lbl)
	p.Status.Phase = corev1.PodRunning
	p.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name: "app", RestartCount: 7,
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
	}}
	return p
}

func service(ns, name string, selector map[string]string, port int32, target intstr.IntOrString) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.0.10",
			Selector:  selector,
			Ports:     []corev1.ServicePort{{Name: "http", Port: port, TargetPort: target, Protocol: corev1.ProtocolTCP}},
		},
	}
}

// shopSnapshot: shop/frontend → payments/api (Service 8080 → "http" = 8000),
// with kube-dns present so the DNS egress layer is evaluated.
func shopSnapshot() *Snapshot {
	return &Snapshot{
		Pods: []corev1.Pod{
			readyPod("shop", "frontend-1", map[string]string{"app": "frontend"}, nil),
			readyPod("payments", "api-1", map[string]string{"app": "api"}, map[string]int32{"http": 8000}),
			crashingPod("payments", "api-2", map[string]string{"app": "api"}),
			readyPod("kube-system", "coredns-1", map[string]string{"k8s-app": "kube-dns"}, map[string]int32{"dns": 53}),
		},
		Services: []corev1.Service{
			service("payments", "api", map[string]string{"app": "api"}, 8080, intstr.FromString("http")),
		},
	}
}

func TestPathServiceChainReachable(t *testing.T) {
	res, err := ExplainPath(shopSnapshot(), "", "shop/frontend", "api.payments.svc.cluster.local:8080", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict() != "REACHABLE" {
		t.Fatalf("expected REACHABLE, got %q; layers: %+v", res.Verdict(), res.Layers)
	}
	if res.Service == nil || res.Service.Matched != 2 || res.Service.Ready != 1 {
		t.Errorf("expected Service hop with 2 matched / 1 ready, got %+v", res.Service)
	}
	if res.TargetPort != 8000 {
		t.Errorf("policy must be evaluated at the pod port 8000, got %d", res.TargetPort)
	}
	// Only the Ready pod is an endpoint.
	if len(res.DstPods) != 1 || res.DstPods[0] != "payments/api-1" {
		t.Errorf("expected only the ready pod as destination, got %v", res.DstPods)
	}
	want := []string{"DNS egress", "DNS", "Service", "Port", "NetworkPolicy", "Mesh"}
	for i, l := range res.Layers {
		if l.Name != want[i] {
			t.Errorf("layer %d: want %s, got %s", i, want[i], l.Name)
		}
	}
	svc := findLayer(res, "Service")
	if len(svc.Detail) != 1 || !strings.Contains(svc.Detail[0], "CrashLoopBackOff") {
		t.Errorf("expected the crashing pod to be diagnosed, got %v", svc.Detail)
	}
	if port := findLayer(res, "Port"); !strings.Contains(port.Summary, "= 8000") {
		t.Errorf("expected the named targetPort to resolve to 8000, got %q", port.Summary)
	}
	if findLayer(res, "Mesh").Status != LayerSkip {
		t.Errorf("no sidecars: Mesh layer should be skipped")
	}
}

func TestPathNamedTargetPortMissing(t *testing.T) {
	snap := shopSnapshot()
	snap.Pods[1] = readyPod("payments", "api-1", map[string]string{"app": "api"}, map[string]int32{"web": 8000})
	res, err := ExplainPath(snap, "", "shop/frontend", "payments/api:8080", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict() != "BLOCKED at Port" {
		t.Errorf("expected BLOCKED at Port, got %q", res.Verdict())
	}
	if l := findLayer(res, "Port"); !strings.Contains(l.Fix, "8000") {
		t.Errorf("fix should list the declared container ports, got %q", l.Fix)
	}
}

func TestPathServicePortNotExposed(t *testing.T) {
	res, err := ExplainPath(shopSnapshot(), "", "shop/frontend", "payments/api:9090", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict() != "BLOCKED at Port" {
		t.Errorf("expected BLOCKED at Port, got %q", res.Verdict())
	}
}

func TestPathServiceNoReadyPods(t *testing.T) {
	snap := shopSnapshot()
	snap.Pods[1] = crashingPod("payments", "api-1", map[string]string{"app": "api"})
	res, err := ExplainPath(snap, "", "shop/frontend", "payments/api", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict() != "BLOCKED at Service" {
		t.Errorf("expected BLOCKED at Service, got %q", res.Verdict())
	}
	// The policy verdict is still computed against the matched pods.
	if len(res.DstPods) != 2 {
		t.Errorf("expected policy to be evaluated against the 2 matched pods, got %v", res.DstPods)
	}
}

func TestPathServiceSelectorMatchesNothing(t *testing.T) {
	snap := shopSnapshot()
	snap.Services[0].Spec.Selector = map[string]string{"app": "payments-api"}
	res, err := ExplainPath(snap, "", "shop/frontend", "payments/api", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict() != "BLOCKED at Service" {
		t.Errorf("expected BLOCKED at Service, got %q", res.Verdict())
	}
	if l := findLayer(res, "Service"); !strings.Contains(l.Fix, "app=api (2 pods)") {
		t.Errorf("fix should show the label values pods carry, got %q", l.Fix)
	}
}

func TestPathWrongNamespaceInDNSName(t *testing.T) {
	res, err := ExplainPath(shopSnapshot(), "", "shop/frontend", "api.payment.svc", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict() != "BLOCKED at DNS" {
		t.Errorf("expected BLOCKED at DNS, got %q", res.Verdict())
	}
	if l := findLayer(res, "DNS"); !strings.Contains(l.Fix, "api.payments.svc") {
		t.Errorf("expected a did-you-mean hint naming api.payments.svc, got %q", l.Fix)
	}
}

func TestPathDefaultNamespaceAndPortSuffix(t *testing.T) {
	res, err := ExplainPath(shopSnapshot(), "shop", "frontend", "payments/api:http", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SrcPods) != 1 || res.SrcPods[0] != "shop/frontend-1" {
		t.Errorf("unqualified source should resolve in the default namespace, got %v", res.SrcPods)
	}
	if res.TargetPort != 8000 {
		t.Errorf("Service port by name should resolve to pod port 8000, got %d", res.TargetPort)
	}
	if _, err := ExplainPath(shopSnapshot(), "shop", "frontend", "payments/api:8080", "9090"); err == nil {
		t.Errorf("expected an error when --port conflicts with the :port suffix")
	}
}

// A deny-all egress policy on the source that only opens the destination
// breaks name resolution first: the DNS egress layer must fail even though
// the policy layer allows the edge.
func TestPathDNSEgressDenied(t *testing.T) {
	snap := shopSnapshot()
	snap.Policies = []networkingv1.NetworkPolicy{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "egress-to-api"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "frontend"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{},
					PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				}},
			}},
		},
	}}
	res, err := ExplainPath(snap, "", "shop/frontend", "payments/api:8080", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict() != "BLOCKED at DNS egress" {
		t.Errorf("expected BLOCKED at DNS egress, got %q", res.Verdict())
	}
	if l := findLayer(res, "NetworkPolicy"); l.Status != LayerPass {
		t.Errorf("the edge itself is allowed; got %s: %s", l.Status, l.Summary)
	}
	if l := findLayer(res, "DNS egress"); !strings.Contains(l.Fix, "kube-dns") {
		t.Errorf("expected a fix naming kube-dns, got %q", l.Fix)
	}
}

// A standard NetworkPolicy rule on a named port must resolve against the
// destination pod's container ports.
func TestNamedPortInPolicyResolves(t *testing.T) {
	snap := shopSnapshot()
	snap.Policies = []networkingv1.NetworkPolicy{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "ingress-http"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				Ports: []networkingv1.NetworkPolicyPort{{Port: &[]intstr.IntOrString{intstr.FromString("http")}[0]}},
			}},
		},
	}}
	allow, err := ExplainPath(snap, "", "shop/frontend", "payments/api:8080", "")
	if err != nil {
		t.Fatal(err)
	}
	if !allow.Cell.Allowed || len(allow.Cell.Ports) != 1 || allow.Cell.Ports[0] != "8000" {
		t.Errorf("named port http should resolve to 8000 and allow: %+v", allow.Cell)
	}
	deny, err := ExplainPath(snap, "", "shop/frontend", "payments/api-1:9000", "")
	if err != nil {
		t.Fatal(err)
	}
	if deny.Cell.Allowed {
		t.Errorf("port 9000 is not the named port; expected DENY, got %q", deny.Cell.Reason)
	}
	// A named port no container declares matches no traffic, even with no
	// port filter and an unrestricted source.
	snap.Policies[0].Spec.Ingress[0].Ports[0].Port = &[]intstr.IntOrString{intstr.FromString("metrics")}[0]
	missing, err := ExplainPath(snap, "", "shop/frontend", "payments/api-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if missing.Cell.Allowed || !strings.Contains(missing.Cell.Reason, "named port metrics not declared") {
		t.Errorf("undeclared named port must deny and say so, got %+v", missing.Cell)
	}
}

// An egress rule that only opens 80 and an ingress rule that only opens 443
// leave no usable port: that is a DENY, not an ALLOW with no ports.
func TestDisjointPortsAreDenied(t *testing.T) {
	snap := shopSnapshot()
	one := func(ns, name string, sel map[string]string, pt networkingv1.PolicyType, port int) networkingv1.NetworkPolicy {
		p := intstr.FromInt(port)
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec:       networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: sel}, PolicyTypes: []networkingv1.PolicyType{pt}},
		}
		if pt == networkingv1.PolicyTypeEgress {
			np.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{Ports: []networkingv1.NetworkPolicyPort{{Port: &p}}}}
		} else {
			np.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{Ports: []networkingv1.NetworkPolicyPort{{Port: &p}}}}
		}
		return np
	}
	snap.Policies = []networkingv1.NetworkPolicy{
		one("shop", "egress-80", map[string]string{"app": "frontend"}, networkingv1.PolicyTypeEgress, 80),
		one("payments", "ingress-443", map[string]string{"app": "api"}, networkingv1.PolicyTypeIngress, 443),
	}
	res, err := ExplainPath(snap, "", "shop/frontend", "payments/api-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Cell.Allowed || !strings.Contains(res.Cell.Reason, "no port in common") {
		t.Errorf("expected DENY for disjoint ports, got %+v", res.Cell)
	}
	snap.Policies[1] = one("payments", "ingress-80", map[string]string{"app": "api"}, networkingv1.PolicyTypeIngress, 80)
	res, err = ExplainPath(snap, "", "shop/frontend", "payments/api-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cell.Allowed || len(res.Cell.Ports) != 1 || res.Cell.Ports[0] != "80" {
		t.Errorf("expected ALLOW :80 when both sides open 80, got %+v", res.Cell)
	}
}

func TestPathMeshStrictWithoutSidecar(t *testing.T) {
	snap := shopSnapshot()
	snap.Pods[1].Spec.Containers = append(snap.Pods[1].Spec.Containers, corev1.Container{Name: "istio-proxy"})
	snap.Mesh = &MeshSnapshot{PeerAuthentications: []unstructured.Unstructured{{Object: map[string]interface{}{
		"apiVersion": "security.istio.io/v1",
		"kind":       "PeerAuthentication",
		"metadata":   map[string]interface{}{"namespace": "payments", "name": "default"},
		"spec":       map[string]interface{}{"mtls": map[string]interface{}{"mode": "STRICT"}},
	}}}}
	res, err := ExplainPath(snap, "", "shop/frontend", "payments/api:8080", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict() != "BLOCKED at Mesh" {
		t.Errorf("expected BLOCKED at Mesh, got %q", res.Verdict())
	}
	if l := findLayer(res, "Mesh"); !strings.Contains(l.Summary, "payments/default") {
		t.Errorf("expected the PeerAuthentication to be named, got %q", l.Summary)
	}

	// A port-level PERMISSIVE override on the evaluated pod port lifts it.
	snap.Mesh.PeerAuthentications[0].Object["spec"].(map[string]interface{})["portLevelMtls"] =
		map[string]interface{}{"8000": map[string]interface{}{"mode": "PERMISSIVE"}}
	res, err = ExplainPath(snap, "", "shop/frontend", "payments/api:8080", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict() != "REACHABLE" {
		t.Errorf("expected port-level PERMISSIVE to allow, got %q", res.Verdict())
	}
}

func TestParseRef(t *testing.T) {
	cases := []struct {
		in   string
		want ref
	}{
		{"shop/frontend", ref{ns: "shop", name: "frontend"}},
		{"shop/api:8080", ref{ns: "shop", name: "api", port: "8080"}},
		{"shop/api:http", ref{ns: "shop", name: "api", port: "http"}},
		{"api.payments.svc.cluster.local:8080", ref{ns: "payments", name: "api", dns: true, cluster: true, port: "8080"}},
		{"api.payments", ref{ns: "payments", name: "api", dns: true}},
		{"shop:app=frontend", ref{ns: "shop", selector: "app=frontend"}},
		{"shop:app=frontend:8080", ref{ns: "shop", selector: "app=frontend", port: "8080"}},
		{"shop:app", ref{ns: "shop", selector: "app"}},
		{"api:8080", ref{ns: "default", name: "api", port: "8080"}},
		{"api", ref{ns: "default", name: "api"}},
	}
	for _, c := range cases {
		got, err := parseRef(c.in, "default")
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q: got %+v, want %+v", c.in, got, c.want)
		}
	}
	for _, ext := range []string{"internet", "1.2.3.4", "10.0.0.0/8", "api.stripe.com:443"} {
		r, err := parseRef(ext, "default")
		if err != nil || r.external == nil {
			t.Errorf("%q: expected an external destination, got %+v (%v)", ext, r, err)
		}
	}
	for _, bad := range []string{"", "/x", "ns/"} {
		if _, err := parseRef(bad, ""); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}
