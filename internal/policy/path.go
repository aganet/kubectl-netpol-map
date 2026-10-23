package policy

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// PathResult answers `kubectl netpol-map path <src> <dst>`: the chain of layers a
// connection crosses, checked in order, plus the NetworkPolicy verdict
// aggregated across every pod pair the two references resolve to.
type PathResult struct {
	SrcRef  string // the references as the user typed them
	DstRef  string
	SrcPods []string // resolved pod names (ns/name)
	DstPods []string
	// Service is set when the destination was given as a Service; the chain
	// then walks DNS egress → DNS → Service → Port → NetworkPolicy → Mesh.
	// Nil when the destination is a pod set (only the last two apply).
	Service *ServiceHop
	// External is set when the destination is outside the cluster (a host,
	// an IP/CIDR or "internet"); the chain is then DNS egress → Egress
	// policy → Mesh and DstPods is empty.
	External string
	// Port is the destination port as asked: a Service port (number or name)
	// when via a Service, else the pod port. Empty = any.
	Port string
	// TargetPort is the pod port the NetworkPolicy layer was evaluated at
	// (0 = any). It differs from Port when the Service maps port → targetPort.
	TargetPort int32
	// Protocol is the Service port's protocol when the destination is a
	// single Service port; rules opening the port on another protocol then
	// do not count.
	Protocol string
	Layers   []Layer
	Cell     Cell // NetworkPolicy verdict across all pairs
	PerPair  []Pair
}

// ServiceHop is the Service the destination resolved through.
type ServiceHop struct {
	Namespace string
	Name      string
	Type      string
	ClusterIP string
	Selector  map[string]string
	Matched   int // pods the selector matches
	Ready     int // of those, Ready — i.e. actual endpoints
}

// Layer is one hop of the chain. Fail breaks the chain; Warn marks a caveat
// the engine cannot settle (PARTIAL, UNKNOWN, un-evaluated mesh policy).
type Layer struct {
	Name    string
	Status  LayerStatus
	Summary string
	Detail  []string
	Fix     string
}

type LayerStatus string

const (
	LayerPass LayerStatus = "pass"
	LayerWarn LayerStatus = "warn"
	LayerFail LayerStatus = "fail"
	LayerSkip LayerStatus = "skip"
)

// Pair is one resolved (src-pod, dst-pod) verdict inside a PathResult.
type Pair struct {
	Src     string
	Dst     string
	Allowed bool
	Unknown bool
	Ports   []string
	Reason  string
}

// Status is the worst layer status: fail > warn > pass.
func (r *PathResult) Status() LayerStatus {
	worst := LayerPass
	for _, l := range r.Layers {
		switch {
		case l.Status == LayerFail:
			return LayerFail
		case l.Status == LayerWarn:
			worst = LayerWarn
		}
	}
	return worst
}

// Verdict is the one-line answer: BLOCKED at the first failing layer,
// REACHABLE with caveats naming the first unsettled one, else REACHABLE.
func (r *PathResult) Verdict() string {
	for _, l := range r.Layers {
		if l.Status == LayerFail {
			return "BLOCKED at " + l.Name
		}
	}
	for _, l := range r.Layers {
		if l.Status == LayerWarn {
			return "REACHABLE with caveats (" + l.Name + ")"
		}
	}
	return "REACHABLE"
}

// ExplainPath resolves two references against the snapshot and walks the
// connection chain between them. A reference is one of:
//
//	<namespace>/<pod>                          exact pod
//	<namespace>/<workload>                     all pods of a Deployment/StatefulSet/...
//	<namespace>/<service>[:<port>]             pods behind a Service, via its port mapping
//	<service>.<namespace>.svc[.cluster.local][:<port>]
//	<namespace>:<key>=<value>                  label selector within a namespace
//	<name>[:<port>]                            any of the above in defaultNS
//	<host>[:<port>] | <ip> | <cidr> | internet  a destination outside the cluster
//
// The first matching interpretation wins (pod, Service, workload, name
// prefix). A two-label name such as example.com is read as <service>.<namespace>
// when that namespace exists and as an external host otherwise. A port given
// as --port must agree with a :port suffix.
func ExplainPath(snap *Snapshot, defaultNS, srcRef, dstRef, port string) (*PathResult, error) {
	src, err := parseRef(srcRef, defaultNS)
	if err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}
	if src.port != "" {
		return nil, fmt.Errorf("source %q: the port belongs on the destination", srcRef)
	}
	dst, err := parseRef(dstRef, defaultNS)
	if err != nil {
		return nil, fmt.Errorf("destination: %w", err)
	}
	if port != "" {
		if dst.port != "" && dst.port != port {
			return nil, fmt.Errorf("--port %s conflicts with destination port %s", port, dst.port)
		}
		dst.port = port
	}

	srcPods, srcSvc, err := resolveRef(snap, src)
	if err != nil {
		return nil, fmt.Errorf("source %q: %w", srcRef, err)
	}
	if srcSvc != nil {
		if srcPods = servicePods(snap, srcSvc); len(srcPods) == 0 {
			return nil, fmt.Errorf("source %q: Service selects no pods", srcRef)
		}
	}

	res := &PathResult{SrcRef: srcRef, DstRef: dstRef, Port: dst.port, SrcPods: podNames(srcPods)}
	if len(snap.Unevaluated) > 0 {
		res.Layers = append(res.Layers, Layer{Name: "Other policies", Status: LayerWarn,
			Summary: "present but not evaluated, so this verdict may be wrong: " + strings.Join(snap.Unevaluated, ", ")})
	}
	ctx := newEvalContext(snap)

	// "name.ns" without a .svc suffix is a Service only if that namespace
	// exists; otherwise it is an external host such as example.com.
	if dst.dns && !dst.cluster && dst.external == nil && !namespaceKnown(snap, dst.ns) {
		dst.external = &externalTarget{raw: dst.name + "." + dst.ns, host: normalizeFQDN(dst.name + "." + dst.ns)}
	}
	if dst.external != nil {
		res.External = dst.external.raw
		if dst.port != "" {
			n, err := strconv.Atoi(dst.port)
			if err != nil {
				return nil, fmt.Errorf("destination %q: the port of an external destination must be a number", dstRef)
			}
			res.TargetPort = int32(n)
		}
		res.Layers = externalLayers(ctx, snap, srcPods, *dst.external, res.TargetPort)
		return res, nil
	}

	dstPods, dstSvc, err := resolveRef(snap, dst)
	switch {
	case dstSvc != nil:
		dstPods = res.walkService(ctx, snap, srcPods, dstSvc)
	case err != nil:
		res.Layers = append(res.Layers, Layer{Name: "DNS", Status: LayerFail, Summary: err.Error(), Fix: suggestNames(snap, dst)})
	default:
		res.TargetPort, err = podPort(dstPods, dst.port)
		if err != nil {
			return nil, fmt.Errorf("destination %q: %w", dstRef, err)
		}
	}
	if len(dstPods) == 0 {
		res.Layers = append(res.Layers,
			Layer{Name: "NetworkPolicy", Status: LayerSkip, Summary: "no destination pods to evaluate"},
			Layer{Name: "Mesh", Status: LayerSkip, Summary: "no destination pods to evaluate"})
		return res, nil
	}

	res.DstPods = podNames(dstPods)
	res.Cell, res.PerPair = evaluatePods(ctx, srcPods, dstPods, res.TargetPort)
	res.Cell, res.PerPair = restrictProtocol(res.Cell, res.PerPair, res.TargetPort, res.Protocol)
	res.Layers = append(res.Layers, policyLayer(res.Cell, res.suggestRule()), meshLayer(snap, srcPods, dstPods, res.TargetPort))
	return res, nil
}

// walkService appends the DNS egress, DNS, Service and Port layers for a
// Service destination and returns the pods traffic would reach: the Ready
// ones, or every matched pod when none is Ready so the policy verdict is
// still shown.
func (r *PathResult) walkService(ctx evalContext, snap *Snapshot, srcPods []corev1.Pod, svc *corev1.Service) []corev1.Pod {
	r.Service = &ServiceHop{
		Namespace: svc.Namespace, Name: svc.Name, Type: string(svc.Spec.Type),
		ClusterIP: svc.Spec.ClusterIP, Selector: svc.Spec.Selector,
	}
	r.Layers = append(r.Layers, dnsEgressLayer(ctx, snap, srcPods), dnsLayer(svc))

	// Service: selector → pods → Ready (what the endpoints controller publishes).
	if len(svc.Spec.Selector) == 0 {
		r.Layers = append(r.Layers, Layer{Name: "Service", Status: LayerWarn,
			Summary: "Service has no selector; its endpoints are managed outside Kubernetes (ExternalName or manual EndpointSlices) and cannot be followed"},
			Layer{Name: "Port", Status: LayerSkip, Summary: "no backing pods"})
		return nil
	}
	matched := servicePods(snap, svc)
	r.Service.Matched = len(matched)
	selText := labels.SelectorFromSet(svc.Spec.Selector).String()
	if len(matched) == 0 {
		r.Layers = append(r.Layers, Layer{Name: "Service", Status: LayerFail,
			Summary: fmt.Sprintf("selector %s matches no pods in namespace %q", selText, svc.Namespace),
			Fix:     suggestLabels(snap, svc)},
			Layer{Name: "Port", Status: LayerSkip, Summary: "no backing pods"})
		return nil
	}

	var ready, notReady []corev1.Pod
	for _, p := range matched {
		if podReady(p) {
			ready = append(ready, p)
		} else {
			notReady = append(notReady, p)
		}
	}
	r.Service.Ready = len(ready)
	l := Layer{Name: "Service", Status: LayerPass,
		Summary: fmt.Sprintf("selector %s matches %d pod(s), %d ready", selText, len(matched), len(ready))}
	for _, p := range notReady {
		l.Detail = append(l.Detail, fmt.Sprintf("%s  %s", p.Name, podState(p)))
	}
	if len(ready) == 0 {
		switch {
		case svc.Spec.PublishNotReadyAddresses:
			l.Status = LayerWarn
			l.Summary += " (publishNotReadyAddresses: unready pods are still endpoints)"
		default:
			l.Status = LayerFail
			l.Summary += " — the Service has no endpoints"
			l.Fix = fmt.Sprintf("the pods are not Ready, so nothing answers behind the Service: kubectl -n %s describe pod %s",
				svc.Namespace, matched[0].Name)
		}
	}
	r.Layers = append(r.Layers, l)

	dstPods := ready
	if len(dstPods) == 0 {
		dstPods = matched
	}
	portLayer, target, proto := resolveServicePort(svc, dstPods, r.Port)
	r.Layers = append(r.Layers, portLayer)
	r.TargetPort, r.Protocol = target, proto
	return dstPods
}

// dnsEgressLayer checks the step every Service connection starts with: can
// the source reach the cluster DNS pods on port 53? A deny-all egress policy
// that forgot DNS is the most common reason "A can't talk to B".
func dnsEgressLayer(ctx evalContext, snap *Snapshot, srcPods []corev1.Pod) Layer {
	dns := clusterDNSPods(snap)
	if len(dns) == 0 {
		return Layer{Name: "DNS egress", Status: LayerSkip, Summary: "cluster DNS pods not found (kube-system, k8s-app=kube-dns)"}
	}
	cell, _ := evaluatePods(ctx, srcPods, dns, 53)
	l := Layer{Name: "DNS egress"}
	switch {
	case cell.Unknown, cell.Partial:
		l.Status = LayerWarn
		l.Summary = fmt.Sprintf("%s to kube-system/kube-dns:53 — %s", cell.Verdict(), cell.Reason)
	case !cell.Allowed:
		l.Status = LayerFail
		l.Summary = "source cannot reach kube-system/kube-dns:53 — " + cell.Reason
		l.Fix = "name resolution fails before any connection is attempted: add an egress rule to the source's\n" +
			"  policy allowing UDP and TCP 53 to namespace kube-system, pods k8s-app=kube-dns"
	default:
		l.Status = LayerPass
		l.Summary = "source may reach kube-system/kube-dns:53 — " + cell.Reason
	}
	return l
}

func clusterDNSPods(snap *Snapshot) []corev1.Pod {
	sel := map[string]string{"k8s-app": "kube-dns"}
	if svc := findService(snap, "kube-system", "kube-dns"); svc != nil && len(svc.Spec.Selector) > 0 {
		sel = svc.Spec.Selector
	}
	return podsMatching(podsInNamespace(snap.Pods, "kube-system"), sel)
}

func dnsLayer(svc *corev1.Service) Layer {
	name := svc.Name + "." + svc.Namespace + ".svc"
	switch {
	case svc.Spec.Type == corev1.ServiceTypeExternalName:
		return Layer{Name: "DNS", Status: LayerWarn,
			Summary: fmt.Sprintf("%s is a CNAME to %s (ExternalName); the destination is outside the cluster", name, svc.Spec.ExternalName)}
	case svc.Spec.ClusterIP == corev1.ClusterIPNone:
		return Layer{Name: "DNS", Status: LayerPass,
			Summary: fmt.Sprintf("%s → Service %s/%s (headless: resolves to the ready pod IPs)", name, svc.Namespace, svc.Name)}
	case svc.Spec.ClusterIP == "": // a manifest read offline has no IP yet
		return Layer{Name: "DNS", Status: LayerPass,
			Summary: fmt.Sprintf("%s → Service %s/%s (ClusterIP assigned at apply)", name, svc.Namespace, svc.Name)}
	default:
		return Layer{Name: "DNS", Status: LayerPass,
			Summary: fmt.Sprintf("%s → Service %s/%s (ClusterIP %s)", name, svc.Namespace, svc.Name, svc.Spec.ClusterIP)}
	}
}

// resolveServicePort maps the asked Service port (or every port when none
// was asked) to the pod port, checking named targetPorts against the pods'
// declared container ports. Returns the pod port to evaluate policy at, or
// 0 when it is not a single number.
func resolveServicePort(svc *corev1.Service, pods []corev1.Pod, want string) (Layer, int32, string) {
	exposed := make([]string, 0, len(svc.Spec.Ports))
	for _, sp := range svc.Spec.Ports {
		exposed = append(exposed, servicePortText(sp))
	}
	chosen := svc.Spec.Ports
	if want != "" {
		chosen = nil
		for _, sp := range svc.Spec.Ports {
			if sp.Name == want || strconv.Itoa(int(sp.Port)) == want {
				chosen = append(chosen, sp)
			}
		}
		if len(chosen) == 0 {
			return Layer{Name: "Port", Status: LayerFail,
				Summary: fmt.Sprintf("port %s is not exposed by Service %s/%s (exposes %s)", want, svc.Namespace, svc.Name, strings.Join(exposed, ", ")),
				Fix:     "connect to one of the exposed ports, or add port " + want + " to the Service",
			}, 0, ""
		}
	}
	if len(chosen) == 0 {
		return Layer{Name: "Port", Status: LayerWarn, Summary: "Service exposes no ports"}, 0, ""
	}

	l := Layer{Name: "Port", Status: LayerPass}
	lines := []string{}
	targets := map[int32]bool{}
	declared := declaredPorts(pods)
	for _, sp := range chosen {
		tp := sp.TargetPort
		if tp.Type == intstr.Int && tp.IntVal == 0 {
			tp = intstr.FromInt32(sp.Port) // Kubernetes defaults targetPort to port
		}
		line := servicePortText(sp)
		if tp.Type == intstr.String {
			nums := map[int32]int{}
			missing := []string{}
			for _, p := range pods {
				if n := containerPortByName(p, tp.StrVal); n != 0 {
					nums[n]++
				} else {
					missing = append(missing, p.Name)
				}
			}
			switch {
			case len(nums) == 0:
				l.Status = LayerFail
				line += fmt.Sprintf(": no container port named %q on any of the %d pod(s), so the Service has no endpoint for it", tp.StrVal, len(pods))
				l.Fix = fmt.Sprintf("name a container port %q in the pod spec, or point targetPort at a number; the pods declare %s",
					tp.StrVal, declaredText(declared))
			case len(missing) > 0:
				if l.Status != LayerFail {
					l.Status = LayerWarn
				}
				line += fmt.Sprintf(" = %s, but %d pod(s) lack a port named %q: %s", portNums(nums), len(missing), tp.StrVal, strings.Join(missing, ", "))
			default:
				line += " = " + portNums(nums)
			}
			for n := range nums {
				targets[n] = true
			}
		} else {
			targets[tp.IntVal] = true
			if len(declared) > 0 && !declared[tp.IntVal] {
				if l.Status != LayerFail {
					l.Status = LayerWarn
				}
				line += fmt.Sprintf(": no container declares port %d (declared: %s)", tp.IntVal, declaredText(declared))
				if l.Fix == "" {
					l.Fix = fmt.Sprintf("check that the app really listens on %d; a targetPort that does not match the container's\n  port is a common typo", tp.IntVal)
				}
			}
		}
		lines = append(lines, line)
	}
	l.Summary, l.Detail = lines[0], lines[1:]
	if len(chosen) == 1 && len(targets) == 1 {
		proto := string(chosen[0].Protocol)
		if proto == "" {
			proto = "TCP"
		}
		for n := range targets {
			return l, n, proto
		}
	}
	return l, 0, ""
}

// restrictProtocol turns an ALLOW that opens the port only on other
// protocols into a DENY: a UDP Service is not reachable through a TCP rule.
func restrictProtocol(c Cell, pairs []Pair, port int32, proto string) (Cell, []Pair) {
	if proto == "" || port == 0 {
		return c, pairs
	}
	deny := func(ports []string, reason string) string {
		return fmt.Sprintf("port %d is opened only on %s, the Service port is %s — %s", port, strings.Join(DisplayPorts(ports), ","), proto, reason)
	}
	if c.Allowed && !portsCover(c.Ports, port, proto) {
		c = Cell{Allowed: false, PolicyApplied: true, Reason: deny(c.Ports, c.Reason), DeniedPairs: c.AllowedPairs + c.DeniedPairs}
	}
	for i, p := range pairs {
		if p.Allowed && !portsCover(p.Ports, port, proto) {
			pairs[i] = Pair{Src: p.Src, Dst: p.Dst, Reason: deny(p.Ports, p.Reason)}
		}
	}
	return c, pairs
}

func servicePortText(sp corev1.ServicePort) string {
	proto := string(sp.Protocol)
	if proto == "" {
		proto = "TCP"
	}
	s := fmt.Sprintf("%d/%s", sp.Port, proto)
	if sp.Name != "" {
		s += " (" + sp.Name + ")"
	}
	tp := sp.TargetPort.String()
	if tp == "0" {
		tp = strconv.Itoa(int(sp.Port))
	}
	return s + " → targetPort " + tp
}

func declaredPorts(pods []corev1.Pod) map[int32]bool {
	out := map[int32]bool{}
	for _, p := range pods {
		for _, c := range append(p.Spec.InitContainers, p.Spec.Containers...) {
			for _, cp := range c.Ports {
				out[cp.ContainerPort] = true
			}
		}
	}
	return out
}

func declaredText(declared map[int32]bool) string {
	if len(declared) == 0 {
		return "no container ports"
	}
	return "container ports " + portNums(declared)
}

func portNums[V any](m map[int32]V) string {
	nums := make([]int, 0, len(m))
	for n := range m {
		nums = append(nums, int(n))
	}
	sort.Ints(nums)
	parts := make([]string, len(nums))
	for i, n := range nums {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ",")
}

// podPort turns the port asked on a pod destination into a number, resolving
// a name against the pods' container ports.
func podPort(pods []corev1.Pod, want string) (int32, error) {
	if want == "" {
		return 0, nil
	}
	if n, err := strconv.Atoi(want); err == nil {
		return int32(n), nil
	}
	for _, p := range pods {
		if n := containerPortByName(p, want); n != 0 {
			return n, nil
		}
	}
	return 0, fmt.Errorf("no container port named %q on the destination pods", want)
}

func policyLayer(c Cell, fix string) Layer {
	l := Layer{Name: "NetworkPolicy", Summary: c.Verdict() + " — " + c.Reason, Fix: fix}
	switch {
	case c.IsSelf:
		l.Status, l.Summary = LayerSkip, "source and destination are the same pod"
	case c.Unknown, c.Partial:
		l.Status = LayerWarn
	case !c.Allowed:
		l.Status = LayerFail
	default:
		l.Status = LayerPass
	}
	return l
}

// evaluatePods runs the policy engine over src × dst and returns the
// aggregated cell plus every pair, in the same way the matrix does.
func evaluatePods(ctx evalContext, src, dst []corev1.Pod, port int32) (Cell, []Pair) {
	cell := evaluateAxisPair(ctx, Axis{Pods: ptrs(src)}, Axis{Pods: ptrs(dst)}, port)
	pairs := []Pair{}
	for _, sp := range src {
		for _, dp := range dst {
			if sp.Namespace == dp.Namespace && sp.Name == dp.Name {
				continue
			}
			c := decide(ctx, sp, dp, port)
			pairs = append(pairs, Pair{
				Src: sp.Namespace + "/" + sp.Name, Dst: dp.Namespace + "/" + dp.Name,
				Allowed: c.Allowed, Unknown: c.Unknown, Ports: c.Ports, Reason: c.Reason,
			})
		}
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i].Src != pairs[j].Src {
			return pairs[i].Src < pairs[j].Src
		}
		return pairs[i].Dst < pairs[j].Dst
	})
	return cell, pairs
}

func ptrs(pods []corev1.Pod) []*corev1.Pod {
	out := make([]*corev1.Pod, len(pods))
	for i := range pods {
		out[i] = &pods[i]
	}
	return out
}

// ref is a parsed user reference.
type ref struct {
	ns, name string
	selector string          // ns:<selector> form
	dns      bool            // given as <svc>.<ns>[.svc...]
	cluster  bool            // the DNS form carried the .svc suffix
	external *externalTarget // outside the cluster
	port     string          // :<port> suffix — number or Service port name
}

// parseRef splits a reference into namespace, name/selector and port. A
// trailing :<token> is a port when it is numeric, or a name when the rest is
// clearly a qualified reference (contains / . or :) — so "api:8080" is a
// port on "api" but "ns:app" stays a label selector.
func parseRef(raw, defaultNS string) (ref, error) {
	r := ref{}
	s := raw
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		tail, head := s[i+1:], s[:i]
		_, numeric := strconv.Atoi(tail)
		if tail != "" && !strings.ContainsAny(tail, "=/ ") &&
			(numeric == nil || strings.ContainsAny(head, "/.:")) {
			r.port, s = tail, head
		}
	}
	if t, ok := parseExternal(s); ok {
		r.external = &t
		return r, nil
	}
	switch {
	case strings.Contains(s, ":"):
		r.ns, r.selector, _ = strings.Cut(s, ":")
	case strings.Contains(s, "/"):
		r.ns, r.name, _ = strings.Cut(s, "/")
	case strings.Contains(s, "."):
		parts := strings.Split(s, ".")
		r.name, r.ns, r.dns, r.cluster = parts[0], parts[1], true, len(parts) > 2
	default:
		r.ns, r.name = defaultNS, s
	}
	if r.ns == "" || (r.name == "" && r.selector == "") {
		return r, fmt.Errorf("%q: expected <namespace>/<pod|workload|service>[:port], <service>.<namespace>.svc[:port] or <namespace>:<selector>", raw)
	}
	return r, nil
}

// resolveRef turns a reference into a pod set, or the Service it names. The
// first interpretation that matches wins: exact pod, Service, workload, pod
// name prefix.
func resolveRef(snap *Snapshot, r ref) ([]corev1.Pod, *corev1.Service, error) {
	if r.selector != "" {
		pods, err := selectPods(podsInNamespace(snap.Pods, r.ns), r.selector)
		if err != nil {
			return nil, nil, err
		}
		if len(pods) == 0 {
			return nil, nil, fmt.Errorf("label selector %q matched no pods in namespace %q", r.selector, r.ns)
		}
		return pods, nil, nil
	}

	inNS := podsInNamespace(snap.Pods, r.ns)
	if !r.dns {
		for _, p := range inNS {
			if p.Name == r.name {
				return []corev1.Pod{p}, nil, nil
			}
		}
	}
	if svc := findService(snap, r.ns, r.name); svc != nil {
		return nil, svc, nil
	}
	if r.dns {
		return nil, nil, fmt.Errorf("no Service named %q in namespace %q", r.name, r.ns)
	}
	for _, w := range groupPodsByWorkload(inNS, snap.ReplicaSets) {
		if w.Name == r.name || w.Kind+"/"+w.Name == r.name {
			out := make([]corev1.Pod, 0, len(w.Pods))
			for _, pp := range w.Pods {
				out = append(out, *pp)
			}
			return out, nil, nil
		}
	}
	var prefixed []corev1.Pod
	for _, p := range inNS {
		if strings.HasPrefix(p.Name, r.name) {
			prefixed = append(prefixed, p)
		}
	}
	if len(prefixed) > 0 {
		return prefixed, nil, nil
	}
	return nil, nil, fmt.Errorf("no pod, Service or workload named %q in namespace %q", r.name, r.ns)
}

func namespaceKnown(snap *Snapshot, ns string) bool {
	if _, ok := snap.NamespaceLabels[ns]; ok {
		return true
	}
	for _, s := range snap.Services {
		if s.Namespace == ns {
			return true
		}
	}
	return len(podsInNamespace(snap.Pods, ns)) > 0
}

func findService(snap *Snapshot, ns, name string) *corev1.Service {
	for i := range snap.Services {
		if snap.Services[i].Namespace == ns && snap.Services[i].Name == name {
			return &snap.Services[i]
		}
	}
	return nil
}

// servicePods returns the pods a Service's selector matches that can still
// become endpoints (not Succeeded/Failed).
func servicePods(snap *Snapshot, svc *corev1.Service) []corev1.Pod {
	out := []corev1.Pod{}
	for _, p := range podsMatching(podsInNamespace(snap.Pods, svc.Namespace), svc.Spec.Selector) {
		if p.Status.Phase != corev1.PodSucceeded && p.Status.Phase != corev1.PodFailed {
			out = append(out, p)
		}
	}
	return out
}

func podsMatching(pods []corev1.Pod, matchLabels map[string]string) []corev1.Pod {
	sel := labels.SelectorFromSet(matchLabels)
	out := []corev1.Pod{}
	for _, p := range pods {
		if sel.Matches(labels.Set(p.Labels)) {
			out = append(out, p)
		}
	}
	return out
}

func podsInNamespace(pods []corev1.Pod, ns string) []corev1.Pod {
	out := []corev1.Pod{}
	for _, p := range pods {
		if p.Namespace == ns {
			out = append(out, p)
		}
	}
	return out
}

func podNames(pods []corev1.Pod) []string {
	out := make([]string, 0, len(pods))
	for _, p := range pods {
		out = append(out, p.Namespace+"/"+p.Name)
	}
	return out
}

// podReady mirrors the endpoints controller: Running, condition Ready and
// not terminating.
func podReady(p corev1.Pod) bool {
	if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// podState is a short diagnosis for a pod that is not Ready, in the order a
// human would look: terminating, a container that cannot start, a running
// container failing its readiness probe, then the pod conditions.
func podState(p corev1.Pod) string {
	if p.DeletionTimestamp != nil {
		return "Terminating"
	}
	for _, cs := range append(p.Status.InitContainerStatuses, p.Status.ContainerStatuses...) {
		switch {
		case cs.State.Waiting != nil && cs.State.Waiting.Reason != "":
			return fmt.Sprintf("%s (container %s, %d restarts)", cs.State.Waiting.Reason, cs.Name, cs.RestartCount)
		case cs.State.Terminated != nil && cs.State.Terminated.Reason != "":
			return fmt.Sprintf("%s (container %s)", cs.State.Terminated.Reason, cs.Name)
		}
	}
	for _, cs := range p.Status.ContainerStatuses {
		if cs.State.Running != nil && !cs.Ready {
			return fmt.Sprintf("Running, readiness probe failing (container %s)", cs.Name)
		}
	}
	for _, c := range p.Status.Conditions {
		if c.Status != corev1.ConditionTrue && c.Reason != "" {
			return c.Reason
		}
	}
	if p.Status.Phase != "" {
		return string(p.Status.Phase)
	}
	return "NotReady"
}

// suggestNames hints at what an unresolved destination might have meant: the
// same Service name in another namespace (the classic wrong-namespace DNS
// name), or similarly named Services in the asked namespace.
func suggestNames(snap *Snapshot, r ref) string {
	elsewhere := []string{}
	similar := []string{}
	for _, s := range snap.Services {
		switch {
		case s.Name == r.name && s.Namespace != r.ns:
			elsewhere = append(elsewhere, s.Name+"."+s.Namespace+".svc")
		case s.Namespace == r.ns && (strings.Contains(s.Name, r.name) || strings.Contains(r.name, s.Name)):
			similar = append(similar, s.Name)
		}
	}
	sort.Strings(elsewhere)
	sort.Strings(similar)
	switch {
	case len(elsewhere) > 0:
		return fmt.Sprintf("a Service %q exists in another namespace — did you mean %s?", r.name, strings.Join(elsewhere, " or "))
	case len(similar) > 0:
		return fmt.Sprintf("similarly named Services in %q: %s", r.ns, strings.Join(similar, ", "))
	}
	return fmt.Sprintf("list what exists with: kubectl -n %s get svc,pods", r.ns)
}

// suggestLabels shows, for each selector key, the values pods in the
// namespace actually carry — a selector that matches nothing is usually one
// value off.
func suggestLabels(snap *Snapshot, svc *corev1.Service) string {
	keys := make([]string, 0, len(svc.Spec.Selector))
	for k := range svc.Spec.Selector {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := []string{}
	for _, k := range keys {
		values := map[string]int{}
		for _, p := range podsInNamespace(snap.Pods, svc.Namespace) {
			if v, ok := p.Labels[k]; ok {
				values[v]++
			}
		}
		if len(values) == 0 {
			lines = append(lines, fmt.Sprintf("no pod in %q carries label %s", svc.Namespace, k))
			continue
		}
		vs := make([]string, 0, len(values))
		for v, n := range values {
			vs = append(vs, fmt.Sprintf("%s (%d pods)", v, n))
		}
		sort.Strings(vs)
		lines = append(lines, fmt.Sprintf("pods in %q carry %s=%s", svc.Namespace, k, strings.Join(vs, ", ")))
	}
	return "the Service selector matches nothing: " + strings.Join(lines, "; ")
}

// suggestRule is a best-effort hint for opening a denied edge — guidance,
// not a manifest.
func (r *PathResult) suggestRule() string {
	if r.Cell.Allowed && !r.Cell.Partial {
		return ""
	}
	if r.Cell.Unknown {
		return "the source is isolated and only a rule this tool cannot decide could permit this edge:\n" +
			"  an unresolved or wildcard toFQDNs (try --resolve-fqdn), toServices or toRequires/fromRequires.\n" +
			"  Inspect that rule, or verify with Hubble flow logs, before concluding the edge is blocked."
	}
	dstNS := ""
	if len(r.DstPods) > 0 {
		dstNS, _, _ = strings.Cut(r.DstPods[0], "/")
	}
	portLine := "all ports"
	if r.TargetPort != 0 {
		portLine = fmt.Sprintf("port %d", r.TargetPort)
	}
	return fmt.Sprintf("add an egress rule to the source's policy permitting %s to endpoints in namespace %q\n"+
		"  matching the destination pod's labels, and an ingress rule on the destination side if it is isolated",
		portLine, dstNS)
}
