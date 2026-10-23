package policy

import (
	"fmt"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// GroupBy controls how rows/columns are formed. "pod" treats each pod as
// its own axis entry (the original behaviour); "workload" collapses pods
// owned by the same controller (Deployment/StatefulSet/DaemonSet/...) into
// a single axis entry whose cell is aggregated across all pod-pairs.
type GroupBy string

const (
	GroupByPod      GroupBy = "pod"
	GroupByWorkload GroupBy = "workload"
)

// Axis is one row or column in the matrix. In pod mode each Axis contains
// a single pod; in workload mode it contains every pod the controller owns.
type Axis struct {
	Namespace string
	Kind      string // "Pod" in pod mode; controller kind ("Deployment", ...) in workload mode
	Name      string
	Pods      []*corev1.Pod
}

// Display returns "namespace/Kind/Name" — fully qualified, axis-aware.
// For backwards-compatible rendering of plain pods, "Pod" prefix is elided.
func (a Axis) Display() string {
	if a.Kind == "Pod" {
		if a.Namespace == "" {
			return a.Name
		}
		return a.Namespace + "/" + a.Name
	}
	return a.Namespace + "/" + a.Kind + "/" + a.Name
}

// Short returns the axis entry without its namespace (used inside the
// per-namespace sub-matrices where namespace is already in the title).
func (a Axis) Short() string {
	if a.Kind == "Pod" {
		return a.Name
	}
	return a.Kind + "/" + a.Name
}

// Cell is one (source, destination) reachability result.
//
// In pod mode AllowedPairs+DeniedPairs is exactly 1 (or 0 for self).
// In workload mode the cell aggregates verdicts across the cartesian
// product of source and destination pods, so the counts can be larger
// and Partial may be true if the verdicts disagree.
type Cell struct {
	IsSelf  bool
	Allowed bool // pure ALLOW: every pair permitted
	Partial bool // mixed: at least one pair allowed AND at least one denied
	// Unknown is true when the verdict could not be fully determined because
	// the decision depended on a rule the engine does not evaluate (Cilium
	// L7/FQDN/entity/CIDR). The reported Allowed/DeniedPairs are the L4-only
	// view; the real answer may differ. An UNKNOWN edge must never be read as
	// a definitive DENY.
	Unknown bool
	// L7Restricted is true for an ALLOW that is permitted at L4 but whose
	// matching rule also carries L7 conditions (HTTP method/path, DNS) that
	// this engine does not evaluate. The connection is allowed, but only some
	// requests over it may be — the ALLOW is narrower than it looks.
	L7Restricted bool
	// PolicyApplied is true when at least one NetworkPolicy or Cilium policy
	// participated in the verdict — either by isolating an endpoint or by
	// explicitly allowing/denying the edge. When false, the verdict is the
	// Kubernetes default ("no policy in scope, traffic flows"), and the cell
	// can be safely elided from cluster-scale views.
	PolicyApplied bool
	Ports         []string
	Reason        string
	AllowedPairs  int
	DeniedPairs   int
}

// Matrix is a grid of source→destination cells plus context for rendering.
type Matrix struct {
	Namespace string
	Mode      GroupBy
	Rows      []Axis
	Cols      []Axis
	Cells     [][]Cell
	Port      int32

	// FromNamespace/ToNamespace, when set, restrict which rows/columns the
	// renderer displays. Evaluation still runs across the full row/col set so
	// counts remain accurate; only the rendered slice is narrowed.
	FromNamespace string
	ToNamespace   string

	PodCount          int
	Policies          []networkingv1.NetworkPolicy
	CiliumPolicies    []unstructured.Unstructured
	CiliumClusterwide []unstructured.Unstructured
	// Unevaluated names policy kinds in the cluster this tool ignores; the
	// verdicts may then be wrong.
	Unevaluated []string

	// ExternalEgress lists allowed egress to destinations that are not
	// in-cluster pods (FQDNs that resolve externally, CIDRs, entities),
	// derived from Cilium egress rules. These have no matrix cell.
	ExternalEgress []ExternalEgress
}

// Evaluator turns a snapshot into a reachability matrix.
type Evaluator interface {
	Evaluate(snap *Snapshot, mode GroupBy, rowSel, colSel string, port int32) (*Matrix, error)
}

func NewBasicEvaluator() Evaluator { return &basicEvaluator{} }

type basicEvaluator struct{}

// evalContext carries everything decide() needs — collected once per Evaluate.
type evalContext struct {
	policies []networkingv1.NetworkPolicy
	cnps     []unstructured.Unstructured
	ccnps    []unstructured.Unstructured
	// resolver + podIPs let an egress toFQDNs rule that resolves to an
	// in-cluster pod IP count as a real match. resolver is never nil here
	// (NopResolver is substituted when the caller leaves Snapshot.Resolver
	// unset), so toFQDNs against external names still falls through to UNKNOWN.
	resolver Resolver
	podIPs   map[string]string // ip -> "ns/name"
	nsLabels map[string]map[string]string
}

func (basicEvaluator) Evaluate(snap *Snapshot, mode GroupBy, rowSel, colSel string, port int32) (*Matrix, error) {
	if mode == "" {
		mode = GroupByPod
	}

	rowPods, err := selectPods(snap.Pods, rowSel)
	if err != nil {
		return nil, fmt.Errorf("--from selector: %w", err)
	}
	colPods, err := selectPods(snap.Pods, colSel)
	if err != nil {
		return nil, fmt.Errorf("--to selector: %w", err)
	}

	rows := buildAxes(rowPods, snap.ReplicaSets, mode)
	cols := buildAxes(colPods, snap.ReplicaSets, mode)

	m := &Matrix{
		Namespace:         snap.Namespace,
		Mode:              mode,
		Rows:              rows,
		Cols:              cols,
		Port:              port,
		PodCount:          len(snap.Pods),
		Policies:          snap.Policies,
		CiliumPolicies:    snap.CiliumNamespacePolicies,
		CiliumClusterwide: snap.CiliumClusterPolicies,
		Unevaluated:       snap.Unevaluated,
	}
	m.Cells = make([][]Cell, len(rows))
	for i := range rows {
		m.Cells[i] = make([]Cell, len(cols))
	}

	ctx := newEvalContext(snap)
	for i, src := range rows {
		for j, dst := range cols {
			m.Cells[i][j] = evaluateAxisPair(ctx, src, dst, port)
		}
	}
	m.ExternalEgress = collectExternalEgress(ctx, rows, ctx.resolver)
	return m, nil
}

func newEvalContext(snap *Snapshot) evalContext {
	resolver := snap.Resolver
	if resolver == nil {
		resolver = NopResolver{}
	}
	refs := make([]podRef, 0, len(snap.Pods))
	for _, p := range snap.Pods {
		refs = append(refs, podRef{ns: p.Namespace, name: p.Name, ip: p.Status.PodIP})
	}
	return evalContext{
		policies: snap.Policies,
		cnps:     enforcedCilium(snap.CiliumNamespacePolicies),
		ccnps:    enforcedCilium(snap.CiliumClusterPolicies),
		resolver: resolver,
		podIPs:   podIPIndex(refs),
		nsLabels: snap.NamespaceLabels,
	}
}

// Verdict is the plain-text verdict of a cell: ALLOW[ :ports][ (L7)], DENY,
// PARTIAL n/m or UNKNOWN.
func (c Cell) Verdict() string {
	switch {
	case c.Unknown:
		return "UNKNOWN"
	case c.Partial:
		return fmt.Sprintf("PARTIAL %d/%d", c.AllowedPairs, c.AllowedPairs+c.DeniedPairs)
	case !c.Allowed:
		return "DENY"
	}
	v := "ALLOW"
	if len(c.Ports) > 0 && !(len(c.Ports) == 1 && c.Ports[0] == "*") {
		v += " :" + strings.Join(DisplayPorts(c.Ports), ",")
	}
	if c.L7Restricted {
		v += " (L7)"
	}
	return v
}

// buildAxes turns a pod set into axis entries according to the selected mode.
func buildAxes(pods []corev1.Pod, replicaSets []appsv1.ReplicaSet, mode GroupBy) []Axis {
	if mode == GroupByWorkload {
		ws := groupPodsByWorkload(pods, replicaSets)
		out := make([]Axis, 0, len(ws))
		for _, w := range ws {
			out = append(out, Axis{
				Namespace: w.Namespace,
				Kind:      w.Kind,
				Name:      w.Name,
				Pods:      w.Pods,
			})
		}
		return out
	}

	// pod mode
	out := make([]Axis, 0, len(pods))
	for i := range pods {
		p := &pods[i]
		out = append(out, Axis{
			Namespace: p.Namespace,
			Kind:      "Pod",
			Name:      p.Name,
			Pods:      []*corev1.Pod{p},
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// evaluateAxisPair aggregates the per-pod verdicts across the cartesian
// product of source-axis pods and destination-axis pods.
func evaluateAxisPair(ctx evalContext, src, dst Axis, port int32) Cell {
	allowed := 0
	denied := 0
	unknown := 0
	allowReasons := map[string]int{}
	denyReasons := map[string]int{}
	unknownReasons := map[string]int{}
	portSet := map[string]bool{}
	policyApplied := false
	l7Restricted := false

	for _, sp := range src.Pods {
		for _, dp := range dst.Pods {
			if sp.Namespace == dp.Namespace && sp.Name == dp.Name {
				continue // identical pod — not an edge
			}
			c := decide(ctx, *sp, *dp, port)
			if c.PolicyApplied {
				policyApplied = true
			}
			switch {
			case c.Unknown:
				unknown++
				unknownReasons[c.Reason]++
			case c.Allowed:
				allowed++
				allowReasons[c.Reason]++
				if c.L7Restricted {
					l7Restricted = true
				}
				for _, p := range c.Ports {
					portSet[p] = true
				}
			default:
				denied++
				denyReasons[c.Reason]++
			}
		}
	}

	if allowed == 0 && denied == 0 && unknown == 0 {
		// happens only when both axes are the same single-pod axis
		return Cell{IsSelf: true}
	}

	ports := make([]string, 0, len(portSet))
	for p := range portSet {
		ports = append(ports, p)
	}
	sort.Strings(ports)

	switch {
	case allowed > 0 && denied == 0 && unknown == 0:
		return Cell{
			Allowed:       true,
			L7Restricted:  l7Restricted,
			PolicyApplied: policyApplied,
			Ports:         ports,
			Reason:        summarise(allowReasons, allowed),
			AllowedPairs:  allowed,
			DeniedPairs:   0,
		}
	case allowed == 0 && denied > 0 && unknown == 0:
		return Cell{
			Allowed:       false,
			PolicyApplied: policyApplied,
			Reason:        summarise(denyReasons, denied),
			AllowedPairs:  0,
			DeniedPairs:   denied,
		}
	case allowed == 0 && denied == 0 && unknown > 0:
		// Every pair is undecidable for the same kind of reason.
		return Cell{
			Unknown:       true,
			PolicyApplied: policyApplied,
			Reason:        summarise(unknownReasons, unknown),
			AllowedPairs:  0,
			DeniedPairs:   0,
		}
	default:
		// mixed: a combination of allow / deny / unknown pairs.
		merged := mergeReasons(allowReasons, denyReasons)
		if unknown > 0 {
			merged += fmt.Sprintf("; unknown: %s", topReason(unknownReasons))
		}
		return Cell{
			Partial:       true,
			PolicyApplied: policyApplied,
			Ports:         ports,
			Reason:        merged,
			AllowedPairs:  allowed,
			// Undecidable pairs count against "fully allowed" for display.
			DeniedPairs: denied + unknown,
		}
	}
}

// summarise returns the single most common reason annotated with its share.
func summarise(reasons map[string]int, total int) string {
	if len(reasons) == 0 {
		return ""
	}
	if len(reasons) == 1 && total == 1 {
		for r := range reasons {
			return r
		}
	}
	type kv struct {
		reason string
		n      int
	}
	pairs := make([]kv, 0, len(reasons))
	for r, n := range reasons {
		pairs = append(pairs, kv{r, n})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].n > pairs[j].n })
	top := pairs[0]
	if len(pairs) == 1 {
		return fmt.Sprintf("%s (all %d pairs)", top.reason, total)
	}
	return fmt.Sprintf("%s (%d/%d pairs); also %d other reason(s)", top.reason, top.n, total, len(pairs)-1)
}

func mergeReasons(allow, deny map[string]int) string {
	parts := []string{}
	if len(allow) > 0 {
		parts = append(parts, "allow: "+topReason(allow))
	}
	if len(deny) > 0 {
		parts = append(parts, "deny: "+topReason(deny))
	}
	return strings.Join(parts, "; ")
}

func topReason(m map[string]int) string {
	var best string
	bestN := -1
	for r, n := range m {
		if n > bestN {
			best, bestN = r, n
		}
	}
	return best
}

func selectPods(pods []corev1.Pod, selector string) ([]corev1.Pod, error) {
	if strings.TrimSpace(selector) == "" {
		out := make([]corev1.Pod, len(pods))
		copy(out, pods)
		return out, nil
	}
	sel, err := labels.Parse(selector)
	if err != nil {
		return nil, err
	}
	out := []corev1.Pod{}
	for _, p := range pods {
		if sel.Matches(labels.Set(p.Labels)) {
			out = append(out, p)
		}
	}
	return out, nil
}

// side is what the policies selecting one end of a pair say about one
// direction: whether they isolate it and which rules open it.
type side struct {
	isolated   bool
	isolatedBy []string
	ports      []string // opened by matching rules; empty when none matched
	allowedBy  []string
	unresolved []string // named ports the destination does not declare
	skipped    int      // Cilium rules that could not be decided
	l7         bool     // an opening Cilium rule carries L7 conditions
}

// union merges what another policy kind says about the same direction.
// Cilium enforces standard and Cilium policies from one pool, so a
// direction is isolated when any selecting policy isolates it and open
// when any rule of either kind allows the traffic.
func (s side) union(o side) side {
	return side{
		isolated: s.isolated || o.isolated, isolatedBy: append(s.isolatedBy, o.isolatedBy...),
		ports: append(s.ports, o.ports...), allowedBy: append(s.allowedBy, o.allowedBy...),
		unresolved: append(s.unresolved, o.unresolved...), skipped: s.skipped + o.skipped, l7: s.l7 || o.l7,
	}
}

// open reports what the side lets through and why. ports is nil when the
// direction is closed; unknown marks a closed verdict that an undecided
// Cilium rule might still open.
func (s side) open(dir string) (ports []string, reason string, unknown bool) {
	if !s.isolated {
		return []string{"*"}, "no policy restricts " + dir, false
	}
	if len(s.ports) == 0 {
		who, what := "src", "no rule matches dst"
		if dir == "ingress" {
			who, what = "dst", "no rule allows src"
		}
		reason = fmt.Sprintf("%s isolated for %s by %s; %s%s", who, dir, strings.Join(unique(s.isolatedBy), ", "), what, unresolvedNote(s.unresolved))
		if s.skipped > 0 {
			return nil, reason + fmt.Sprintf(", but %d Cilium rule(s) could not be decided", s.skipped), true
		}
		return nil, reason, false
	}
	reason = dir + " allowed by " + strings.Join(unique(s.allowedBy), ", ")
	if s.skipped > 0 {
		reason += fmt.Sprintf(" (%d other Cilium rule(s) could not be decided)", s.skipped)
	}
	return unique(s.ports), reason, false
}

func decide(ctx evalContext, src, dst corev1.Pod, port int32) Cell {
	eg, in := checkEgress(ctx, src, dst, port), checkIngress(ctx, src, dst, port)
	if len(ctx.cnps)+len(ctx.ccnps) > 0 {
		cv := evaluateCilium(ctx, src, dst, port)
		if cv.Denied {
			return Cell{PolicyApplied: true, Reason: cv.Reason}
		}
		eg, in = eg.union(cv.Egress), in.union(cv.Ingress)
	}
	egPorts, egReason, egUnknown := eg.open("egress")
	if egPorts == nil {
		return Cell{Unknown: egUnknown, PolicyApplied: true, Reason: egReason}
	}
	inPorts, inReason, inUnknown := in.open("ingress")
	if inPorts == nil {
		return Cell{Unknown: inUnknown, PolicyApplied: true, Reason: inReason}
	}
	ports := intersectPorts(egPorts, inPorts)
	if len(ports) == 0 {
		return Cell{PolicyApplied: true, Reason: fmt.Sprintf(
			"no port in common: egress allows %s, ingress allows %s", strings.Join(DisplayPorts(egPorts), ","), strings.Join(DisplayPorts(inPorts), ","))}
	}
	return Cell{Allowed: true, L7Restricted: eg.l7 || in.l7, PolicyApplied: eg.isolated || in.isolated, Ports: ports, Reason: inReason + "; " + egReason}
}

// checkEgress is what the standard NetworkPolicies selecting src say about
// its egress to dst.
func checkEgress(ctx evalContext, src, dst corev1.Pod, port int32) side {
	var s side
	for _, p := range ctx.policies {
		if p.Namespace != src.Namespace || !selects(p.Spec.PodSelector, src) || !hasType(p, networkingv1.PolicyTypeEgress) {
			continue
		}
		s.isolated = true
		s.isolatedBy = append(s.isolatedBy, p.Namespace+"/"+p.Name)
		for _, rule := range p.Spec.Egress {
			if !peersMatch(ctx, rule.To, dst, p.Namespace) {
				continue
			}
			ports, missing := rulePorts(rule.Ports, port, dst)
			s.unresolved = append(s.unresolved, missing...)
			if len(ports) > 0 {
				s.ports = append(s.ports, ports...)
				s.allowedBy = append(s.allowedBy, p.Namespace+"/"+p.Name)
			}
		}
	}
	return s
}

// checkIngress is what the standard NetworkPolicies selecting dst say about
// its ingress from src.
func checkIngress(ctx evalContext, src, dst corev1.Pod, port int32) side {
	var s side
	for _, p := range ctx.policies {
		if p.Namespace != dst.Namespace || !selects(p.Spec.PodSelector, dst) || !hasType(p, networkingv1.PolicyTypeIngress) {
			continue
		}
		s.isolated = true
		s.isolatedBy = append(s.isolatedBy, p.Namespace+"/"+p.Name)
		for _, rule := range p.Spec.Ingress {
			if !peersMatch(ctx, rule.From, src, p.Namespace) {
				continue
			}
			ports, missing := rulePorts(rule.Ports, port, dst)
			s.unresolved = append(s.unresolved, missing...)
			if len(ports) > 0 {
				s.ports = append(s.ports, ports...)
				s.allowedBy = append(s.allowedBy, p.Namespace+"/"+p.Name)
			}
		}
	}
	return s
}

func policyNames(ps []networkingv1.NetworkPolicy) string {
	names := make([]string, 0, len(ps))
	for _, p := range ps {
		names = append(names, fmt.Sprintf("%s/%s", p.Namespace, p.Name))
	}
	return strings.Join(names, ", ")
}

func unique(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range in {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func hasType(p networkingv1.NetworkPolicy, t networkingv1.PolicyType) bool {
	if len(p.Spec.PolicyTypes) == 0 {
		if t == networkingv1.PolicyTypeIngress {
			return true
		}
		return len(p.Spec.Egress) > 0
	}
	for _, pt := range p.Spec.PolicyTypes {
		if pt == t {
			return true
		}
	}
	return false
}

func selects(sel metav1.LabelSelector, pod corev1.Pod) bool {
	s, err := metav1.LabelSelectorAsSelector(&sel)
	if err != nil {
		return false
	}
	return s.Matches(labels.Set(pod.Labels))
}

// matchesNamespace reports whether targetNS satisfies the peer's
// namespaceSelector. An empty selector ({}) matches every namespace. A
// non-empty selector is matched against the target namespace's real labels
// (from ctx.nsLabels); if those labels are unavailable (RBAC, not fetched)
// it conservatively falls back to "same namespace as the policy".
func matchesNamespace(ctx evalContext, sel *metav1.LabelSelector, targetNS, policyNS string) bool {
	if sel == nil {
		return false
	}
	if len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0 {
		return true
	}
	nsl, ok := ctx.nsLabels[targetNS]
	if !ok {
		return targetNS == policyNS
	}
	s, err := metav1.LabelSelectorAsSelector(sel)
	if err != nil {
		return false
	}
	return s.Matches(labels.Set(nsl))
}

func peersMatch(ctx evalContext, peers []networkingv1.NetworkPolicyPeer, pod corev1.Pod, policyNS string) bool {
	if len(peers) == 0 {
		return true
	}
	for _, peer := range peers {
		if peer.IPBlock != nil {
			continue
		}
		nsMatch := false
		switch {
		case peer.NamespaceSelector == nil && peer.PodSelector == nil:
			continue
		case peer.NamespaceSelector == nil:
			nsMatch = pod.Namespace == policyNS
		default:
			nsMatch = matchesNamespace(ctx, peer.NamespaceSelector, pod.Namespace, policyNS)
		}
		if !nsMatch {
			continue
		}

		podMatch := true
		if peer.PodSelector != nil {
			s, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
			if err != nil {
				podMatch = false
			} else {
				podMatch = s.Matches(labels.Set(pod.Labels))
			}
		}
		if podMatch {
			return true
		}
	}
	return false
}

// rulePorts returns the ports a rule permits, as strings, honouring the port
// filter. A named port is resolved against the destination pod's container
// ports (that is what the spec matches it on, for ingress and egress alike);
// a name no container declares is kept verbatim so it stays visible.
// rulePorts resolves a rule's ports against the destination pod and keeps
// the entries that open the filtered port (0 = any). Protocol defaults to
// TCP and endPort gives a range, as in the API. A named port no container
// of dst declares matches no traffic, as in Kubernetes; its name is returned
// in unresolved so the verdict can say why the rule did not apply.
func rulePorts(ports []networkingv1.NetworkPolicyPort, filter int32, dst corev1.Pod) (out, unresolved []string) {
	if len(ports) == 0 {
		return []string{"*"}, nil
	}
	out = []string{}
	for _, p := range ports {
		spec := portSpec{proto: "TCP"}
		if p.Protocol != nil {
			spec.proto = string(*p.Protocol)
		}
		if p.Port != nil {
			spec.lo = int32(p.Port.IntValue())
			if p.Port.Type == intstr.String {
				spec.lo = containerPortByName(dst, p.Port.StrVal)
				if spec.lo == 0 {
					unresolved = append(unresolved, p.Port.StrVal)
					continue
				}
			}
			spec.hi = spec.lo
			if p.EndPort != nil {
				spec.hi = *p.EndPort
			}
		}
		if filter != 0 && !spec.covers(filter, "") {
			continue
		}
		out = append(out, spec.String())
	}
	return out, unresolved
}

// unresolvedNote explains a rule that matched the peer but none of its ports.
func unresolvedNote(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return fmt.Sprintf(" (named port %s not declared by the destination pod)", strings.Join(unique(names), ", "))
}

// containerPortByName returns the numeric port a pod's containers declare
// under the given name, or 0 if none does.
func containerPortByName(pod corev1.Pod, name string) int32 {
	for _, c := range append(pod.Spec.InitContainers, pod.Spec.Containers...) {
		for _, cp := range c.Ports {
			if cp.Name == name {
				return cp.ContainerPort
			}
		}
	}
	return 0
}
