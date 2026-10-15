// Package ui serves a local web page where source and destination are picked
// from dropdowns filled with live cluster data, backed by the same engine as
// the CLI. Everything runs on the user's machine; nothing is deployed.
package ui

import (
	"context"
	_ "embed"
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/aganet/kubectl-npmap/internal/lint"
	"github.com/aganet/kubectl-npmap/internal/policy"
	"github.com/aganet/kubectl-npmap/internal/render"
)

//go:embed index.html
var indexHTML []byte

// Snapshots older than this are re-fetched on the next request; the page's
// refresh button forces it.
const snapshotTTL = 30 * time.Second

type server struct {
	fetch   func(context.Context) (*policy.Snapshot, error)
	context string

	mu   sync.Mutex
	snap *policy.Snapshot
	at   time.Time
}

// LocalOnly rejects requests whose Host header is not a loopback name. A
// web page on another site cannot read the UI's responses directly, but DNS
// rebinding would let it reach the server under its own host name; this
// closes that door for the default loopback listen.
func LocalOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		switch host {
		case "localhost", "127.0.0.1", "::1", "[::1]":
			next.ServeHTTP(w, r)
		default:
			http.Error(w, "kubectl-npmap ui only answers to localhost", http.StatusForbidden)
		}
	})
}

// New returns the HTTP handler. fetch produces a cluster-wide snapshot (with
// Mesh populated if available); contextName is shown in the page header.
func New(fetch func(context.Context) (*policy.Snapshot, error), contextName string) http.Handler {
	s := &server{fetch: fetch, context: contextName}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})
	mux.HandleFunc("GET /api/refs", s.refs)
	mux.HandleFunc("GET /api/path", s.path)
	mux.HandleFunc("GET /api/matrix", s.matrix)
	mux.HandleFunc("GET /api/lint", s.lint)
	mux.HandleFunc("GET /api/policies", s.policies)
	return mux
}

// policies explains every policy with its peers resolved to workloads.
func (s *server) policies(w http.ResponseWriter, r *http.Request) {
	snap, err := s.snapshot(r)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	views, cov := policy.Describe(snap)
	writeJSON(w, struct {
		Policies []policy.PolicyView `json:"policies"`
		Coverage policy.Coverage     `json:"coverage"`
	}{views, cov})
}

func (s *server) snapshot(r *http.Request) (*policy.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snap != nil && r.URL.Query().Get("refresh") == "" && time.Since(s.at) < snapshotTTL {
		return s.snap, nil
	}
	snap, err := s.fetch(r.Context())
	if err != nil {
		return nil, err
	}
	s.snap, s.at = snap, time.Now()
	return snap, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

type servicePort struct {
	Name       string `json:"name,omitempty"`
	Port       int32  `json:"port"`
	TargetPort string `json:"targetPort"`
	Protocol   string `json:"protocol"`
}

type serviceRef struct {
	Name      string        `json:"name"`
	Type      string        `json:"type"`
	ClusterIP string        `json:"clusterIP,omitempty"`
	Ports     []servicePort `json:"ports"`
}

type workloadRef struct {
	Kind  string  `json:"kind"`
	Name  string  `json:"name"`
	Pods  int     `json:"pods"`
	Ports []int32 `json:"ports"` // container ports its pods declare
}

type namespaceRef struct {
	Name      string        `json:"name"`
	Workloads []workloadRef `json:"workloads"`
	Services  []serviceRef  `json:"services"`
}

// refs is everything the dropdowns need, grouped by namespace.
func (s *server) refs(w http.ResponseWriter, r *http.Request) {
	snap, err := s.snapshot(r)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	byNS := map[string]*namespaceRef{}
	ns := func(name string) *namespaceRef {
		if n, ok := byNS[name]; ok {
			return n
		}
		n := &namespaceRef{Name: name, Workloads: []workloadRef{}, Services: []serviceRef{}}
		byNS[name] = n
		return n
	}
	for _, wl := range snap.Workloads() {
		ports := map[int32]bool{}
		for _, p := range wl.Pods {
			for _, c := range p.Spec.Containers {
				for _, cp := range c.Ports {
					ports[cp.ContainerPort] = true
				}
			}
		}
		ref := workloadRef{Kind: wl.Kind, Name: wl.Name, Pods: len(wl.Pods), Ports: []int32{}}
		for p := range ports {
			ref.Ports = append(ref.Ports, p)
		}
		sort.Slice(ref.Ports, func(i, j int) bool { return ref.Ports[i] < ref.Ports[j] })
		n := ns(wl.Namespace)
		n.Workloads = append(n.Workloads, ref)
	}
	for _, svc := range snap.Services {
		ref := serviceRef{Name: svc.Name, Type: string(svc.Spec.Type), ClusterIP: svc.Spec.ClusterIP, Ports: []servicePort{}}
		for _, sp := range svc.Spec.Ports {
			tp := sp.TargetPort.String()
			if tp == "0" {
				tp = strconv.Itoa(int(sp.Port))
			}
			ref.Ports = append(ref.Ports, servicePort{Name: sp.Name, Port: sp.Port, TargetPort: tp, Protocol: string(sp.Protocol)})
		}
		n := ns(svc.Namespace)
		n.Services = append(n.Services, ref)
	}
	out := struct {
		Context     string         `json:"context"`
		FetchedAt   time.Time      `json:"fetchedAt"`
		PodCount    int            `json:"podCount"`
		PolicyCount int            `json:"policyCount"`
		MeshFetched bool           `json:"meshFetched"`
		Namespaces  []namespaceRef `json:"namespaces"`
		Externals   []string       `json:"externals"` // FQDNs/CIDRs the policies mention
	}{
		Context: s.context, FetchedAt: s.at, PodCount: len(snap.Pods),
		PolicyCount: len(snap.Policies) + len(snap.CiliumNamespacePolicies) + len(snap.CiliumClusterPolicies),
		MeshFetched: snap.Mesh != nil, Namespaces: []namespaceRef{}, Externals: snap.ExternalTargets(),
	}
	for _, n := range byNS {
		sort.Slice(n.Services, func(i, j int) bool { return n.Services[i].Name < n.Services[j].Name })
		out.Namespaces = append(out.Namespaces, *n)
	}
	sort.Slice(out.Namespaces, func(i, j int) bool { return out.Namespaces[i].Name < out.Namespaces[j].Name })
	writeJSON(w, out)
}

// path traces src → dst exactly like `kubectl npmap path`.
func (s *server) path(w http.ResponseWriter, r *http.Request) {
	snap, err := s.snapshot(r)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	q := r.URL.Query()
	res, err := policy.ExplainPath(snap, "", q.Get("src"), q.Get("dst"), q.Get("port"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	render.PathJSON(w, res)
}

// matrix evaluates workload reachability between two namespaces (either may
// be empty for "any"). Default-allow edges are counted but omitted unless
// all=1, as in the CLI.
func (s *server) matrix(w http.ResponseWriter, r *http.Request) {
	snap, err := s.snapshot(r)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	q := r.URL.Query()
	var port int32
	if p := q.Get("port"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		port = int32(n)
	}
	edges, hidden, err := policy.Edges(snap, q.Get("from"), q.Get("to"), port, q.Get("all") != "")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, struct {
		Hidden int           `json:"hidden"`
		Edges  []policy.Edge `json:"edges"`
	}{hidden, edges})
}

func (s *server) lint(w http.ResponseWriter, r *http.Request) {
	snap, err := s.snapshot(r)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, lint.Run(snap))
}
