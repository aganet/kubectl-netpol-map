package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/aganet/kubectl-netpol-map/internal/policy"
)

func readyPod(ns, name string, lbl map[string]string, portName string, port int32) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: lbl},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app", Ports: []corev1.ContainerPort{{Name: portName, ContainerPort: port}},
		}}},
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
		},
	}
}

func testHandler(t *testing.T) http.Handler {
	t.Helper()
	snap := &policy.Snapshot{
		Pods: []corev1.Pod{
			readyPod("shop", "frontend-1", map[string]string{"app": "frontend"}, "web", 3000),
			readyPod("payments", "api-1", map[string]string{"app": "api"}, "http", 8000),
		},
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"},
			Spec: corev1.ServiceSpec{
				ClusterIP: "10.96.0.10",
				Selector:  map[string]string{"app": "api"},
				Ports:     []corev1.ServicePort{{Name: "http", Port: 8080, TargetPort: intstr.FromString("http"), Protocol: corev1.ProtocolTCP}},
			},
		}},
	}
	fetches := 0
	h := New(func(context.Context) (*policy.Snapshot, error) {
		fetches++
		if fetches > 1 {
			t.Errorf("snapshot should be cached across requests, fetched %d times", fetches)
		}
		return snap, nil
	}, "test-ctx", "test")
	return h
}

func get(t *testing.T, h http.Handler, url string, into any) int {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, url, nil))
	if into != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), into); err != nil {
			t.Fatalf("%s: bad JSON %v: %s", url, err, rec.Body.String())
		}
	}
	return rec.Code
}

func TestRefsAndPath(t *testing.T) {
	h := testHandler(t)

	var refs struct {
		Context    string `json:"context"`
		Namespaces []struct {
			Name     string `json:"name"`
			Services []struct {
				Name  string `json:"name"`
				Ports []struct {
					Port       int32  `json:"port"`
					TargetPort string `json:"targetPort"`
				} `json:"ports"`
			} `json:"services"`
			Workloads []struct {
				Kind  string  `json:"kind"`
				Name  string  `json:"name"`
				Ports []int32 `json:"ports"`
			} `json:"workloads"`
		} `json:"namespaces"`
	}
	if code := get(t, h, "/api/refs", &refs); code != 200 {
		t.Fatalf("refs: status %d", code)
	}
	if refs.Context != "test-ctx" || len(refs.Namespaces) != 2 {
		t.Fatalf("unexpected refs: %+v", refs)
	}
	pay := refs.Namespaces[0]
	if pay.Name != "payments" || len(pay.Services) != 1 || pay.Services[0].Ports[0].TargetPort != "http" {
		t.Errorf("payments namespace should list Service api with targetPort http: %+v", pay)
	}
	if len(pay.Workloads) != 1 || pay.Workloads[0].Kind != "Pod" || pay.Workloads[0].Ports[0] != 8000 {
		t.Errorf("payments workloads should list the bare pod with port 8000: %+v", pay.Workloads)
	}

	var path struct {
		Verdict string `json:"verdict"`
		Layers  []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"layers"`
	}
	if code := get(t, h, "/api/path?src=shop/Pod/frontend-1&dst=payments/api&port=8080", &path); code != 200 {
		t.Fatalf("path: status %d", code)
	}
	if path.Verdict != "REACHABLE" || len(path.Layers) != 6 {
		t.Errorf("expected REACHABLE with 6 layers, got %+v", path)
	}

	var bad struct {
		Error string `json:"error"`
	}
	if code := get(t, h, "/api/path?src=shop/nope&dst=payments/api", &bad); code != 400 || !strings.Contains(bad.Error, "nope") {
		t.Errorf("expected 400 naming the missing source, got %d %q", code, bad.Error)
	}
}

func TestMatrixAndLint(t *testing.T) {
	h := testHandler(t)

	var m struct {
		Hidden int `json:"hidden"`
		Edges  []struct {
			Status string `json:"status"`
		} `json:"edges"`
	}
	if code := get(t, h, "/api/matrix?from=shop&to=payments", &m); code != 200 {
		t.Fatalf("matrix: status %d", code)
	}
	if m.Hidden != 1 || len(m.Edges) != 0 {
		t.Errorf("no policies: the single edge should be hidden as default-allow, got %+v", m)
	}
	if code := get(t, h, "/api/matrix?from=shop&to=payments&all=1", &m); code != 200 || len(m.Edges) != 1 || m.Edges[0].Status != "allow" {
		t.Errorf("all=1 should list the allow edge, got %d %+v", code, m)
	}

	var findings []any
	if code := get(t, h, "/api/lint", &findings); code != 200 {
		t.Errorf("lint: status %d", code)
	}
	var pol struct {
		Policies []any `json:"policies"`
		Coverage struct {
			Workloads int `json:"workloads"`
		} `json:"coverage"`
	}
	if code := get(t, h, "/api/policies", &pol); code != 200 || len(pol.Policies) != 0 || pol.Coverage.Workloads != 2 {
		t.Errorf("policies: status %d, %+v", code, pol)
	}
	if code := get(t, h, "/", nil); code != 200 {
		t.Errorf("index: status %d", code)
	}
	if code := get(t, h, "/nope", nil); code != 404 {
		t.Errorf("unknown path should 404, got %d", code)
	}
}

func TestLocalOnlyRejectsForeignHost(t *testing.T) {
	h := LocalOnly(testHandler(t))
	for host, want := range map[string]int{"127.0.0.1:8471": 200, "localhost:8471": 200, "[::1]:8471": 200, "evil.example:8471": 403, "10.0.0.5": 403} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Host %q: got %d, want %d", host, rec.Code, want)
		}
	}
}
