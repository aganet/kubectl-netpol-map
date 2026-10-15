package render

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aganet/kubectl-netpol-map/internal/policy"
)

func samplePath() *policy.PathResult {
	return &policy.PathResult{
		SrcRef: "shop/frontend", DstRef: "payments/api:8080",
		SrcPods: []string{"shop/frontend-1"}, DstPods: []string{"payments/api-1"},
		Service:    &policy.ServiceHop{Namespace: "payments", Name: "api", Matched: 2, Ready: 1},
		Port:       "8080",
		TargetPort: 8000,
		Layers: []policy.Layer{
			{Name: "DNS egress", Status: policy.LayerPass, Summary: "source may reach kube-system/kube-dns:53"},
			{Name: "Service", Status: policy.LayerPass, Summary: "selector app=api matches 2 pod(s), 1 ready", Detail: []string{"api-2  CrashLoopBackOff"}},
			{Name: "Port", Status: policy.LayerFail, Summary: "8080/TCP → targetPort http: no container port named \"http\"", Fix: "name a container port \"http\""},
			{Name: "Mesh", Status: policy.LayerSkip, Summary: "no Istio/Linkerd sidecar on either side"},
		},
		Cell: policy.Cell{Allowed: true, Ports: []string{"8000"}},
	}
}

func TestPathRendersLayersVerdictAndFix(t *testing.T) {
	var b strings.Builder
	if err := Path(&b, samplePath()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"Service payments/api", "✓ DNS egress", "✗ Port", "– Mesh", "CrashLoopBackOff", "BLOCKED at Port", "How to fix (Port)", "name a container port"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestPathJSONShape(t *testing.T) {
	var b strings.Builder
	if err := PathJSON(&b, samplePath()); err != nil {
		t.Fatal(err)
	}
	var o struct {
		Verdict    string `json:"verdict"`
		Status     string `json:"status"`
		TargetPort int32  `json:"targetPort"`
		Layers     []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Fix    string `json:"fix"`
		} `json:"layers"`
		Service *struct {
			Ready int `json:"Ready"`
		} `json:"service"`
	}
	if err := json.Unmarshal([]byte(b.String()), &o); err != nil {
		t.Fatal(err)
	}
	if o.Verdict != "BLOCKED at Port" || o.Status != "fail" || o.TargetPort != 8000 || len(o.Layers) != 4 || o.Layers[2].Fix == "" || o.Service == nil || o.Service.Ready != 1 {
		t.Errorf("unexpected JSON: %s", b.String())
	}
}
