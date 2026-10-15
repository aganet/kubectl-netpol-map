package policy

import (
	"os"
	"path/filepath"
	"testing"
)

const offlineManifests = `
apiVersion: v1
kind: Namespace
metadata:
  name: shop
  labels: {team: web}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: frontend, namespace: shop}
spec:
  replicas: 2
  selector: {matchLabels: {app: frontend}}
  template:
    metadata: {labels: {app: frontend}}
    spec:
      containers:
        - name: web
          image: nginx
          ports: [{name: http, containerPort: 8080}]
---
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: postgres, namespace: shop}
spec:
  selector: {matchLabels: {app: postgres}}
  template:
    metadata: {labels: {app: postgres}}
    spec:
      containers:
        - name: db
          image: postgres
          ports: [{name: postgres, containerPort: 5432}]
---
apiVersion: v1
kind: Service
metadata: {name: postgres, namespace: shop}
spec:
  selector: {app: postgres}
  ports: [{port: 5432, targetPort: postgres}]
---
apiVersion: v1
kind: ConfigMap
metadata: {name: ignored, namespace: shop}
data: {k: v}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: db-ingress, namespace: shop}
spec:
  podSelector: {matchLabels: {app: postgres}}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector: {matchLabels: {app: api}}
      ports: [{port: postgres}]
`

func TestLoadManifestsSynthesisesPodsAndEvaluates(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte(offlineManifests), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "values.yaml"), []byte("replicaCount: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap, err := LoadManifests(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Pods) != 2 || len(snap.Services) != 1 || len(snap.Policies) != 1 {
		t.Fatalf("pods %d services %d policies %d", len(snap.Pods), len(snap.Services), len(snap.Policies))
	}
	if snap.NamespaceLabels["shop"]["team"] != "web" || snap.NamespaceLabels["shop"]["kubernetes.io/metadata.name"] != "shop" {
		t.Errorf("namespace labels: %v", snap.NamespaceLabels["shop"])
	}
	ws := snap.Workloads()
	if len(ws) != 2 || ws[0].Kind != "Deployment" || ws[1].Kind != "StatefulSet" {
		t.Errorf("workload grouping from owner references: %+v", ws)
	}

	// The whole chain works on synthetic pods: Service, named port, policy.
	res, err := ExplainPath(snap, "", "shop/frontend", "shop/postgres:5432", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict() != "BLOCKED at NetworkPolicy" || res.TargetPort != 5432 {
		t.Errorf("expected BLOCKED at NetworkPolicy on 5432, got %q (%d); layers %+v", res.Verdict(), res.TargetPort, res.Layers)
	}
	if l := findLayer(res, "Service"); l.Status != LayerPass {
		t.Errorf("synthetic pods must count as Ready endpoints: %+v", l)
	}

	scoped := snap.Scoped("other")
	if len(scoped.Pods) != 0 || len(scoped.Policies) != 0 || scoped.NamespaceLabels["shop"] == nil {
		t.Errorf("Scoped should drop other namespaces' objects but keep labels: %+v", scoped)
	}
	if _, err := LoadManifests(filepath.Join(dir, "values.yaml")); err == nil {
		t.Errorf("a file with no Kubernetes objects must be an error")
	}
}
