package policy

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// LoadManifests builds a snapshot from Kubernetes manifests instead of a
// cluster: each path is a YAML/JSON file, a directory (walked recursively)
// or "-" for stdin, which is how `helm template` and `kustomize build`
// output comes in. Workloads become one synthetic Ready pod each, so every
// evaluation works exactly as it does against a live cluster. Kinds the tool
// does not know are ignored.
func LoadManifests(paths ...string) (*Snapshot, error) {
	snap := &Snapshot{NamespaceLabels: map[string]map[string]string{}, Mesh: &MeshSnapshot{}}
	podIP := 0
	for _, p := range paths {
		var files []string
		switch {
		case p == "-":
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return nil, err
			}
			if err := loadDocs(snap, "stdin", data, &podIP); err != nil {
				return nil, err
			}
			continue
		default:
			info, err := os.Stat(p)
			if err != nil {
				return nil, err
			}
			if !info.IsDir() {
				files = []string{p}
				break
			}
			err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					if path != p && strings.HasPrefix(d.Name(), ".") {
						return filepath.SkipDir
					}
					return nil
				}
				switch strings.ToLower(filepath.Ext(path)) {
				case ".yaml", ".yml", ".json":
					files = append(files, path)
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
		sort.Strings(files)
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				return nil, err
			}
			if err := loadDocs(snap, f, data, &podIP); err != nil {
				return nil, err
			}
		}
	}
	// The API server labels every namespace with its name; policies rely on it.
	for _, ns := range namespacesOf(snap) {
		if snap.NamespaceLabels[ns] == nil {
			snap.NamespaceLabels[ns] = map[string]string{}
		}
		snap.NamespaceLabels[ns]["kubernetes.io/metadata.name"] = ns
	}
	if len(snap.Pods)+len(snap.Policies)+len(snap.CiliumNamespacePolicies)+len(snap.CiliumClusterPolicies) == 0 {
		return nil, fmt.Errorf("no workloads or policies found in %s", strings.Join(paths, ", "))
	}
	return snap, nil
}

func loadDocs(snap *Snapshot, source string, data []byte, podIP *int) error {
	docs, err := SplitYAMLDocuments(data)
	if err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	for _, doc := range docs {
		u, err := decodeUnstructured(doc)
		if err != nil || u.GetKind() == "" {
			continue // not a Kubernetes object (values files, comments, …)
		}
		if err := loadObject(snap, u, doc, podIP); err != nil {
			return fmt.Errorf("%s: %s %s: %w", source, u.GetKind(), u.GetName(), err)
		}
	}
	return nil
}

func loadObject(snap *Snapshot, u unstructured.Unstructured, doc []byte, podIP *int) error {
	group := strings.Split(u.GetAPIVersion(), "/")[0]
	switch u.GetKind() {
	case "Namespace":
		snap.NamespaceLabels[u.GetName()] = u.GetLabels()
	case "Service":
		var svc corev1.Service
		if err := yaml.Unmarshal(doc, &svc); err != nil {
			return err
		}
		svc.Namespace = defaultNS(svc.Namespace)
		snap.Services = append(snap.Services, svc)
	case "Pod":
		var pod corev1.Pod
		if err := yaml.Unmarshal(doc, &pod); err != nil {
			return err
		}
		pod.Namespace = defaultNS(pod.Namespace)
		markReady(&pod, podIP)
		snap.Pods = append(snap.Pods, pod)
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "ReplicationController":
		path := []string{"spec", "template"}
		if u.GetKind() == "CronJob" {
			path = []string{"spec", "jobTemplate", "spec", "template"}
		}
		raw, found, _ := unstructured.NestedMap(u.Object, path...)
		if !found {
			return fmt.Errorf("no pod template")
		}
		var tpl corev1.PodTemplateSpec
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(raw, &tpl); err != nil {
			return err
		}
		pod := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   defaultNS(u.GetNamespace()),
				Name:        u.GetName() + "-0",
				Labels:      tpl.Labels,
				Annotations: tpl.Annotations,
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: u.GetAPIVersion(), Kind: u.GetKind(), Name: u.GetName(), Controller: new(true),
				}},
			},
			Spec: tpl.Spec,
		}
		markReady(&pod, podIP)
		snap.Pods = append(snap.Pods, pod)
	case "NetworkPolicy":
		if group != "networking.k8s.io" { // Calico and Antrea reuse the kind name
			snap.Unevaluated = append(snap.Unevaluated, group+" "+u.GetKind()+" "+u.GetName())
			return nil
		}
		var np networkingv1.NetworkPolicy
		if err := yaml.Unmarshal(doc, &np); err != nil {
			return err
		}
		np.Namespace = defaultNS(np.Namespace)
		snap.Policies = upsertNP(snap.Policies, np)
	case "CiliumNetworkPolicy":
		if u.GetNamespace() == "" {
			u.SetNamespace("default")
		}
		snap.CiliumNamespacePolicies = upsertCNP(snap.CiliumNamespacePolicies, u)
	case "CiliumClusterwideNetworkPolicy":
		snap.CiliumClusterPolicies = upsertCNP(snap.CiliumClusterPolicies, u)
	case "PeerAuthentication":
		snap.Mesh.PeerAuthentications = append(snap.Mesh.PeerAuthentications, u)
	case "AuthorizationPolicy":
		if group == "security.istio.io" {
			snap.Mesh.AuthorizationPolicies = append(snap.Mesh.AuthorizationPolicies, u)
		} else {
			snap.Mesh.LinkerdAuthorizationPolicies = append(snap.Mesh.LinkerdAuthorizationPolicies, u)
		}
	case "Server":
		if group == "policy.linkerd.io" {
			snap.Mesh.LinkerdServers = append(snap.Mesh.LinkerdServers, u)
		}
	case "AdminNetworkPolicy", "BaselineAdminNetworkPolicy", "GlobalNetworkPolicy", "ClusterNetworkPolicy":
		snap.Unevaluated = append(snap.Unevaluated, group+" "+u.GetKind()+" "+u.GetName())
	}
	return nil
}

// markReady makes a synthetic pod look like a running endpoint.
func markReady(pod *corev1.Pod, podIP *int) {
	*podIP++
	pod.Status = corev1.PodStatus{
		Phase:      corev1.PodRunning,
		PodIP:      fmt.Sprintf("10.244.%d.%d", *podIP/250, *podIP%250+1),
		Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
	}
}

func defaultNS(ns string) string {
	if ns == "" {
		return "default"
	}
	return ns
}

func namespacesOf(snap *Snapshot) []string {
	seen := map[string]bool{}
	for ns := range snap.NamespaceLabels {
		seen[ns] = true
	}
	for _, p := range snap.Pods {
		seen[p.Namespace] = true
	}
	for _, s := range snap.Services {
		seen[s.Namespace] = true
	}
	for _, p := range snap.Policies {
		seen[p.Namespace] = true
	}
	for _, p := range snap.CiliumNamespacePolicies {
		seen[p.GetNamespace()] = true
	}
	out := make([]string, 0, len(seen))
	for ns := range seen {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

// Scoped narrows a snapshot to one namespace the way Fetch(namespace) would:
// pods, Services and namespaced policies of that namespace only, cluster-wide
// policies and namespace labels kept.
func (s *Snapshot) Scoped(ns string) *Snapshot {
	if ns == "" {
		return s
	}
	out := *s
	out.Namespace = ns
	out.Pods, out.Services, out.Policies, out.CiliumNamespacePolicies = nil, nil, nil, nil
	for _, p := range s.Pods {
		if p.Namespace == ns {
			out.Pods = append(out.Pods, p)
		}
	}
	for _, svc := range s.Services {
		if svc.Namespace == ns {
			out.Services = append(out.Services, svc)
		}
	}
	for _, p := range s.Policies {
		if p.Namespace == ns {
			out.Policies = append(out.Policies, p)
		}
	}
	for _, p := range s.CiliumNamespacePolicies {
		if p.GetNamespace() == ns {
			out.CiliumNamespacePolicies = append(out.CiliumNamespacePolicies, p)
		}
	}
	return &out
}
