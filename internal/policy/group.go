package policy

import (
	"sort"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// Workload identifies a higher-level controller (Deployment, StatefulSet,
// DaemonSet, Job, ...) that owns one or more pods. Bare pods (no controlling
// owner reference) are themselves Workloads with Kind="Pod".
type Workload struct {
	Namespace string
	Kind      string
	Name      string
	Pods      []*corev1.Pod
}

// Display returns "ns/Kind/Name" — namespace-scoped, kind-aware.
func (w Workload) Display() string {
	return w.Namespace + "/" + w.Kind + "/" + w.Name
}

// Workloads groups every pod in the snapshot by its controller.
func (s *Snapshot) Workloads() []Workload {
	return groupPodsByWorkload(s.Pods, s.ReplicaSets)
}

// groupPodsByWorkload bucketizes pods into Workloads using ownerReferences.
// ReplicaSet owners are walked one level up to their owning Deployment so
// that all replicas of a Deployment collapse into a single Workload.
func groupPodsByWorkload(pods []corev1.Pod, replicaSets []appsv1.ReplicaSet) []Workload {
	rsByKey := map[string]appsv1.ReplicaSet{}
	for _, rs := range replicaSets {
		rsByKey[rs.Namespace+"/"+rs.Name] = rs
	}

	groupKey := func(p corev1.Pod) (kind, name string) {
		for _, or := range p.OwnerReferences {
			if or.Controller == nil || !*or.Controller {
				continue
			}
			if or.Kind == "ReplicaSet" {
				if rs, ok := rsByKey[p.Namespace+"/"+or.Name]; ok {
					for _, rsOwn := range rs.OwnerReferences {
						if rsOwn.Controller != nil && *rsOwn.Controller {
							return rsOwn.Kind, rsOwn.Name
						}
					}
				}
				return "ReplicaSet", or.Name
			}
			return or.Kind, or.Name
		}
		return "Pod", p.Name
	}

	groups := map[string]*Workload{}
	for i := range pods {
		p := &pods[i]
		kind, name := groupKey(*p)
		key := p.Namespace + "/" + kind + "/" + name
		if g, ok := groups[key]; ok {
			g.Pods = append(g.Pods, p)
			continue
		}
		groups[key] = &Workload{
			Namespace: p.Namespace,
			Kind:      kind,
			Name:      name,
			Pods:      []*corev1.Pod{p},
		}
	}

	out := make([]Workload, 0, len(groups))
	for _, g := range groups {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out
}
