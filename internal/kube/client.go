package kube

import (
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// Clients bundles the kube clientsets we need: typed for core/networking and
// dynamic for arbitrary CRDs (Cilium NetworkPolicies, etc.).
type Clients struct {
	Kube    kubernetes.Interface
	Dynamic dynamic.Interface
}

// NewClient builds the clients from kubectl-style config flags
// (honours --kubeconfig, --context, --namespace, etc.). The second return
// is the effective namespace from the user's context.
func NewClient(flags *genericclioptions.ConfigFlags) (*Clients, string, error) {
	cfg, err := flags.ToRESTConfig()
	if err != nil {
		return nil, "", err
	}

	kc, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, "", err
	}

	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, "", err
	}

	ns, _, err := flags.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return nil, "", err
	}

	return &Clients{Kube: kc, Dynamic: dc}, ns, nil
}
