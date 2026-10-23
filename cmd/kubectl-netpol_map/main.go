package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/aganet/kubectl-netpol-map/internal/kube"
	"github.com/aganet/kubectl-netpol-map/internal/lint"
	"github.com/aganet/kubectl-netpol-map/internal/policy"
	"github.com/aganet/kubectl-netpol-map/internal/render"
	"github.com/aganet/kubectl-netpol-map/internal/tui"
	"github.com/aganet/kubectl-netpol-map/internal/ui"
)

// version is set by the release build (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// source is where snapshots come from: the cluster through kubeconfig, or
// manifests given with --offline (files, directories, "-" for stdin).
type source struct {
	flags   *genericclioptions.ConfigFlags
	offline []string
}

// namespace is the current namespace: -n, else the kubeconfig context's
// (offline: -n only, otherwise all).
func (s *source) namespace() string {
	if s.flags.Namespace != nil && *s.flags.Namespace != "" {
		return *s.flags.Namespace
	}
	if len(s.offline) > 0 {
		return ""
	}
	ns, _, err := s.flags.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return ""
	}
	return ns
}

// snapshot loads ns ("" = all namespaces); mesh also reads the mesh CRs.
func (s *source) snapshot(ctx context.Context, ns string, mesh bool) (*policy.Snapshot, error) {
	if len(s.offline) > 0 {
		snap, err := policy.LoadManifests(s.offline...)
		if err != nil {
			return nil, err
		}
		return snap.Scoped(ns), nil
	}
	clients, _, err := kube.NewClient(s.flags)
	if err != nil {
		return nil, fmt.Errorf("kube client: %w", err)
	}
	snap, err := policy.Fetch(ctx, clients, ns)
	if err != nil {
		return nil, fmt.Errorf("fetch policies/pods: %w", err)
	}
	if mesh {
		snap.Mesh = policy.FetchMesh(ctx, clients)
	}
	return snap, nil
}

func (s *source) name() string {
	if len(s.offline) > 0 {
		return "offline: " + strings.Join(s.offline, ", ")
	}
	return contextName(s.flags)
}

func newRootCmd() *cobra.Command {
	configFlags := genericclioptions.NewConfigFlags(true)
	src := &source{flags: configFlags}

	var (
		allNamespaces bool
		fromSelector  string
		toSelector    string
		fromNS        string
		toNS          string
		port          int32
		output        string
		byMode        string
		deniesOnly    bool
		showAllowed   bool
		expandEdges   bool
		fullWhy       bool
		resolveFQDN   bool
		verbose       bool
	)

	cmd := &cobra.Command{
		Use:     "kubectl-netpol-map",
		Version: version,
		Short:   "See what your NetworkPolicies allow and deny, and why A can't reach B",
		Long: `kubectl-netpol-map reads the NetworkPolicies (standard and Cilium) in a cluster
and shows what they allow and deny.

  kubectl netpol-map            reachability matrix for the selected namespace(s)
  kubectl netpol-map ui         web UI: policy map and connection trace
  kubectl netpol-map tui        the same in the terminal, full screen
  kubectl netpol-map path       trace one connection layer by layer and say where it breaks
  kubectl netpol-map diff       what a proposed policy change would alter
  kubectl netpol-map lint       audit policies for stale selectors and risky patterns

The tool only reads the cluster; it never changes anything. With --offline it
reads manifests instead (a directory, files, or - for stdin), so a Git repo,
a Helm chart or a Kustomize build can be reviewed without any cluster:

  kubectl netpol-map ui --offline ./manifests
  helm template my-app ./chart | kubectl netpol-map tui --offline -
  kustomize build overlays/prod | kubectl netpol-map lint --offline -

Examples:
  kubectl netpol-map
  kubectl netpol-map -n my-ns
  kubectl netpol-map --all-namespaces
  kubectl netpol-map --from app=frontend --to app=db --port 5432
  kubectl netpol-map -A --from-namespace shop --to-namespace payments
  kubectl netpol-map -A --denies-only
  kubectl netpol-map -o json`,
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx := context.Background()
			ns := src.namespace()
			if allNamespaces {
				ns = ""
			}
			snap, err := src.snapshot(ctx, ns, false)
			if err != nil {
				return err
			}
			if len(snap.Pods) == 0 && ns != "" {
				// The usual first run: the kubeconfig namespace is "default" and
				// holds nothing. Point at what is worth running instead.
				fmt.Fprintf(os.Stderr, "namespace %q has no pods. Try:\n"+
					"  kubectl netpol-map -A           every namespace\n"+
					"  kubectl netpol-map -n <ns>      one namespace\n"+
					"  kubectl netpol-map ui           the policy map in the browser\n"+
					"  kubectl netpol-map tui          the same in the terminal\n", ns)
				return nil
			}
			if resolveFQDN {
				snap.Resolver = policy.NewNetResolver()
			}

			mode := policy.GroupBy(byMode)
			switch mode {
			case "", policy.GroupByPod, policy.GroupByWorkload:
			default:
				return fmt.Errorf("--by must be pod or workload (got %q)", byMode)
			}

			ev := policy.NewBasicEvaluator()
			matrix, err := ev.Evaluate(snap, mode, fromSelector, toSelector, port)
			if err != nil {
				return err
			}

			matrix.FromNamespace = fromNS
			matrix.ToNamespace = toNS

			opts := render.Options{
				DeniesOnly:  deniesOnly,
				ShowAllowed: showAllowed,
				ExpandEdges: expandEdges,
				FullWhy:     fullWhy,
				Verbose:     verbose,
			}
			switch output {
			case "json":
				return render.JSON(os.Stdout, matrix)
			case "mermaid":
				return render.MermaidWithOptions(os.Stdout, matrix, opts)
			case "dot":
				return render.DotWithOptions(os.Stdout, matrix, opts)
			case "html":
				return render.HTMLWithOptions(os.Stdout, matrix, opts)
			case "", "table":
				return render.MatrixWithOptions(os.Stdout, matrix, opts)
			default:
				return fmt.Errorf("unsupported output format: %s (want table|json|mermaid|dot|html)", output)
			}
		},
	}

	configFlags.AddFlags(cmd.PersistentFlags())
	cmd.PersistentFlags().StringSliceVar(&src.offline, "offline", nil,
		"read manifests instead of a cluster: files, directories, or - for stdin (helm template … | kubectl netpol-map --offline -)")
	cmd.Flags().BoolVarP(&allNamespaces, "all-namespaces", "A", false, "show reachability across all namespaces")
	cmd.Flags().StringVar(&fromSelector, "from", "", "filter source pods by label selector (e.g. app=frontend)")
	cmd.Flags().StringVar(&toSelector, "to", "", "filter destination pods by label selector")
	cmd.Flags().StringVar(&fromNS, "from-namespace", "", "only include source pods in this namespace")
	cmd.Flags().StringVar(&toNS, "to-namespace", "", "only include destination pods in this namespace")
	cmd.Flags().Int32Var(&port, "port", 0, "only consider this destination port (0 = any)")
	cmd.Flags().StringVarP(&output, "output", "o", "table", "output format: table|json|mermaid|dot|html")
	cmd.Flags().StringVar(&byMode, "by", "workload", "axis grouping: workload|pod (workload collapses Deployment/StatefulSet/DaemonSet replicas; pod shows each replica)")
	cmd.Flags().BoolVar(&deniesOnly, "denies-only", false, "hide ALLOW edges; show only DENY and PARTIAL")
	cmd.Flags().BoolVar(&showAllowed, "show-allowed", false, "also render sub-matrices that are entirely default-allow (off by default)")
	cmd.Flags().BoolVar(&expandEdges, "expand-edges", false, "list every cross-namespace edge instead of collapsing by (source, dest-namespace)")
	cmd.Flags().BoolVar(&fullWhy, "full-why", false, "list every edge in the Why? section instead of grouping by reason")
	cmd.Flags().BoolVar(&resolveFQDN, "resolve-fqdn", false, "resolve Cilium toFQDNs egress via DNS to map external names to in-cluster pods and list external egress (makes DNS queries from where the CLI runs)")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "include policy inventory sections and full legend")

	cmd.AddCommand(newLintCmd(src))
	cmd.AddCommand(newPathCmd(src))
	cmd.AddCommand(newDiffCmd(src))
	cmd.AddCommand(newUICmd(src))
	cmd.AddCommand(newTUICmd(src))
	return cmd
}

func newTUICmd(src *source) *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Browse policies and connections in a full-screen terminal app",
		Long: `tui opens a full-screen terminal app: namespaces on the left, the policies,
evaluated connections or workloads of the selected namespace in the middle,
and the detail below — the editor-style view of a policy (y for its YAML), the
layered trace of a connection, or what touches a workload. t traces any
source → destination. Press ? inside the app for all keys.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			fetch := func(ctx context.Context) (*policy.Snapshot, error) { return src.snapshot(ctx, "", true) }
			return tui.Run(tui.New(fetch, src.name(), version))
		},
	}
}

func newUICmd(src *source) *cobra.Command {
	var (
		listen string
		noOpen bool
	)
	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Open a local web UI: policy map and connection trace",
		Long: `ui serves a page on localhost with two views: Policies (every policy on
one map with what it allows and denies, lint findings as badges) and Trace
(path, with source and destination picked from dropdowns).

The server runs only on your machine and reads the cluster with your
kubeconfig; nothing is deployed. Stop it with Ctrl-C.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx := context.Background()
			fetch := func(ctx context.Context) (*policy.Snapshot, error) {
				snap, err := src.snapshot(ctx, "", true)
				if err != nil {
					return nil, err
				}
				// External hosts are resolved from this machine so CIDR rules
				// can be matched against them (same as --resolve-fqdn).
				snap.Resolver = policy.NewNetResolver()
				return snap, nil
			}
			// Fail fast on a bad kubeconfig or path before opening the browser.
			if _, err := fetch(ctx); err != nil {
				return err
			}
			ln, err := net.Listen("tcp", listen)
			if err != nil {
				return err
			}
			url := "http://" + ln.Addr().String()
			fmt.Fprintf(os.Stderr, "kubectl-netpol-map ui: %s  (Ctrl-C to stop)\n", url)
			if !noOpen {
				openBrowser(url)
			}
			handler := ui.New(fetch, src.name(), version)
			if ln.Addr().(*net.TCPAddr).IP.IsLoopback() {
				handler = ui.LocalOnly(handler)
			} else {
				fmt.Fprintln(os.Stderr, "warning: --listen is not a loopback address; anyone who can reach this port sees the cluster's policies and workloads (read-only, no authentication)")
			}
			return http.Serve(ln, handler)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:8471", "address to serve the UI on")
	cmd.Flags().BoolVar(&noOpen, "no-open", false, "do not open the browser automatically")
	return cmd
}

func contextName(flags *genericclioptions.ConfigFlags) string {
	if flags.Context != nil && *flags.Context != "" {
		return *flags.Context
	}
	raw, err := flags.ToRawKubeConfigLoader().RawConfig()
	if err != nil {
		return ""
	}
	return raw.CurrentContext
}

func openBrowser(url string) {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		c = exec.Command("open", url)
	case "windows":
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		c = exec.Command("xdg-open", url)
	}
	_ = c.Start() // best-effort; the URL is printed either way
}

func newPathCmd(src *source) *cobra.Command {
	var (
		port        string
		output      string
		resolveFQDN bool
		failOnBlock bool
	)
	cmd := &cobra.Command{
		Use:   "path <source> <destination>[:<port>]",
		Short: "Trace one source → destination connection and say where it breaks",
		Long: `path walks the chain a connection crosses and checks each layer in order:
DNS egress (can the source reach kube-dns?), DNS (does the name map to a
Service?), Service (selector → pods → ready endpoints), Port (service port →
targetPort → container port), NetworkPolicy (standard + Cilium, evaluated at
the pod port) and Mesh (Istio mTLS mode; AuthorizationPolicy / Linkerd Server
presence). The verdict names the first layer that breaks, with a fix hint.

A reference is one of:
  <namespace>/<pod>                       exact pod
  <namespace>/<workload>                  all pods of a Deployment/StatefulSet/...
  <namespace>/<service>[:<port>]          the pods behind a Service, via its port mapping
  <service>.<namespace>.svc[:<port>]      the same, as a DNS name (cluster.local suffix optional)
  <namespace>:<key>=<value>               label selector within a namespace
  <name>[:<port>]                         any of the above in the current namespace
  <host>[:<port>], <ip>, <cidr>, internet  a destination outside the cluster

DNS, Service and Port are only checked when the destination is a Service.
For an external destination the egress rules that can leave the cluster
(ipBlock, Cilium toEntities/toCIDR/toFQDNs) are checked instead; with
--resolve-fqdn a host is resolved so CIDR rules can be matched against it.

Examples:
  kubectl netpol-map path shop/frontend payments/api:8080
  kubectl netpol-map path shop/frontend api.payments.svc.cluster.local:8080
  kubectl netpol-map path shop/frontend internet
  kubectl netpol-map path shop/frontend api.stripe.com:443 --resolve-fqdn
  kubectl netpol-map path shop/frontend payments/api --port 8080
  kubectl netpol-map path "shop:app=frontend" payments/api
  kubectl netpol-map path -n shop frontend api:8080 -o json`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			ns := src.namespace()
			// path needs cluster-wide visibility to resolve either side.
			snap, err := src.snapshot(ctx, "", true)
			if err != nil {
				return err
			}
			if resolveFQDN {
				snap.Resolver = policy.NewNetResolver()
			}
			res, err := policy.ExplainPath(snap, ns, args[0], args[1], port)
			if err != nil {
				return err
			}
			switch output {
			case "json":
				err = render.PathJSON(os.Stdout, res)
			case "", "table":
				err = render.Path(os.Stdout, res)
			default:
				return fmt.Errorf("unsupported output format: %s (want table|json)", output)
			}
			if err != nil {
				return err
			}
			if failOnBlock && res.Status() == policy.LayerFail {
				// Signal CI without printing a Go error/usage dump.
				cmd.SilenceUsage = true
				cmd.SilenceErrors = true
				os.Exit(2)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&port, "port", "", "destination port, number or Service port name (default: any); same as a :<port> suffix on the destination")
	cmd.Flags().StringVarP(&output, "output", "o", "table", "output format: table|json")
	cmd.Flags().BoolVar(&resolveFQDN, "resolve-fqdn", false, "resolve host names via DNS from this machine so CIDR rules can be matched (external destinations and Cilium toFQDNs)")
	cmd.Flags().BoolVar(&failOnBlock, "fail-on-block", false, "exit non-zero (2) when the connection is BLOCKED — for CI smoke checks")
	return cmd
}

func newDiffCmd(src *source) *cobra.Command {
	var (
		filename      string
		allNamespaces bool
		port          int32
		byMode        string
		output        string
		failOnChange  bool
	)
	cmd := &cobra.Command{
		Use:   "diff -f <policy.yaml>",
		Short: "Show how a proposed NetworkPolicy change would alter reachability",
		Long: `diff evaluates reachability twice — once against the live cluster, and
once with the policies in -f applied on top — and reports which edges become
newly allowed, newly denied, or change ports.

A manifest with the same namespace+name as a live policy replaces it;
otherwise it is added. Standard NetworkPolicy and Cilium(Clusterwide)NetworkPolicy
documents are supported, including multi-document files.

With --fail-on-change the command exits non-zero if any edge changes, which
makes it usable as a pre-merge CI gate.

Examples:
  kubectl netpol-map diff -f new-policy.yaml
  kubectl netpol-map diff -f new-policy.yaml -A --fail-on-change
  kubectl netpol-map diff -f new-policy.yaml -o json | jq '.newlyAllowed'`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if filename == "" {
				return fmt.Errorf("--filename/-f is required")
			}
			data, err := os.ReadFile(filename)
			if err != nil {
				return fmt.Errorf("read %s: %w", filename, err)
			}
			docs, err := policy.SplitYAMLDocuments(data)
			if err != nil {
				return fmt.Errorf("parse %s: %w", filename, err)
			}

			ctx := context.Background()
			ns := src.namespace()
			if allNamespaces {
				ns = ""
			}
			before, err := src.snapshot(ctx, ns, false)
			if err != nil {
				return err
			}
			after, err := before.ApplyManifests(docs)
			if err != nil {
				return err
			}

			mode := policy.GroupBy(byMode)
			switch mode {
			case "", policy.GroupByPod, policy.GroupByWorkload:
			default:
				return fmt.Errorf("--by must be pod or workload (got %q)", byMode)
			}

			result, err := policy.Diff(before, after, mode, "", "", port)
			if err != nil {
				return err
			}

			switch output {
			case "json":
				if err := render.DiffJSON(os.Stdout, result); err != nil {
					return err
				}
			case "", "table":
				if err := render.Diff(os.Stdout, result); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unsupported output format: %s (want table|json)", output)
			}

			changed := len(result.NewlyAllowed) + len(result.NewlyDenied) + len(result.Changed)
			if failOnChange && changed > 0 {
				// Signal CI without printing a Go error/usage dump.
				cmd.SilenceUsage = true
				cmd.SilenceErrors = true
				os.Exit(2)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&filename, "filename", "f", "", "policy manifest to evaluate (YAML, may be multi-document)")
	cmd.Flags().BoolVarP(&allNamespaces, "all-namespaces", "A", false, "diff reachability across all namespaces")
	cmd.Flags().Int32Var(&port, "port", 0, "only consider this destination port (0 = any)")
	cmd.Flags().StringVar(&byMode, "by", "workload", "axis grouping: workload|pod")
	cmd.Flags().StringVarP(&output, "output", "o", "table", "output format: table|json")
	cmd.Flags().BoolVar(&failOnChange, "fail-on-change", false, "exit non-zero (2) if any edge changes verdict — for CI gates")
	return cmd
}

func newLintCmd(src *source) *cobra.Command {
	var (
		allNamespaces bool
		output        string
	)

	cmd := &cobra.Command{
		Use:   "lint",
		Short: "Audit NetworkPolicies for stale selectors, redundancy, and risky patterns",
		Long: `lint runs a set of rules against the NetworkPolicies in scope and
reports findings (stale selectors, deny-all baselines, allow-from-anywhere
rules, overlapping isolation, standard/Cilium interaction).

The tool only reports — it never mutates cluster state.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx := context.Background()
			ns := src.namespace()
			if allNamespaces {
				ns = ""
			}
			snap, err := src.snapshot(ctx, ns, false)
			if err != nil {
				return err
			}

			findings := lint.Run(snap)

			switch output {
			case "json":
				return render.LintJSON(os.Stdout, findings)
			case "", "table":
				return render.Lint(os.Stdout, findings)
			default:
				return fmt.Errorf("unsupported output format: %s", output)
			}
		},
	}

	cmd.Flags().BoolVarP(&allNamespaces, "all-namespaces", "A", false, "lint policies across all namespaces")
	cmd.Flags().StringVarP(&output, "output", "o", "table", "output format: table|json")
	return cmd
}
