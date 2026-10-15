# kubectl-netpol-map

![Policies map](docs/policies-map.png)

![Policy detail](docs/policy-detail.png)

![Terminal UI](docs/terminal.png)

`kubectl netpol-map` shows what your Kubernetes NetworkPolicies (standard and Cilium)
allow and deny, and why A can't reach B. Web UI, terminal UI and CLI. Read-only.

## Install

```sh
go install github.com/aganet/kubectl-netpol-map/cmd/kubectl-netpol-map@latest
export PATH="$PATH:$(go env GOPATH)/bin"   # kubectl finds plugins on the PATH
```

Or a binary from [releases](https://github.com/aganet/kubectl-netpol-map/releases)
(macOS, Linux, Windows; amd64, arm64), placed on your `PATH` as `kubectl-netpol-map`:

```sh
V=0.2.1; OS=darwin; ARCH=arm64
curl -LO https://github.com/aganet/kubectl-netpol-map/releases/download/v$V/kubectl-netpol-map_${V}_${OS}_${ARCH}.tar.gz
tar -xzf kubectl-netpol-map_${V}_${OS}_${ARCH}.tar.gz && sudo install -m 0755 kubectl-netpol-map /usr/local/bin/
```

## Commands

```sh
kubectl netpol-map ui                                          # web UI, localhost only
kubectl netpol-map tui                                         # terminal UI, k9s-style
kubectl netpol-map path shop/frontend api.payments.svc:8080     # why can't frontend reach api?
kubectl netpol-map path shop/worker internet                   # can worker reach the internet?
kubectl netpol-map -A --denies-only                            # reachability matrix, denied edges only
kubectl netpol-map diff -f new-policy.yaml -A --fail-on-change # what a policy change would alter; CI gate
kubectl netpol-map lint -A                                     # stale selectors, allow-from-anywhere, …
```

| Command | Flags |
| --- | --- |
| matrix | `-n`, `-A`, `--from`/`--to` selectors, `--from-namespace`/`--to-namespace`, `--port`, `--by workload\|pod`, `--denies-only`, `--show-allowed`, `--expand-edges`, `--resolve-fqdn`, `-o table\|json\|mermaid\|dot\|html` |
| `path` | `--port`, `--resolve-fqdn`, `--fail-on-block` (exit 2), `-o table\|json` |
| `ui` | `--listen` (default `127.0.0.1:8471`), `--no-open` |
| `tui` | `?` inside for keys |
| `diff` | `-f` manifest, `-A`, `--port`, `--fail-on-change` (exit 2), `-o table\|json` |
| `lint` | `-A`, `-o table\|json` |

All commands take the kubectl flags (`--kubeconfig`, `--context`, `-n`, `--as`)
and `--offline <path>` to read manifests instead of a cluster.
A `path` reference is `ns/pod`, `ns/workload`, `ns/service[:port]`,
`service.ns.svc[:port]`, `ns:key=value`, or external: `internet`, a host, an IP, a CIDR.

`demo/demo.yaml` is a three-tier app with typical policies; its header lists the
expected verdict of each command. `demo/cilium.yaml` adds Cilium examples.

**Offline**: `--offline` on any command reads manifests instead of a cluster,
so a Git repo, a Helm chart or a Kustomize build can be reviewed before it is
applied. Workloads become synthetic pods; everything else works the same.

```sh
kubectl netpol-map ui --offline ./manifests                   # a directory, walked recursively
kubectl netpol-map tui --offline demo/demo.yaml
helm template shop ./chart | kubectl netpol-map lint --offline -
kustomize build overlays/prod | kubectl netpol-map path --offline - shop/frontend shop/api:8080
```

## Trace

```text
$ kubectl netpol-map path shop/frontend api.payments.svc:8080
  ✓ DNS egress     source may reach kube-system/kube-dns:53 — egress allowed by shop/frontend-egress
  ✓ DNS            api.payments.svc → Service payments/api (ClusterIP 10.96.12.4)
  ✓ Service        selector app=api matches 3 pod(s), 2 ready
                   api-55f4856d6d-b2zr8  CrashLoopBackOff (container api, 12 restarts)
  ✗ Port           8080/TCP (http) → targetPort http: no container port named "http" on any of the 2 pod(s)
  ✓ NetworkPolicy  ALLOW :8000 — ingress allowed by payments/allow-frontend; egress allowed by shop/frontend-egress
  – Mesh           no Istio/Linkerd sidecar on either side

  Verdict: BLOCKED at Port
  How to fix (Port): name a container port "http" in the pod spec, or point targetPort at a number
```

Layers: DNS egress (can the source reach kube-dns), DNS (name → Service),
Service (selector → Ready pods), Port (port → targetPort → container port),
NetworkPolicy (standard + Cilium at the pod port), Mesh (Istio mTLS STRICT).
External targets check `ipBlock`, Cilium `toEntities`/`toCIDR`/`toFQDNs`.

## UIs

**Web** (`ui`): the policy map with namespace, port and edge-type filters,
draggable groups, SVG export, lint badges; a policy detail in the Cilium-editor
layout; trace with dropdowns.

**Terminal** (`tui`): namespaces left; policies (`1`), connections (`2`) or
workloads (`3`) middle; detail below with a "what this policy does" list, the
three-column layout, `y` for YAML, `enter` to trace a connection, `t` to trace
any pair, `/` filter, `d` denied, `r` refresh, `?` help. Mouse works.

## How it decides

Per pod pair: egress allowed at the source, ingress at the destination, by both
engines, on a shared port; workloads aggregate to `ALLOW`, `DENY`, `PARTIAL`.
Anything that depends on a rule the engine can't evaluate (Cilium L7,
unresolved FQDN, CIDR, entity) is `UNKNOWN`, never a false `DENY`.

Not evaluated: Cilium `matchExpressions`, `toRequires`, `toServices`,
`toNodes`, ICMP, host policies, `endPort` ranges, protocols;
`AdminNetworkPolicy`; Calico and Antrea policies. `path` is static: it reads
objects, sends no packets, assumes CoreDNS in `kube-system` and outbound NAT.

## Safety

Only `list` and discovery calls; nothing is created, updated or deleted. A
read-only RBAC role is enough. The web UI binds to localhost and answers only
to localhost host names. Dependencies are scanned with `govulncheck` in CI.
See [SECURITY.md](SECURITY.md) for reporting.

## Development

`make build`, `make test`, `make demo`. Layout: `cmd/` CLI, `internal/policy`
engine, `internal/render`, `internal/ui`, `internal/tui`, `internal/lint`,
`demo/`. PRs welcome; one change per PR, `make test` green.

[MIT](LICENSE)
