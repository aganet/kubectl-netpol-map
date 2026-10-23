package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/aganet/kubectl-netpol-map/internal/policy"
)

// Path renders a single src→dst question as the chain of layers the
// connection crosses, one line each, then the verdict and how to fix the
// first thing that is wrong. This is the "why can't A talk to B?" answer.
func Path(w io.Writer, r *policy.PathResult) error {
	fmt.Fprintln(w, text.Bold.Sprintf("Path: %s  →  %s", r.SrcRef, r.DstRef))
	fmt.Fprintf(w, "  source       %d pod(s): %s\n", len(r.SrcPods), joinTrunc(r.SrcPods, 4))
	switch {
	case r.External != "":
		fmt.Fprintf(w, "  destination  outside the cluster: %s\n", r.External)
		fmt.Fprintln(w, text.Faint.Sprint("  (static check of egress rules; assumes the cluster has outbound NAT or an egress gateway)"))
	case r.Service != nil:
		fmt.Fprintf(w, "  destination  Service %s/%s → %d pod(s): %s\n",
			r.Service.Namespace, r.Service.Name, len(r.DstPods), joinTrunc(r.DstPods, 4))
	case len(r.DstPods) > 0:
		fmt.Fprintf(w, "  destination  %d pod(s): %s\n", len(r.DstPods), joinTrunc(r.DstPods, 4))
		fmt.Fprintln(w, text.Faint.Sprint("  (destination given as pods: DNS, Service and Port layers skipped — use <ns>/<service>[:port] to check them)"))
	}
	fmt.Fprintln(w)

	for _, l := range r.Layers {
		fmt.Fprintf(w, "  %s %-14s %s\n", layerGlyph(l.Status), l.Name, l.Summary)
		for _, d := range l.Detail {
			fmt.Fprintf(w, "    %-14s %s\n", "", text.Faint.Sprint(d))
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Verdict: %s\n", statusColor(r.Status()).Sprint(r.Verdict()))

	switch {
	case len(r.PerPair) > 1 && uniformPairs(r.PerPair):
		fmt.Fprintln(w, text.Faint.Sprintf("  (%d pod pairs, all with the same verdict)", len(r.PerPair)))
	case len(r.PerPair) > 1:
		fmt.Fprintln(w)
		fmt.Fprintln(w, text.Bold.Sprint("  NetworkPolicy per pod pair:"))
		for _, p := range r.PerPair {
			var v string
			switch {
			case p.Unknown:
				v = color.New(color.FgHiYellow).Sprint("UNKNOWN")
			case !p.Allowed:
				v = color.RedString("DENY")
			case len(p.Ports) > 0 && !(len(p.Ports) == 1 && p.Ports[0] == "*"):
				v = color.GreenString("ALLOW :" + strings.Join(policy.DisplayPorts(p.Ports), ","))
			default:
				v = color.GreenString("ALLOW")
			}
			fmt.Fprintf(w, "    %s → %s   %s   %s\n", p.Src, p.Dst, v, p.Reason)
		}
	}

	for _, l := range r.Layers {
		if l.Fix == "" {
			continue
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, text.Bold.Sprintf("  How to fix (%s):", l.Name))
		for _, line := range strings.Split(l.Fix, "\n") {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}
	return nil
}

// uniformPairs is true when every pod pair reached the same verdict for
// the same reason, so listing them adds nothing.
func uniformPairs(pairs []policy.Pair) bool {
	for _, p := range pairs[1:] {
		if p.Allowed != pairs[0].Allowed || p.Unknown != pairs[0].Unknown || p.Reason != pairs[0].Reason ||
			strings.Join(p.Ports, ",") != strings.Join(pairs[0].Ports, ",") {
			return false
		}
	}
	return true
}

func layerGlyph(s policy.LayerStatus) string {
	switch s {
	case policy.LayerPass:
		return color.GreenString("✓")
	case policy.LayerFail:
		return color.RedString("✗")
	case policy.LayerWarn:
		return color.YellowString("!")
	}
	return color.New(color.Faint).Sprint("–")
}

func statusColor(s policy.LayerStatus) *color.Color {
	switch s {
	case policy.LayerFail:
		return color.New(color.FgRed, color.Bold)
	case policy.LayerWarn:
		return color.New(color.FgYellow, color.Bold)
	}
	return color.New(color.FgGreen, color.Bold)
}

// PathJSON emits the path result as JSON for scripting / CI.
func PathJSON(w io.Writer, r *policy.PathResult) error {
	type layer struct {
		Name    string   `json:"name"`
		Status  string   `json:"status"`
		Summary string   `json:"summary"`
		Detail  []string `json:"detail,omitempty"`
		Fix     string   `json:"fix,omitempty"`
	}
	type pair struct {
		Src     string   `json:"src"`
		Dst     string   `json:"dst"`
		Allowed bool     `json:"allowed"`
		Unknown bool     `json:"unknown,omitempty"`
		Ports   []string `json:"ports,omitempty"`
		Reason  string   `json:"reason,omitempty"`
	}
	type out struct {
		Src        string             `json:"src"`
		Dst        string             `json:"dst"`
		Port       string             `json:"port,omitempty"`
		TargetPort int32              `json:"targetPort,omitempty"`
		Verdict    string             `json:"verdict"`
		Status     string             `json:"status"`
		Service    *policy.ServiceHop `json:"service,omitempty"`
		External   string             `json:"external,omitempty"`
		Layers     []layer            `json:"layers"`
		Allowed    bool               `json:"allowed"`
		Partial    bool               `json:"partial,omitempty"`
		Unknown    bool               `json:"unknown,omitempty"`
		Ports      []string           `json:"ports,omitempty"`
		Reason     string             `json:"reason,omitempty"`
		SrcPods    []string           `json:"srcPods"`
		DstPods    []string           `json:"dstPods"`
		Pairs      []pair             `json:"pairs,omitempty"`
	}
	o := out{
		Src: r.SrcRef, Dst: r.DstRef, Port: r.Port, TargetPort: r.TargetPort,
		Verdict: r.Verdict(), Status: string(r.Status()), Service: r.Service, External: r.External,
		Allowed: r.Cell.Allowed, Partial: r.Cell.Partial, Unknown: r.Cell.Unknown,
		Ports: policy.DisplayPorts(r.Cell.Ports), Reason: r.Cell.Reason,
		SrcPods: r.SrcPods, DstPods: r.DstPods,
	}
	for _, l := range r.Layers {
		o.Layers = append(o.Layers, layer{l.Name, string(l.Status), l.Summary, l.Detail, l.Fix})
	}
	for _, p := range r.PerPair {
		o.Pairs = append(o.Pairs, pair{p.Src, p.Dst, p.Allowed, p.Unknown, policy.DisplayPorts(p.Ports), p.Reason})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(o)
}

func joinTrunc(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:max], ", ") + fmt.Sprintf(", … (+%d more)", len(items)-max)
}
