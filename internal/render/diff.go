package render

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/aganet/kubectl-netpol-map/internal/policy"
)

// Diff renders a before/after reachability comparison: edges newly allowed,
// newly denied, or with changed ports. This is the pre-merge "what does this
// policy change actually do?" view.
func Diff(w io.Writer, d *policy.DiffResult) error {
	total := len(d.NewlyAllowed) + len(d.NewlyDenied) + len(d.Changed)
	fmt.Fprintln(w, text.Bold.Sprintf("Policy change impact  (%d edges change verdict)", total))
	fmt.Fprintln(w)

	if total == 0 {
		fmt.Fprintln(w, "  No reachability changes — the manifest does not alter any edge in scope.")
		return nil
	}

	if len(d.NewlyDenied) > 0 {
		fmt.Fprintln(w, color.RedString("  Newly DENIED  (was reachable, now blocked):"))
		printChanges(w, d.NewlyDenied, func(c policy.EdgeChange) string {
			return fmt.Sprintf("was %s → now DENY", verdictWord(c.Before))
		})
		fmt.Fprintln(w)
	}
	if len(d.NewlyAllowed) > 0 {
		fmt.Fprintln(w, color.GreenString("  Newly ALLOWED  (was blocked, now reachable):"))
		printChanges(w, d.NewlyAllowed, func(c policy.EdgeChange) string {
			return fmt.Sprintf("was DENY → now %s", verdictWord(c.After))
		})
		fmt.Fprintln(w)
	}
	if len(d.Changed) > 0 {
		fmt.Fprintln(w, color.YellowString("  Ports changed  (still reachable, different ports):"))
		printChanges(w, d.Changed, func(c policy.EdgeChange) string {
			return fmt.Sprintf("%s → %s", portsWord(c.Before.Ports), portsWord(c.After.Ports))
		})
		fmt.Fprintln(w)
	}
	return nil
}

func printChanges(w io.Writer, changes []policy.EdgeChange, summary func(policy.EdgeChange) string) {
	sort.SliceStable(changes, func(i, j int) bool {
		if changes[i].Key.Src != changes[j].Key.Src {
			return changes[i].Key.Src < changes[j].Key.Src
		}
		return changes[i].Key.Dst < changes[j].Key.Dst
	})
	for _, c := range changes {
		fmt.Fprintf(w, "    %s → %s   (%s)\n", c.Key.Src, c.Key.Dst, summary(c))
	}
}

func verdictWord(v policy.EdgeVerdict) string {
	switch {
	case v.Unknown:
		return "UNKNOWN"
	case v.Partial:
		return "PARTIAL"
	case v.Allowed:
		return "ALLOW" + portSuffix(v.Ports)
	default:
		return "DENY"
	}
}

func portSuffix(ports []string) string {
	if len(ports) == 0 || (len(ports) == 1 && ports[0] == "*") {
		return ""
	}
	return " :" + strings.Join(policy.DisplayPorts(ports), ",")
}

func portsWord(ports []string) string {
	if len(ports) == 0 || (len(ports) == 1 && ports[0] == "*") {
		return "all ports"
	}
	return strings.Join(policy.DisplayPorts(ports), ",")
}

// DiffJSON emits the diff as JSON. CI gates can fail on a non-empty
// newlyAllowed list (or any change) using the structured output.
func DiffJSON(w io.Writer, d *policy.DiffResult) error {
	type change struct {
		Src    string `json:"src"`
		Dst    string `json:"dst"`
		Before string `json:"before"`
		After  string `json:"after"`
	}
	type out struct {
		NewlyAllowed []change `json:"newlyAllowed"`
		NewlyDenied  []change `json:"newlyDenied"`
		PortsChanged []change `json:"portsChanged"`
	}
	conv := func(list []policy.EdgeChange) []change {
		res := make([]change, 0, len(list))
		for _, c := range list {
			res = append(res, change{
				Src: c.Key.Src, Dst: c.Key.Dst,
				Before: verdictWord(c.Before), After: verdictWord(c.After),
			})
		}
		return res
	}
	o := out{
		NewlyAllowed: conv(d.NewlyAllowed),
		NewlyDenied:  conv(d.NewlyDenied),
		PortsChanged: conv(d.Changed),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(o)
}
