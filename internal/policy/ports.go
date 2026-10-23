package policy

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// A port list entry is "<lo>[-<hi>]/<PROTO>" (8080/TCP, 8000-9000/UDP,
// 53/ANY for a Cilium rule without protocol), "ICMP" for a Cilium rule that
// opens only ICMP, or "*" for every port of every protocol.
type portSpec struct {
	proto  string // TCP, UDP, SCTP, ANY, ICMP
	lo, hi int32  // 0 = every port
}

func (p portSpec) String() string {
	switch {
	case p.proto == "ICMP":
		return "ICMP"
	case p.lo == 0 && p.proto == "ANY":
		return "*"
	case p.lo == 0:
		return "*/" + p.proto
	case p.hi > p.lo:
		return fmt.Sprintf("%d-%d/%s", p.lo, p.hi, p.proto)
	}
	return fmt.Sprintf("%d/%s", p.lo, p.proto)
}

// covers reports whether the entry opens port on proto ("" = any protocol).
func (p portSpec) covers(port int32, proto string) bool {
	if p.proto == "ICMP" {
		return false
	}
	if proto != "" && p.proto != "ANY" && p.proto != proto {
		return false
	}
	return p.lo == 0 || (port >= p.lo && port <= p.hi)
}

func parsePortSpec(s string) portSpec {
	if s == "*" {
		return portSpec{proto: "ANY"}
	}
	if s == "ICMP" {
		return portSpec{proto: "ICMP"}
	}
	rng, proto, hasProto := strings.Cut(s, "/")
	if !hasProto {
		proto = "TCP" // a bare number is a standard-policy port
	}
	if rng == "*" {
		return portSpec{proto: proto}
	}
	loS, hiS, _ := strings.Cut(rng, "-")
	lo, _ := strconv.Atoi(loS)
	hi := lo
	if hiS != "" {
		hi, _ = strconv.Atoi(hiS)
	}
	return portSpec{proto: proto, lo: int32(lo), hi: int32(hi)}
}

// intersectPorts is what two allow lists open together: the same protocol
// (ANY matches all) and the overlapping part of the ranges.
func intersectPorts(a, b []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, as := range a {
		x := parsePortSpec(as)
		for _, bs := range b {
			y := parsePortSpec(bs)
			r, ok := x.intersect(y)
			if !ok || seen[r.String()] {
				continue
			}
			seen[r.String()] = true
			out = append(out, r.String())
		}
	}
	sort.Strings(out)
	return out
}

func (p portSpec) intersect(q portSpec) (portSpec, bool) {
	r := portSpec{proto: p.proto, lo: p.lo, hi: p.hi}
	switch {
	case p.proto == q.proto:
	case p.proto == "ANY":
		r.proto = q.proto
	case q.proto == "ANY":
	default:
		return portSpec{}, false
	}
	if q.lo != 0 {
		if r.lo == 0 {
			r.lo, r.hi = q.lo, q.hi
		} else {
			r.lo, r.hi = max(r.lo, q.lo), min(r.hi, q.hi)
			if r.lo > r.hi {
				return portSpec{}, false
			}
		}
	}
	return r, true
}

// portsCover reports whether an allow list opens port on proto.
func portsCover(ports []string, port int32, proto string) bool {
	for _, s := range ports {
		if parsePortSpec(s).covers(port, proto) {
			return true
		}
	}
	return false
}

// DisplayPorts shortens port entries for people: TCP, the usual case, is
// implied; other protocols stay visible.
func DisplayPorts(ports []string) []string {
	out := make([]string, 0, len(ports))
	for _, s := range ports {
		switch {
		case s == "*" || s == "ICMP":
			out = append(out, strings.ToLower(s))
		case strings.HasSuffix(s, "/TCP"):
			out = append(out, strings.TrimSuffix(s, "/TCP"))
		case strings.HasSuffix(s, "/ANY"):
			out = append(out, strings.TrimSuffix(s, "/ANY")+"/any")
		default:
			out = append(out, s)
		}
	}
	return out
}
