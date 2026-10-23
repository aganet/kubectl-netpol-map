package policy

import (
	"strings"
	"testing"
)

func TestIntersectPorts(t *testing.T) {
	cases := []struct{ a, b, want string }{
		{"*", "8080/TCP", "8080/TCP"},                       // any port, any protocol
		{"*/TCP", "53/UDP", ""},                             // any TCP port is not UDP 53
		{"8080/TCP", "8080/UDP", ""},                        // same number, other protocol
		{"53/ANY", "53/UDP", "53/UDP"},                      // Cilium ANY narrows to the other side
		{"8000-9000/TCP", "8500/TCP", "8500/TCP"},           // a number inside a range
		{"8000-9000/TCP", "8900-9500/TCP", "8900-9000/TCP"}, // overlapping ranges
		{"8000-9000/TCP", "9001/TCP", ""},                   // just outside
		{"ICMP", "*", "ICMP"},                               // ICMP is not an L4 port
		{"ICMP", "80/TCP", ""},
	}
	for _, c := range cases {
		got := strings.Join(intersectPorts([]string{c.a}, []string{c.b}), ",")
		if got != c.want {
			t.Errorf("intersect(%s, %s) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
	if !portsCover([]string{"8000-9000/TCP"}, 8500, "TCP") || portsCover([]string{"8000-9000/TCP"}, 8500, "UDP") || portsCover([]string{"ICMP"}, 80, "") {
		t.Error("portsCover must honour the range and the protocol")
	}
	if got := strings.Join(DisplayPorts([]string{"8080/TCP", "53/UDP", "53/ANY", "*", "ICMP"}), " "); got != "8080 53/UDP 53/any * icmp" {
		t.Errorf("DisplayPorts: %q", got)
	}
}
