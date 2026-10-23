package policy

import (
	"sync"
	"testing"
)

// The web UI evaluates several requests at once against one snapshot, so
// the resolver's cache must survive concurrent use (run with -race).
func TestNetResolverConcurrent(t *testing.T) {
	r := NewNetResolver()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				r.Resolve("localhost")
			}
		}()
	}
	wg.Wait()
	if len(r.cache) != 1 {
		t.Errorf("expected one cached name, got %d entries", len(r.cache))
	}
}
