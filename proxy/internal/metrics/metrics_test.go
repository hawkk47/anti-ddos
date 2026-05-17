package metrics

import (
	"sync"
	"testing"
)

func TestCounter_Inc(t *testing.T) {
	r := NewInMemory()
	c := r.Counter("foo")
	c.Inc()
	c.Add(4)
	if got := c.Value(); got != 5 {
		t.Errorf("got %d want 5", got)
	}
}

func TestRegistry_Stable(t *testing.T) {
	r := NewInMemory()
	a := r.Counter("foo")
	b := r.Counter("foo")
	a.Inc()
	if b.Value() != 1 {
		t.Errorf("Counter(name) must be stable across calls")
	}
}

func TestHistogram_Concurrent(t *testing.T) {
	r := NewInMemory()
	h := r.Histogram("d")
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.Observe(0.01)
		}()
	}
	wg.Wait()
	if h.Count() != 100 {
		t.Errorf("count: got %d want 100", h.Count())
	}
}
