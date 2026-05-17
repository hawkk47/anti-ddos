package largeheader

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"anti-ddos/proxy/internal/metrics"
)

// --- helpers ---------------------------------------------------------

func newLimiter(t *testing.T, cfg Config) *Limiter {
	t.Helper()
	l, err := New(cfg, metrics.NewInMemory())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l
}

func makeHeader(count, valueBytes int) http.Header {
	h := http.Header{}
	for i := 0; i < count; i++ {
		h.Set("X-Pad-"+strings.Repeat("a", 1)+itoa(i), strings.Repeat("v", valueBytes))
	}
	return h
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

// --- reproducer ------------------------------------------------------

// TestReproducer_LargeHeader_WithoutMitigation prouve qu'un client peut
// envoyer un volume arbitraire de headers/valeurs et que le handler
// upstream le voit sans broncher.
func TestReproducer_LargeHeader_WithoutMitigation(t *testing.T) {
	t.Parallel()
	seen := 0
	upstream := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = len(r.Header)
	})
	srv := httptest.NewServer(upstream)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("X-Big", strings.Repeat("A", 100_000))
	for i := 0; i < 200; i++ {
		req.Header.Set("X-N-"+itoa(i), "x")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("got %d, want 200 (proves attack reaches upstream)", resp.StatusCode)
	}
	if seen < 200 {
		t.Fatalf("upstream saw %d headers, expected >= 200", seen)
	}
}

// TestReproducer_LargeHeader_WithMitigation_Blocks prouve que la
// mitigation rejette la même requête en HTTP 431.
func TestReproducer_LargeHeader_WithMitigation_Blocks(t *testing.T) {
	t.Parallel()
	upstreamCalled := false
	upstream := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		upstreamCalled = true
	})
	lim := newLimiter(t, Config{
		Enabled:        true,
		MaxHeaderCount: 50,
		MaxValueBytes:  4096,
		OnError:        "allow",
	})
	srv := httptest.NewServer(lim.Middleware(upstream))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("X-Big", strings.Repeat("A", 100_000)) // value too large
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("got %d, want 431", resp.StatusCode)
	}
	if upstreamCalled {
		t.Fatal("upstream should NOT have been called")
	}
	_, blocked, _ := lim.Metrics()
	if blocked == 0 {
		t.Fatal("blocked counter should have incremented")
	}
}

// --- unit ------------------------------------------------------------

func TestEvaluate_DisabledPassesThrough(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: false})
	if got := lim.Evaluate(makeHeader(1000, 1_000_000)); got != Allow {
		t.Fatalf("disabled: got %v, want Allow", got)
	}
	ev, bl, _ := lim.Metrics()
	if ev != 0 || bl != 0 {
		t.Fatalf("disabled should not touch counters: ev=%d bl=%d", ev, bl)
	}
}

func TestEvaluate_HeaderCountCap(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, MaxHeaderCount: 10, MaxValueBytes: 1024, OnError: "allow"})
	if got := lim.Evaluate(makeHeader(5, 4)); got != Allow {
		t.Fatalf("5 headers: got %v, want Allow", got)
	}
	if got := lim.Evaluate(makeHeader(50, 4)); got != Deny {
		t.Fatalf("50 headers: got %v, want Deny", got)
	}
}

func TestEvaluate_ValueBytesCap(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, MaxHeaderCount: 1000, MaxValueBytes: 16, OnError: "allow"})
	h := http.Header{}
	h.Set("X-Ok", strings.Repeat("a", 10))
	if got := lim.Evaluate(h); got != Allow {
		t.Fatalf("small value: got %v, want Allow", got)
	}
	h.Set("X-Big", strings.Repeat("a", 1024))
	if got := lim.Evaluate(h); got != Deny {
		t.Fatalf("big value: got %v, want Deny", got)
	}
}

func TestUpdate_AppliesNewConfig(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, MaxHeaderCount: 100, MaxValueBytes: 100, OnError: "allow"})
	if got := lim.Evaluate(makeHeader(20, 4)); got != Allow {
		t.Fatalf("before: got %v, want Allow", got)
	}
	if err := lim.Update(Config{Enabled: true, MaxHeaderCount: 5, MaxValueBytes: 100, OnError: "allow"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got := lim.Evaluate(makeHeader(20, 4)); got != Deny {
		t.Fatalf("after: got %v, want Deny", got)
	}
}

func TestUpdate_RejectsInvalidKeepsOld(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, MaxHeaderCount: 10, MaxValueBytes: 100, OnError: "allow"})
	if err := lim.Update(Config{Enabled: true, MaxHeaderCount: 0, MaxValueBytes: 100}); err == nil {
		t.Fatal("Update should have rejected MaxHeaderCount=0")
	}
	if lim.Config().MaxHeaderCount != 10 {
		t.Fatalf("old config should remain, got %d", lim.Config().MaxHeaderCount)
	}
	_, _, errs := lim.Metrics()
	if errs == 0 {
		t.Fatal("errors_total should have incremented")
	}
}

func TestConfig_Validate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"disabled ignores limits", Config{Enabled: false, OnError: "allow"}, false},
		{"ok", Config{Enabled: true, MaxHeaderCount: 100, MaxValueBytes: 8192, OnError: "deny"}, false},
		{"bad on_error", Config{OnError: "yolo"}, true},
		{"count 0 enabled", Config{Enabled: true, MaxHeaderCount: 0, MaxValueBytes: 100, OnError: "allow"}, true},
		{"count too high", Config{Enabled: true, MaxHeaderCount: 100_000, MaxValueBytes: 100, OnError: "allow"}, true},
		{"value 0 enabled", Config{Enabled: true, MaxHeaderCount: 10, MaxValueBytes: 0, OnError: "allow"}, true},
		{"value too high", Config{Enabled: true, MaxHeaderCount: 10, MaxValueBytes: 100 * 1024 * 1024, OnError: "allow"}, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("got err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func BenchmarkEvaluate_Allow(b *testing.B) {
	lim, _ := New(Config{Enabled: true, MaxHeaderCount: 100, MaxValueBytes: 4096, OnError: "allow"}, metrics.NewInMemory())
	h := makeHeader(10, 32)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lim.Evaluate(h)
	}
}

func BenchmarkEvaluate_Deny(b *testing.B) {
	lim, _ := New(Config{Enabled: true, MaxHeaderCount: 5, MaxValueBytes: 16, OnError: "allow"}, metrics.NewInMemory())
	h := makeHeader(50, 32)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lim.Evaluate(h)
	}
}
