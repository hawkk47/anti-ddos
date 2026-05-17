package rangeamp

import (
	"fmt"
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

// makeRangeHeader construit un header Range avec n ranges qui se
// recouvrent, à la manière de l'exploit Apache Killer.
func makeRangeHeader(n int) string {
	if n == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("bytes=")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "0-%d", i)
	}
	return b.String()
}

// --- reproducer ------------------------------------------------------

// TestReproducer_RangeAmp_WithoutMitigation prouve qu'un client peut
// envoyer un Range header avec un grand nombre de ranges et que
// l'upstream le reçoit intact (charge à lui de produire le multipart).
func TestReproducer_RangeAmp_WithoutMitigation(t *testing.T) {
	t.Parallel()
	var seen string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Range")
		w.WriteHeader(200)
	})
	srv := httptest.NewServer(upstream)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/big.bin", nil)
	req.Header.Set("Range", makeRangeHeader(1000))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("got %d, want 200 (proves attack reaches upstream)", resp.StatusCode)
	}
	if strings.Count(seen, ",") < 999 {
		t.Fatalf("upstream saw only %d commas, expected >= 999", strings.Count(seen, ","))
	}
}

// TestReproducer_RangeAmp_WithMitigation_Blocks prouve que la
// mitigation rejette la même requête en HTTP 416 et que l'upstream
// n'est jamais appelé.
func TestReproducer_RangeAmp_WithMitigation_Blocks(t *testing.T) {
	t.Parallel()
	upstreamCalled := false
	upstream := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		upstreamCalled = true
	})
	lim := newLimiter(t, Config{Enabled: true, MaxRanges: 8, OnError: "allow"})
	srv := httptest.NewServer(lim.Middleware(upstream))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/big.bin", nil)
	req.Header.Set("Range", makeRangeHeader(1000))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("got %d, want 416", resp.StatusCode)
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

func TestCountRanges(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"bytes=0-100", 1},
		{"bytes=0-100,200-300", 2},
		{"bytes=0-,0-1,0-2", 3},
		{"bytes=0-,0-1,0-2,0-3,0-4", 5},
	}
	for _, tc := range cases {
		if got := countRanges(tc.in); got != tc.want {
			t.Errorf("countRanges(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestEvaluate_DisabledPassesThrough(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: false})
	if got := lim.Evaluate(makeRangeHeader(10_000)); got != Allow {
		t.Fatalf("disabled: got %v, want Allow", got)
	}
	ev, bl, _ := lim.Metrics()
	if ev != 0 || bl != 0 {
		t.Fatalf("disabled should not touch counters: ev=%d bl=%d", ev, bl)
	}
}

func TestEvaluate_RangeCap(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, MaxRanges: 8, OnError: "allow"})
	if got := lim.Evaluate(makeRangeHeader(8)); got != Allow {
		t.Fatalf("8 ranges at cap: got %v, want Allow", got)
	}
	if got := lim.Evaluate(makeRangeHeader(9)); got != Deny {
		t.Fatalf("9 ranges: got %v, want Deny", got)
	}
	if got := lim.Evaluate(""); got != Allow {
		t.Fatalf("no Range header: got %v, want Allow", got)
	}
	if got := lim.Evaluate("bytes=0-1023"); got != Allow {
		t.Fatalf("single legit range: got %v, want Allow", got)
	}
}

func TestUpdate_AppliesNewConfig(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, MaxRanges: 100, OnError: "allow"})
	if got := lim.Evaluate(makeRangeHeader(50)); got != Allow {
		t.Fatalf("before: got %v, want Allow", got)
	}
	if err := lim.Update(Config{Enabled: true, MaxRanges: 8, OnError: "allow"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got := lim.Evaluate(makeRangeHeader(50)); got != Deny {
		t.Fatalf("after: got %v, want Deny", got)
	}
}

func TestUpdate_RejectsInvalidKeepsOld(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, MaxRanges: 8, OnError: "allow"})
	if err := lim.Update(Config{Enabled: true, MaxRanges: 0}); err == nil {
		t.Fatal("Update should have rejected MaxRanges=0")
	}
	if lim.Config().MaxRanges != 8 {
		t.Fatalf("old config should remain, got %d", lim.Config().MaxRanges)
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
		{"ok", Config{Enabled: true, MaxRanges: 8, OnError: "deny"}, false},
		{"bad on_error", Config{OnError: "yolo"}, true},
		{"count 0 enabled", Config{Enabled: true, MaxRanges: 0, OnError: "allow"}, true},
		{"count too high", Config{Enabled: true, MaxRanges: 10_000, OnError: "allow"}, true},
		{"empty on_error ok", Config{Enabled: true, MaxRanges: 8}, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestMiddleware_AllowsLegit(t *testing.T) {
	t.Parallel()
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(206)
	})
	lim := newLimiter(t, Config{Enabled: true, MaxRanges: 8, OnError: "allow"})
	srv := httptest.NewServer(lim.Middleware(next))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/x", nil)
	req.Header.Set("Range", "bytes=0-1023")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 206 {
		t.Fatalf("got %d, want 206", resp.StatusCode)
	}
	if !called {
		t.Fatal("next should have been called")
	}
}

func TestMiddleware_PassesThroughWhenNoRangeHeader(t *testing.T) {
	t.Parallel()
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(200)
	})
	lim := newLimiter(t, Config{Enabled: true, MaxRanges: 8, OnError: "allow"})
	srv := httptest.NewServer(lim.Middleware(next))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/x")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if !called || resp.StatusCode != 200 {
		t.Fatalf("expected pass-through 200, got %d called=%v", resp.StatusCode, called)
	}
}
