package hashflood

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

// makeQuery construit une query string de n paramètres `kN=v`.
func makeQuery(n int) string {
	if n == 0 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte('&')
		}
		fmt.Fprintf(&b, "k%d=v", i)
	}
	return b.String()
}

// --- reproducer ------------------------------------------------------

// TestReproducer_HashFlood_WithoutMitigation prouve qu'un client peut
// envoyer une URL avec un grand nombre de paramètres et que le handler
// upstream les reçoit (le parsing par r.URL.Query() est facturé au
// serveur).
func TestReproducer_HashFlood_WithoutMitigation(t *testing.T) {
	t.Parallel()
	seen := 0
	upstream := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = len(r.URL.Query())
	})
	srv := httptest.NewServer(upstream)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/?" + makeQuery(5000))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("got %d, want 200 (proves attack reaches upstream)", resp.StatusCode)
	}
	if seen < 5000 {
		t.Fatalf("upstream saw %d params, expected >= 5000", seen)
	}
}

// TestReproducer_HashFlood_WithMitigation_Blocks prouve que la
// mitigation rejette la même requête en HTTP 400 et que l'upstream
// n'est jamais appelé.
func TestReproducer_HashFlood_WithMitigation_Blocks(t *testing.T) {
	t.Parallel()
	upstreamCalled := false
	upstream := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		upstreamCalled = true
	})
	lim := newLimiter(t, Config{Enabled: true, MaxQueryParams: 64, OnError: "allow"})
	srv := httptest.NewServer(lim.Middleware(upstream))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/?" + makeQuery(5000))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", resp.StatusCode)
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

func TestCountParams(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"a=1", 1},
		{"a=1&b=2", 2},
		{"a&b&c", 3},
		{"a=&", 2}, // trailing & counted (matches ParseQuery behavior of empty key)
		{"a=1&b=2&c=3&d=4", 4},
	}
	for _, tc := range cases {
		if got := countParams(tc.in); got != tc.want {
			t.Errorf("countParams(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestEvaluate_DisabledPassesThrough(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: false})
	if got := lim.Evaluate(makeQuery(10_000)); got != Allow {
		t.Fatalf("disabled: got %v, want Allow", got)
	}
	ev, bl, _ := lim.Metrics()
	if ev != 0 || bl != 0 {
		t.Fatalf("disabled should not touch counters: ev=%d bl=%d", ev, bl)
	}
}

func TestEvaluate_QueryParamCap(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, MaxQueryParams: 10, OnError: "allow"})
	if got := lim.Evaluate(makeQuery(10)); got != Allow {
		t.Fatalf("10 params at cap: got %v, want Allow", got)
	}
	if got := lim.Evaluate(makeQuery(11)); got != Deny {
		t.Fatalf("11 params: got %v, want Deny", got)
	}
	if got := lim.Evaluate(""); got != Allow {
		t.Fatalf("empty query: got %v, want Allow", got)
	}
}

func TestUpdate_AppliesNewConfig(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, MaxQueryParams: 100, OnError: "allow"})
	if got := lim.Evaluate(makeQuery(50)); got != Allow {
		t.Fatalf("before: got %v, want Allow", got)
	}
	if err := lim.Update(Config{Enabled: true, MaxQueryParams: 10, OnError: "allow"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got := lim.Evaluate(makeQuery(50)); got != Deny {
		t.Fatalf("after: got %v, want Deny", got)
	}
}

func TestUpdate_RejectsInvalidKeepsOld(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, MaxQueryParams: 10, OnError: "allow"})
	if err := lim.Update(Config{Enabled: true, MaxQueryParams: 0}); err == nil {
		t.Fatal("Update should have rejected MaxQueryParams=0")
	}
	if lim.Config().MaxQueryParams != 10 {
		t.Fatalf("old config should remain, got %d", lim.Config().MaxQueryParams)
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
		{"ok", Config{Enabled: true, MaxQueryParams: 100, OnError: "deny"}, false},
		{"bad on_error", Config{OnError: "yolo"}, true},
		{"count 0 enabled", Config{Enabled: true, MaxQueryParams: 0, OnError: "allow"}, true},
		{"count too high", Config{Enabled: true, MaxQueryParams: 100_000, OnError: "allow"}, true},
		{"empty on_error ok", Config{Enabled: true, MaxQueryParams: 10}, false},
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
		w.WriteHeader(204)
	})
	lim := newLimiter(t, Config{Enabled: true, MaxQueryParams: 10, OnError: "allow"})
	srv := httptest.NewServer(lim.Middleware(next))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/?a=1&b=2&c=3")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("got %d, want 204", resp.StatusCode)
	}
	if !called {
		t.Fatal("next should have been called")
	}
}
