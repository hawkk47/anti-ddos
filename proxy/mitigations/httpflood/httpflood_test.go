package httpflood

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

// fakeClock : horloge contrôlée pour tests déterministes.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(0, 0)} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// newLimiterWithClock construit un Limiter dont l'horloge est
// contrôlée.
func newLimiterWithClock(t *testing.T, cfg Config, clk *fakeClock) *Limiter {
	t.Helper()
	lim, err := New(cfg, metrics.NewInMemory())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	lim.now = clk.now
	return lim
}

// ---------------------------------------------------------------
// Reproducer : avant la mitigation, 1000 requêtes en burst frappent
// toutes l'upstream. Avec la mitigation activée (rps=5, burst=10),
// seules ~10 doivent passer.
// ---------------------------------------------------------------

func TestReproducer_FloodWithoutMitigation(t *testing.T) {
	var hits atomic.Uint64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Pas de mitigation : tout passe.
	for i := 0; i < 200; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "127.0.0.1:1000"
		rec := httptest.NewRecorder()
		// On invoque directement le handler upstream (simulant
		// l'absence de mitigation devant).
		upstream.Config.Handler.ServeHTTP(rec, req)
	}
	if hits.Load() != 200 {
		t.Fatalf("repro: expected 200 hits, got %d", hits.Load())
	}
}

func TestReproducer_FloodWithMitigation_Blocks(t *testing.T) {
	clk := newFakeClock()
	lim := newLimiterWithClock(t, Config{
		Enabled:           true,
		RequestsPerSecond: 5,
		Burst:             10,
		OnError:           "deny",
	}, clk)

	var hits atomic.Uint64
	h := lim.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))

	allowed := 0
	denied := 0
	for i := 0; i < 200; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "127.0.0.1:9000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		switch rec.Code {
		case http.StatusOK:
			allowed++
		case http.StatusTooManyRequests:
			denied++
		default:
			t.Fatalf("unexpected status: %d", rec.Code)
		}
	}
	if allowed != 10 {
		t.Errorf("allowed: got %d, want 10 (burst)", allowed)
	}
	if denied != 190 {
		t.Errorf("denied: got %d, want 190", denied)
	}
	if hits.Load() != 10 {
		t.Errorf("upstream hits: got %d, want 10", hits.Load())
	}
}

// ---------------------------------------------------------------
// Refill au rythme configuré.
// ---------------------------------------------------------------

func TestMiddleware_RefillsOverTime(t *testing.T) {
	clk := newFakeClock()
	lim := newLimiterWithClock(t, Config{
		Enabled:           true,
		RequestsPerSecond: 10, // 1 token par 100 ms
		Burst:             1,
		OnError:           "deny",
	}, clk)

	ip := "127.0.0.1"
	if d := lim.Evaluate(ip); d != Allow {
		t.Fatalf("first req should be allowed")
	}
	if d := lim.Evaluate(ip); d != Deny {
		t.Fatalf("second immediate req should be denied")
	}
	clk.advance(120 * time.Millisecond) // > 100 ms ⇒ 1 token restauré
	if d := lim.Evaluate(ip); d != Allow {
		t.Errorf("after refill: should be allowed")
	}
}

// ---------------------------------------------------------------
// Pass-through quand désactivé.
// ---------------------------------------------------------------

func TestMiddleware_DisabledPassThrough(t *testing.T) {
	clk := newFakeClock()
	lim := newLimiterWithClock(t, Config{Enabled: false}, clk)
	for i := 0; i < 1000; i++ {
		if lim.Evaluate("1.2.3.4") != Allow {
			t.Fatalf("disabled limiter must always allow")
		}
	}
	if lim.Metrics().(metrics.Snapshotter) == nil {
		t.Fatal("expected snapshotter registry")
	}
}

// ---------------------------------------------------------------
// IPs distinctes : compteurs indépendants.
// ---------------------------------------------------------------

func TestMiddleware_PerIPIsolation(t *testing.T) {
	clk := newFakeClock()
	lim := newLimiterWithClock(t, Config{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             2,
		OnError:           "deny",
	}, clk)
	// IP A : 2 tokens consommés.
	if lim.Evaluate("10.0.0.1") != Allow {
		t.Fatal("A1")
	}
	if lim.Evaluate("10.0.0.1") != Allow {
		t.Fatal("A2")
	}
	if lim.Evaluate("10.0.0.1") != Deny {
		t.Fatal("A3 should deny")
	}
	// IP B inchangée : doit toujours pouvoir consommer.
	if lim.Evaluate("10.0.0.2") != Allow {
		t.Fatal("B1")
	}
}

// ---------------------------------------------------------------
// Fail-closed : RemoteAddr non parsable ⇒ 503 si OnError="deny".
// ---------------------------------------------------------------

func TestMiddleware_FailClosedOnMissingIP(t *testing.T) {
	clk := newFakeClock()
	lim := newLimiterWithClock(t, Config{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             100,
		OnError:           "deny",
	}, clk)
	h := lim.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "bogus" // pas un host:port
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("got %d, want 503", rec.Code)
	}
}

func TestMiddleware_FailOpenOnMissingIP(t *testing.T) {
	clk := newFakeClock()
	lim := newLimiterWithClock(t, Config{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             100,
		OnError:           "allow",
	}, clk)
	h := lim.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "bogus"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("got %d, want 200 (fail-open)", rec.Code)
	}
}

// ---------------------------------------------------------------
// Hot-reload : Update remplace la config sans reset des buckets.
// ---------------------------------------------------------------

func TestUpdate_HotReload(t *testing.T) {
	clk := newFakeClock()
	lim := newLimiterWithClock(t, Config{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             1,
		OnError:           "deny",
	}, clk)
	if lim.Evaluate("ip") != Allow {
		t.Fatal("first should allow")
	}
	if lim.Evaluate("ip") != Deny {
		t.Fatal("second should deny")
	}
	// Reload : burst plus large.
	if err := lim.Update(Config{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             100,
		OnError:           "deny",
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	// Refill rapide (1s @ 100 rps ⇒ bucket plein).
	clk.advance(time.Second)
	if lim.Evaluate("ip") != Allow {
		t.Errorf("after reload + refill: should allow")
	}
}

// ---------------------------------------------------------------
// Validate.
// ---------------------------------------------------------------

func TestConfig_Validate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"disabled-zero", Config{}, false},
		{"ok", Config{Enabled: true, RequestsPerSecond: 10, Burst: 20, OnError: "deny"}, false},
		{"rps zero", Config{Enabled: true, RequestsPerSecond: 0, Burst: 1}, true},
		{"burst zero", Config{Enabled: true, RequestsPerSecond: 1, Burst: 0}, true},
		{"on_error invalid", Config{OnError: "panic"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate err = %v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------
// Benchmark.
// ---------------------------------------------------------------

func BenchmarkEvaluate_Allow(b *testing.B) {
	lim, _ := New(Config{
		Enabled:           true,
		RequestsPerSecond: 1_000_000,
		Burst:             1_000_000,
		OnError:           "deny",
	}, metrics.NewInMemory())
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = lim.Evaluate("127.0.0.1")
	}
}

func BenchmarkEvaluate_Deny(b *testing.B) {
	lim, _ := New(Config{
		Enabled:           true,
		RequestsPerSecond: 0.000001,
		Burst:             1,
		OnError:           "deny",
	}, metrics.NewInMemory())
	// Vide le bucket initial.
	lim.Evaluate("127.0.0.1")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = lim.Evaluate("127.0.0.1")
	}
}
