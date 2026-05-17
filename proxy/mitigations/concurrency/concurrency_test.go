package concurrency

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

func newLimiter(t *testing.T, cfg Config) *Limiter {
	t.Helper()
	l, err := New(cfg, metrics.NewInMemory())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l
}

// blockingHandler retourne un handler qui bloque jusqu'à release puis
// répond 204. inflight est incrémenté quand le handler est entré.
func blockingHandler(release <-chan struct{}, inflight *atomic.Int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		inflight.Add(1)
		defer inflight.Add(-1)
		<-release
		w.WriteHeader(204)
	})
}

// --- reproducer ------------------------------------------------------

// TestReproducer_ConcurrencyCap_WithoutMitigation prouve qu'un upstream
// non protégé voit toutes les requêtes simultanées arriver dans son
// handler — i.e. un attaquant peut saturer le pool de goroutines sans
// que la stdlib ne s'en émeuve.
func TestReproducer_ConcurrencyCap_WithoutMitigation(t *testing.T) {
	t.Parallel()
	const N = 50
	release := make(chan struct{})
	var peak atomic.Int64
	var cur atomic.Int64

	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		c := cur.Add(1)
		defer cur.Add(-1)
		// piste manuelle du pic.
		for {
			p := peak.Load()
			if c <= p || peak.CompareAndSwap(p, c) {
				break
			}
		}
		<-release
		w.WriteHeader(204)
	})
	srv := httptest.NewServer(upstream)
	defer srv.Close()

	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(srv.URL)
			if err != nil {
				return
			}
			resp.Body.Close()
		}()
	}
	// attendre que toutes les requêtes soient entrées dans le handler.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cur.Load() >= int64(N) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if peak.Load() < int64(N) {
		t.Fatalf("expected pic >= %d, got %d (attack does not reach handler)", N, peak.Load())
	}
	close(release)
	wg.Wait()
}

// TestReproducer_ConcurrencyCap_WithMitigation_Sheds prouve que le cap
// limite l'in-flight et que les requêtes en surnombre reçoivent 503.
func TestReproducer_ConcurrencyCap_WithMitigation_Sheds(t *testing.T) {
	t.Parallel()
	const Cap = 5
	const N = 50

	release := make(chan struct{})
	var inflight atomic.Int64
	upstream := blockingHandler(release, &inflight)
	lim := newLimiter(t, Config{Enabled: true, MaxInFlight: Cap, OnError: "allow"})
	srv := httptest.NewServer(lim.Middleware(upstream))
	defer srv.Close()

	var (
		wg          sync.WaitGroup
		ok503, ok2x atomic.Int64
	)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(srv.URL)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusServiceUnavailable:
				ok503.Add(1)
			case http.StatusNoContent:
				ok2x.Add(1)
			}
		}()
	}

	// Laisse aux goroutines le temps de remplir la sémaphore.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if inflight.Load() >= int64(Cap) && ok503.Load() > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if got := inflight.Load(); got > int64(Cap) {
		t.Fatalf("inflight > cap: got %d, cap=%d", got, Cap)
	}
	if ok503.Load() == 0 {
		t.Fatalf("expected at least one 503; got ok2x=%d ok503=%d", ok2x.Load(), ok503.Load())
	}
	close(release)
	wg.Wait()

	_, blocked, _ := lim.Metrics()
	if blocked == 0 {
		t.Fatal("blocked counter should have incremented")
	}
}

// --- unit ------------------------------------------------------------

func TestEvaluate_DisabledPassesThrough(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: false})
	// Acquérir N fois sans release ne doit jamais bloquer (pass-through).
	for i := 0; i < 1000; i++ {
		slot, ok := lim.tryAcquire()
		if !ok {
			t.Fatalf("disabled: tryAcquire #%d returned !ok", i)
		}
		lim.release(slot)
	}
	ev, bl, _ := lim.Metrics()
	if ev != 0 || bl != 0 {
		t.Fatalf("disabled should not touch counters: ev=%d bl=%d", ev, bl)
	}
}

func TestTryAcquire_RespectsCap(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, MaxInFlight: 3, OnError: "allow"})
	slots := make([]*chan struct{}, 0, 3)
	for i := 0; i < 3; i++ {
		s, ok := lim.tryAcquire()
		if !ok {
			t.Fatalf("acquire #%d failed", i)
		}
		slots = append(slots, s)
	}
	if _, ok := lim.tryAcquire(); ok {
		t.Fatal("4th acquire should fail (cap=3)")
	}
	// release one, re-acquire should succeed.
	lim.release(slots[0])
	s, ok := lim.tryAcquire()
	if !ok {
		t.Fatal("after release, acquire should succeed")
	}
	slots[0] = s
	// cleanup
	for _, s := range slots {
		lim.release(s)
	}
}

func TestUpdate_GrowingCapAllowsMore(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, MaxInFlight: 2, OnError: "allow"})
	s1, _ := lim.tryAcquire()
	s2, _ := lim.tryAcquire()
	if _, ok := lim.tryAcquire(); ok {
		t.Fatal("3rd should fail at cap=2")
	}
	if err := lim.Update(Config{Enabled: true, MaxInFlight: 10, OnError: "allow"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	// Après reload, le nouveau canal est vide → on doit pouvoir prendre
	// 10 slots. Les anciens slots s1/s2 sont sur l'ancien canal et
	// n'occupent rien sur le nouveau.
	newSlots := make([]*chan struct{}, 0, 10)
	for i := 0; i < 10; i++ {
		s, ok := lim.tryAcquire()
		if !ok {
			t.Fatalf("after Update cap=10, acquire #%d failed", i)
		}
		newSlots = append(newSlots, s)
	}
	if _, ok := lim.tryAcquire(); ok {
		t.Fatal("11th should fail at cap=10")
	}
	// release sur ancien canal : ne doit pas affecter le nouveau.
	lim.release(s1)
	lim.release(s2)
	if _, ok := lim.tryAcquire(); ok {
		t.Fatal("after releasing OLD slots, new cap should still be full")
	}
	for _, s := range newSlots {
		lim.release(s)
	}
}

func TestUpdate_RejectsInvalidKeepsOld(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, MaxInFlight: 5, OnError: "allow"})
	if err := lim.Update(Config{Enabled: true, MaxInFlight: 0}); err == nil {
		t.Fatal("Update should reject MaxInFlight=0")
	}
	if got := lim.Config().MaxInFlight; got != 5 {
		t.Fatalf("old config should remain, got %d", got)
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
		{"ok", Config{Enabled: true, MaxInFlight: 100, OnError: "deny"}, false},
		{"bad on_error", Config{OnError: "yolo"}, true},
		{"cap 0 enabled", Config{Enabled: true, MaxInFlight: 0, OnError: "allow"}, true},
		{"cap too high", Config{Enabled: true, MaxInFlight: 2_000_000, OnError: "allow"}, true},
		{"empty on_error ok", Config{Enabled: true, MaxInFlight: 10}, false},
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

func TestMiddleware_AllowsUnderCap(t *testing.T) {
	t.Parallel()
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(200)
	})
	lim := newLimiter(t, Config{Enabled: true, MaxInFlight: 10, OnError: "allow"})
	srv := httptest.NewServer(lim.Middleware(next))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || !called {
		t.Fatalf("expected 200/called, got %d called=%v", resp.StatusCode, called)
	}
}

func TestMiddleware_Returns503AndRetryAfter(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	var inflight atomic.Int64
	upstream := blockingHandler(release, &inflight)
	lim := newLimiter(t, Config{Enabled: true, MaxInFlight: 1, OnError: "allow"})
	srv := httptest.NewServer(lim.Middleware(upstream))
	// close(release) AVANT srv.Close() pour libérer la requête bloquée.
	defer srv.Close()
	defer close(release)

	// Première requête prend le seul slot.
	first := make(chan struct{})
	go func() {
		resp, err := http.Get(srv.URL)
		if err == nil {
			resp.Body.Close()
		}
		close(first)
	}()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && inflight.Load() == 0 {
		time.Sleep(time.Millisecond)
	}

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("2nd Get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", resp.StatusCode)
	}
	if ra := resp.Header.Get("Retry-After"); ra == "" {
		t.Fatal("Retry-After header missing on 503")
	}
	_ = first
}

func TestInFlight_ReflectsAcquisitions(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, MaxInFlight: 3, OnError: "allow"})
	if lim.InFlight() != 0 {
		t.Fatalf("initial InFlight: got %d, want 0", lim.InFlight())
	}
	s1, _ := lim.tryAcquire()
	if lim.InFlight() != 1 {
		t.Fatalf("after 1 acquire: got %d, want 1", lim.InFlight())
	}
	lim.release(s1)
	if lim.InFlight() != 0 {
		t.Fatalf("after release: got %d, want 0", lim.InFlight())
	}
}

// BenchmarkMiddleware_AllowsHotPath mesure la latence ajoutée par la
// mitigation sur le chemin "slot dispo".
func BenchmarkMiddleware_AllowsHotPath(b *testing.B) {
	lim, err := New(Config{Enabled: true, MaxInFlight: 1024, OnError: "allow"}, metrics.NewInMemory())
	if err != nil {
		b.Fatal(err)
	}
	noop := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	mw := lim.Middleware(noop)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mw.ServeHTTP(w, req)
	}
}

// BenchmarkMiddleware_Disabled : pass-through, baseline.
func BenchmarkMiddleware_Disabled(b *testing.B) {
	lim, err := New(Config{Enabled: false}, metrics.NewInMemory())
	if err != nil {
		b.Fatal(err)
	}
	noop := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	mw := lim.Middleware(noop)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mw.ServeHTTP(w, req)
	}
}
