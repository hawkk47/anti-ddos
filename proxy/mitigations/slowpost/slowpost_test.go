package slowpost

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

// fakeClock : horloge déterministe pour tester les seuils de temps.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// dripReader émet p[:1] à chaque appel et fait avancer l'horloge de
// `interval` entre chaque octet — simule un client slow-post.
type dripReader struct {
	src      []byte
	pos      int
	clock    *fakeClock
	interval time.Duration
}

func (d *dripReader) Read(p []byte) (int, error) {
	if d.pos >= len(d.src) {
		return 0, io.EOF
	}
	if d.pos > 0 {
		d.clock.Advance(d.interval)
	}
	p[0] = d.src[d.pos]
	d.pos++
	return 1, nil
}

func (d *dripReader) Close() error { return nil }

func newLimiter(t *testing.T, cfg Config, clk *fakeClock) *Limiter {
	t.Helper()
	l, err := New(cfg, metrics.NewInMemory())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if clk != nil {
		l.now = clk.Now
	}
	return l
}

// --- reproducer ------------------------------------------------------

// TestReproducer_SlowPost_WithoutMitigation prouve qu'en l'absence de
// la mitigation, un body envoyé à 10 o/s pendant 10 s atteint le
// handler upstream.
func TestReproducer_SlowPost_WithoutMitigation(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(0, 0)}
	receivedBytes := 0
	upstream := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedBytes = len(b)
	})

	// Simule directement un POST en appelant le handler (pas de
	// httptest.NewServer pour rester indépendant du transport).
	req := httptest.NewRequest(http.MethodPost, "/", &dripReader{
		src: bytes.Repeat([]byte("a"), 100), clock: clk, interval: 100 * time.Millisecond,
	})
	req.ContentLength = 100
	rec := httptest.NewRecorder()
	upstream.ServeHTTP(rec, req)

	if receivedBytes != 100 {
		t.Fatalf("upstream got %d bytes, want 100 (attack reaches upstream)", receivedBytes)
	}
}

// TestReproducer_SlowPost_WithMitigation_Blocks prouve que la même
// charge est interrompue en HTTP 4xx.
func TestReproducer_SlowPost_WithMitigation_Blocks(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(0, 0)}
	upstreamReadErr := error(nil)
	upstreamBytes := 0
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		upstreamReadErr = err
		upstreamBytes = len(b)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// 50 octets/s minimum, grace 1 s. Le client envoie 10 o/s ⇒ violation.
	lim := newLimiter(t, Config{
		Enabled:           true,
		MaxBodyBytes:      10 * 1024,
		MinBytesPerSecond: 50,
		GracePeriod:       time.Second,
		OnError:           "allow",
	}, clk)

	req := httptest.NewRequest(http.MethodPost, "/", &dripReader{
		src: bytes.Repeat([]byte("a"), 500), clock: clk, interval: 100 * time.Millisecond,
	})
	req.ContentLength = 500
	rec := httptest.NewRecorder()
	lim.Middleware(upstream).ServeHTTP(rec, req)

	if upstreamReadErr == nil {
		t.Fatal("upstream should have received a Read error from slowReader")
	}
	if !errors.Is(upstreamReadErr, ErrSlowPost) {
		t.Fatalf("got error %v, want ErrSlowPost wrapped", upstreamReadErr)
	}
	if upstreamBytes >= 500 {
		t.Fatalf("upstream got %d bytes, want < 500 (interrupted)", upstreamBytes)
	}
	_, blocked, _ := lim.Metrics()
	if blocked == 0 {
		t.Fatal("blocked counter should have incremented")
	}
}

// --- unit ------------------------------------------------------------

func TestMiddleware_PassThroughOnEmptyBody(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{
		Enabled: true, MaxBodyBytes: 1024, MinBytesPerSecond: 1000, GracePeriod: time.Second, OnError: "allow",
	}, nil)
	called := false
	h := lim.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called {
		t.Fatal("handler should have been called for GET without body")
	}
}

func TestMiddleware_DisabledPassesThrough(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(0, 0)}
	lim := newLimiter(t, Config{Enabled: false}, clk)
	upstreamBytes := 0
	h := lim.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		upstreamBytes = len(b)
	}))
	req := httptest.NewRequest(http.MethodPost, "/", &dripReader{
		src: bytes.Repeat([]byte("a"), 100), clock: clk, interval: 100 * time.Millisecond,
	})
	req.ContentLength = 100
	h.ServeHTTP(httptest.NewRecorder(), req)
	if upstreamBytes != 100 {
		t.Fatalf("disabled: upstream got %d, want 100", upstreamBytes)
	}
}

func TestSlowReader_RespectsGracePeriod(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(0, 0)}
	// Grace de 2s ⇒ pendant 2s on tolère 0 byte.
	sr := &slowReader{
		r:       io.NopCloser(strings.NewReader("hello world")),
		now:     clk.Now,
		start:   clk.Now(),
		minRate: 1000,
		grace:   2 * time.Second,
	}
	buf := make([]byte, 5)
	clk.Advance(500 * time.Millisecond) // < grace
	n, err := sr.Read(buf)
	if err != nil {
		t.Fatalf("during grace, unexpected err: %v", err)
	}
	if n != 5 {
		t.Fatalf("got n=%d, want 5", n)
	}
}

func TestSlowReader_TriggersAfterGrace(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(0, 0)}
	violations := 0
	sr := &slowReader{
		r:           io.NopCloser(strings.NewReader("hello world")),
		now:         clk.Now,
		start:       clk.Now(),
		minRate:     1000, // 1000 o/s
		grace:       1 * time.Second,
		onViolation: func() { violations++ },
	}
	buf := make([]byte, 1)
	// Lit 1 octet à t=2s ⇒ 1 byte en 2s, attendu 2000 ⇒ violation.
	clk.Advance(2 * time.Second)
	_, err := sr.Read(buf)
	if !errors.Is(err, ErrSlowPost) {
		t.Fatalf("got err=%v, want ErrSlowPost", err)
	}
	if violations != 1 {
		t.Fatalf("violations=%d, want 1", violations)
	}
	// Lecture suivante : reste violated.
	_, err = sr.Read(buf)
	if !errors.Is(err, ErrSlowPost) {
		t.Fatalf("second read: got %v, want ErrSlowPost", err)
	}
}

func TestUpdate_RejectsInvalidKeepsOld(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{
		Enabled: true, MaxBodyBytes: 1024, MinBytesPerSecond: 100, GracePeriod: time.Second, OnError: "allow",
	}, nil)
	if err := lim.Update(Config{Enabled: true, MaxBodyBytes: 0, MinBytesPerSecond: 100, OnError: "allow"}); err == nil {
		t.Fatal("Update should have failed on MaxBodyBytes=0")
	}
	if lim.Config().MaxBodyBytes != 1024 {
		t.Fatalf("old config should remain, got %d", lim.Config().MaxBodyBytes)
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
		{"disabled ok", Config{Enabled: false, OnError: "allow"}, false},
		{"ok", Config{Enabled: true, MaxBodyBytes: 1024, MinBytesPerSecond: 50, GracePeriod: time.Second, OnError: "deny"}, false},
		{"bad on_error", Config{OnError: "yolo"}, true},
		{"max body 0", Config{Enabled: true, MaxBodyBytes: 0, MinBytesPerSecond: 50, GracePeriod: time.Second, OnError: "allow"}, true},
		{"max body too big", Config{Enabled: true, MaxBodyBytes: 2 << 30, MinBytesPerSecond: 50, GracePeriod: time.Second, OnError: "allow"}, true},
		{"rate 0", Config{Enabled: true, MaxBodyBytes: 1024, MinBytesPerSecond: 0, GracePeriod: time.Second, OnError: "allow"}, true},
		{"grace negative", Config{Enabled: true, MaxBodyBytes: 1024, MinBytesPerSecond: 50, GracePeriod: -time.Second, OnError: "allow"}, true},
		{"grace too long", Config{Enabled: true, MaxBodyBytes: 1024, MinBytesPerSecond: 50, GracePeriod: 2 * time.Minute, OnError: "allow"}, true},
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

func BenchmarkSlowReader_FastFlow(b *testing.B) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	sr := &slowReader{
		r:       io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), 1<<20))),
		now:     clk.Now,
		start:   clk.Now(),
		minRate: 1,
		grace:   time.Second,
	}
	buf := make([]byte, 4096)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sr.Read(buf)
	}
}
