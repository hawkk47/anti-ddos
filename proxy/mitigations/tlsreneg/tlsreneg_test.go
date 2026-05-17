package tlsreneg

import (
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

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

// TestReproducer_HandshakeFlood_WithoutMitigation : sans Limiter, le
// listener accepte N connexions d'affilée venant de la même IP.
func TestReproducer_HandshakeFlood_WithoutMitigation(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	const N = 50
	accepted := 0
	done := make(chan struct{})
	go func() {
		for i := 0; i < N; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted++
			_ = c.Close()
		}
		close(done)
	}()

	for i := 0; i < N; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		_ = c.Close()
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: not enough accepts")
	}
	if accepted != N {
		t.Fatalf("got %d accepts, want %d (attack reaches listener)", accepted, N)
	}
}

// TestReproducer_HandshakeFlood_WithMitigation_Caps : avec Limiter
// (burst=5, rate=1/s, clock fakée), seulement 5 handshakes passent
// dans la même milliseconde ; les autres sont fermés immédiatement
// par le wrapper et le compteur `blocked` incrémente.
func TestReproducer_HandshakeFlood_WithMitigation_Caps(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(0, 0)}
	lim := newLimiter(t, Config{
		Enabled:                  true,
		MinTLSVersion:            "1.2",
		HandshakesPerSecondPerIP: 1,
		Burst:                    5,
		OnError:                  "allow",
	}, clk)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	wrapped := lim.WrapListener(ln)

	const N = 20
	accepted := 0
	doneAccept := make(chan struct{})
	go func() {
		defer close(doneAccept)
		for {
			c, err := wrapped.Accept()
			if err != nil {
				return
			}
			accepted++
			_ = c.Close()
		}
	}()

	// On dial N fois successivement. Avec clock fakée, aucun refill
	// ne se produit ⇒ après 5 succès, tout le reste passe en blocked.
	for i := 0; i < N; i++ {
		c, derr := net.Dial("tcp", ln.Addr().String())
		if derr != nil {
			continue
		}
		_ = c.Close()
	}

	// Laisser le wrapper consommer le backlog, puis fermer pour
	// faire sortir le goroutine d'Accept.
	time.Sleep(200 * time.Millisecond)
	_ = ln.Close()
	select {
	case <-doneAccept:
	case <-time.After(3 * time.Second):
		t.Fatal("Accept goroutine did not exit after Close")
	}

	if accepted != 5 {
		t.Fatalf("accepted=%d, want 5 (burst cap)", accepted)
	}
	_, blocked, _ := lim.Metrics()
	if blocked == 0 {
		t.Fatalf("blocked counter should have incremented (got 0, accepted=%d)", accepted)
	}
}

// --- unit ------------------------------------------------------------

func TestBuildTLSConfig_EnforcesMinAndNoRenegotiation(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{
		Enabled: true, MinTLSVersion: "1.3", HandshakesPerSecondPerIP: 10, Burst: 5, OnError: "allow",
	}, nil)
	c := lim.BuildTLSConfig(nil)
	if c.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion=%x want VersionTLS13", c.MinVersion)
	}
	if c.Renegotiation != tls.RenegotiateNever {
		t.Errorf("Renegotiation=%d want RenegotiateNever", c.Renegotiation)
	}

	lim2 := newLimiter(t, Config{
		Enabled: true, MinTLSVersion: "1.2", HandshakesPerSecondPerIP: 10, Burst: 5, OnError: "allow",
	}, nil)
	c2 := lim2.BuildTLSConfig(nil)
	if c2.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion=%x want VersionTLS12", c2.MinVersion)
	}
}

func TestAllow_TokenBucketRefill(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(0, 0)}
	lim := newLimiter(t, Config{
		Enabled:                  true,
		MinTLSVersion:            "1.2",
		HandshakesPerSecondPerIP: 2, // 2 tokens/s
		Burst:                    3,
		OnError:                  "allow",
	}, clk)

	// 3 premiers passent (burst).
	for i := 0; i < 3; i++ {
		if !lim.allow("203.0.113.1") {
			t.Fatalf("hit %d: should pass (burst)", i)
		}
	}
	// 4ᵉ refusé sans temps écoulé.
	if lim.allow("203.0.113.1") {
		t.Fatal("4th hit: should block")
	}
	// Avance 0.5s ⇒ 1 token refill.
	clk.Advance(500 * time.Millisecond)
	if !lim.allow("203.0.113.1") {
		t.Fatal("after refill: should pass")
	}
	if lim.allow("203.0.113.1") {
		t.Fatal("immediate after refill: should block again")
	}

	// IP différente : bucket vierge.
	if !lim.allow("203.0.113.2") {
		t.Fatal("other IP: should pass")
	}
}

func TestAllow_DisabledIsPassThrough(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: false}, nil)
	for i := 0; i < 1000; i++ {
		if !lim.allow("203.0.113.99") {
			t.Fatalf("disabled hit %d: should pass", i)
		}
	}
}

func TestWrapListener_DisabledReturnsSameListener(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: false}, nil)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	if lim.WrapListener(ln) != ln {
		t.Fatal("WrapListener with Enabled=false should return ln verbatim")
	}
}

func TestUpdate_RejectsInvalidKeepsOld(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{
		Enabled: true, MinTLSVersion: "1.2", HandshakesPerSecondPerIP: 10, Burst: 5, OnError: "allow",
	}, nil)
	if err := lim.Update(Config{Enabled: true, MinTLSVersion: "bad", HandshakesPerSecondPerIP: 10, Burst: 5, OnError: "allow"}); err == nil {
		t.Fatal("Update should fail on bad MinTLSVersion")
	}
	if lim.Config().MinTLSVersion != "1.2" {
		t.Fatalf("old config should remain, got %q", lim.Config().MinTLSVersion)
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
		{"ok 1.2", Config{Enabled: true, MinTLSVersion: "1.2", HandshakesPerSecondPerIP: 10, Burst: 5, OnError: "allow"}, false},
		{"ok 1.3 deny", Config{Enabled: true, MinTLSVersion: "1.3", HandshakesPerSecondPerIP: 1, Burst: 1, OnError: "deny"}, false},
		{"bad version", Config{Enabled: true, MinTLSVersion: "1.0", HandshakesPerSecondPerIP: 10, Burst: 5, OnError: "allow"}, true},
		{"rate 0", Config{Enabled: true, MinTLSVersion: "1.2", HandshakesPerSecondPerIP: 0, Burst: 5, OnError: "allow"}, true},
		{"rate too big", Config{Enabled: true, MinTLSVersion: "1.2", HandshakesPerSecondPerIP: 2e6, Burst: 5, OnError: "allow"}, true},
		{"burst 0", Config{Enabled: true, MinTLSVersion: "1.2", HandshakesPerSecondPerIP: 10, Burst: 0, OnError: "allow"}, true},
		{"bad on_error", Config{OnError: "panic"}, true},
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
