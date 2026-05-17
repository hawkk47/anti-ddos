package slowloris

import (
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

// startProxiedListener démarre un net.Listener loopback wrappé par
// le Limiter, derrière un *http.Server qui retourne 200 OK.
// Loopback uniquement (127.0.0.1).
func startProxiedListener(t *testing.T, cfg Config) (string, *Limiter, func()) {
	t.Helper()
	reg := metrics.NewInMemory()
	lim, err := New(cfg, reg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	wrapped := lim.Wrap(ln)

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok")
		}),
		ReadHeaderTimeout: 200 * time.Millisecond,
		ReadTimeout:       500 * time.Millisecond,
		WriteTimeout:      500 * time.Millisecond,
	}
	go func() { _ = srv.Serve(wrapped) }()

	addr := ln.Addr().String()
	stop := func() {
		_ = srv.Close()
	}
	return addr, lim, stop
}

// openSlowConn ouvre une connexion TCP et envoie un en-tête HTTP
// partiel (typique de Slowloris). Reste ouverte jusqu'à ce que
// closeCh soit fermé.
func openSlowConn(t *testing.T, addr string, closeCh <-chan struct{}) (net.Conn, error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		return nil, err
	}
	// On envoie juste la request line, pas le \r\n\r\n final.
	_, _ = c.Write([]byte("GET /slow HTTP/1.1\r\nHost: localhost\r\nX-Pad: "))
	go func() {
		<-closeCh
		_ = c.Close()
	}()
	return c, nil
}

// TestSlowloris_Reproducer_FailsWithoutMitigation : SANS le limiter
// (Enabled=false), N+1 connexions lentes restent toutes ouvertes
// simultanément côté proxy. C'est la condition d'attaque.
func TestSlowloris_Reproducer_FailsWithoutMitigation(t *testing.T) {
	const want = 5
	addr, lim, stop := startProxiedListener(t, Config{Enabled: false})
	defer stop()

	close1 := make(chan struct{})
	defer close(close1)

	conns := make([]net.Conn, 0, want)
	for i := 0; i < want; i++ {
		c, err := openSlowConn(t, addr, close1)
		if err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
		conns = append(conns, c)
	}

	// Sans mitigation, le compteur per-IP du limiter doit être à 0
	// (limiter désactivé) ET les connexions ne sont pas comptées.
	if got := lim.Active("127.0.0.1"); got != 0 {
		t.Errorf("expected 0 tracked conns when disabled, got %d", got)
	}
	// Toutes les connexions doivent être encore vivantes (test : on
	// peut écrire dessus sans erreur immédiate).
	for i, c := range conns {
		_ = c.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
		if _, err := c.Write([]byte("a")); err != nil {
			t.Errorf("conn %d closed prematurely (no mitigation expected): %v", i, err)
		}
	}
}

// TestSlowloris_Reproducer_BlockedWithMitigation : AVEC le limiter
// (MaxConnsPerIP=2), la 3ème connexion lente est fermée immédiatement
// par le proxy (TCP RST/FIN à l'accept), libérant le slot de FD.
func TestSlowloris_Reproducer_BlockedWithMitigation(t *testing.T) {
	addr, lim, stop := startProxiedListener(t, Config{
		Enabled:       true,
		MaxConnsPerIP: 2,
		OnError:       "allow",
	})
	defer stop()

	closeCh := make(chan struct{})
	defer close(closeCh)

	// Deux connexions lentes : doivent réussir.
	c1, err := openSlowConn(t, addr, closeCh)
	if err != nil {
		t.Fatalf("c1: %v", err)
	}
	c2, err := openSlowConn(t, addr, closeCh)
	if err != nil {
		t.Fatalf("c2: %v", err)
	}
	_ = c1
	_ = c2

	// Laisser le serveur enregistrer les deux acceptes.
	deadline := time.Now().Add(2 * time.Second)
	for lim.Active("127.0.0.1") < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := lim.Active("127.0.0.1"); got != 2 {
		t.Fatalf("expected 2 active conns, got %d", got)
	}

	// 3ème : doit être fermée par le proxy. Le client la voit
	// soit rejetée à l'écriture, soit en EOF rapide à la lecture.
	c3, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		// Acceptable : selon l'OS, le RST peut casser le dial.
		return
	}
	defer c3.Close()
	_ = c3.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, readErr := c3.Read(buf)
	if readErr == nil && n > 0 {
		t.Errorf("3rd conn should be closed, got %d bytes: %q", n, buf[:n])
	}
	if readErr == nil {
		t.Errorf("3rd conn should be closed by proxy, got no error")
	}
	if !errors.Is(readErr, io.EOF) && !isClosedConnErr(readErr) {
		// Sur Windows on peut voir "connection forcibly closed".
		// On accepte tout ce qui n'est pas un timeout.
		var netErr net.Error
		if errors.As(readErr, &netErr) && netErr.Timeout() {
			t.Errorf("3rd conn should be closed quickly, got timeout: %v", readErr)
		}
	}

	// Métriques attendues : evaluated >= 3, blocked >= 1.
	reg := lim.Metrics()
	if got := reg.Counter("mitigation_slowloris_blocked_total").Value(); got < 1 {
		t.Errorf("blocked counter: got %d want >= 1", got)
	}
	if got := reg.Counter("mitigation_slowloris_evaluated_total").Value(); got < 3 {
		t.Errorf("evaluated counter: got %d want >= 3", got)
	}
}

// TestSlowloris_ReleaseFreesSlot : après fermeture client, le slot
// doit être libéré et une nouvelle connexion doit pouvoir entrer.
func TestSlowloris_ReleaseFreesSlot(t *testing.T) {
	addr, lim, stop := startProxiedListener(t, Config{
		Enabled: true, MaxConnsPerIP: 1, OnError: "allow",
	})
	defer stop()

	closeCh1 := make(chan struct{})
	c1, err := openSlowConn(t, addr, closeCh1)
	if err != nil {
		t.Fatalf("c1: %v", err)
	}

	// Attendre que le slot soit pris.
	deadline := time.Now().Add(2 * time.Second)
	for lim.Active("127.0.0.1") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	// Fermer c1 → slot libéré.
	close(closeCh1)
	_ = c1.Close()

	deadline = time.Now().Add(2 * time.Second)
	for lim.Active("127.0.0.1") > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := lim.Active("127.0.0.1"); got != 0 {
		t.Fatalf("slot should be released, active=%d", got)
	}

	// Nouvelle connexion : doit passer.
	closeCh2 := make(chan struct{})
	defer close(closeCh2)
	c2, err := openSlowConn(t, addr, closeCh2)
	if err != nil {
		t.Fatalf("c2 (after release): %v", err)
	}
	_ = c2
}

func TestConfig_Validate(t *testing.T) {
	cases := map[string]struct {
		cfg     Config
		wantErr bool
	}{
		"defaults":      {Config{}, false},
		"enabled ok":    {Config{Enabled: true, MaxConnsPerIP: 10}, false},
		"on_error deny": {Config{OnError: "deny"}, false},
		"bad on_error":  {Config{OnError: "kill"}, true},
		"negative max":  {Config{MaxConnsPerIP: -1}, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestLimiter_HotReload(t *testing.T) {
	reg := metrics.NewInMemory()
	lim, err := New(Config{Enabled: true, MaxConnsPerIP: 1}, reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := lim.Update(Config{Enabled: true, MaxConnsPerIP: 5}); err != nil {
		t.Fatalf("update: %v", err)
	}
	cfg := lim.snapshot()
	if cfg.MaxConnsPerIP != 5 {
		t.Errorf("hot-reload failed, max=%d", cfg.MaxConnsPerIP)
	}
	// Update invalide : ancienne config conservée.
	if err := lim.Update(Config{OnError: "kaboom"}); err == nil {
		t.Errorf("expected validation error")
	}
	cfg = lim.snapshot()
	if cfg.MaxConnsPerIP != 5 {
		t.Errorf("invalid update should not have replaced cfg")
	}
	if reg.Counter("mitigation_slowloris_errors_total").Value() != 1 {
		t.Errorf("errors counter not incremented on bad update")
	}
}

// BenchmarkLimiter_Allow mesure le coût du chemin chaud allow/release.
// Référence à comparer dans tests/benchmarks/baselines/ (à créer).
func BenchmarkLimiter_Allow(b *testing.B) {
	lim, _ := New(Config{Enabled: true, MaxConnsPerIP: 1024}, metrics.NewInMemory())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !lim.allow("127.0.0.1") {
			b.Fatalf("unexpected block at i=%d", i)
		}
		lim.release("127.0.0.1")
	}
}

func BenchmarkLimiter_AllowParallel(b *testing.B) {
	lim, _ := New(Config{Enabled: true, MaxConnsPerIP: 1024}, metrics.NewInMemory())
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if lim.allow("127.0.0.1") {
				lim.release("127.0.0.1")
			}
		}
	})
}

// metricsFromLimiter / testRegs : retirés (Limiter.Metrics() expose
// la registry directement).

// isClosedConnErr : test best-effort cross-platform.
func isClosedConnErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "closed") ||
		strings.Contains(msg, "reset") ||
		strings.Contains(msg, "forcibly") ||
		strings.Contains(msg, "broken pipe")
}
