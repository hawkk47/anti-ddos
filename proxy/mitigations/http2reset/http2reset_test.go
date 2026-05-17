package http2reset

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anti-ddos/proxy/internal/metrics"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// --- helpers ------------------------------------------------------

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
	reg := metrics.NewInMemory()
	l, err := New(cfg, reg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if clk != nil {
		l.now = clk.Now
	}
	return l
}

// fakeConn : net.Conn minimaliste qui mémorise si Close a été appelé.
type fakeConn struct {
	closed atomic.Bool
}

func (f *fakeConn) Read(_ []byte) (int, error)         { return 0, errors.New("not implemented") }
func (f *fakeConn) Write(_ []byte) (int, error)        { return 0, errors.New("not implemented") }
func (f *fakeConn) Close() error                       { f.closed.Store(true); return nil }
func (f *fakeConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (f *fakeConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (f *fakeConn) SetDeadline(_ time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(_ time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(_ time.Time) error { return nil }

// simulateEarlyCancel fait passer N "requêtes" annulées dans le
// middleware sur la conn `c`. baseCtx doit avoir été préparé via
// lim.ConnContext(ctx, c) pour que toutes les itérations partagent
// le même connState.
func simulateEarlyCancel(t *testing.T, lim *Limiter, baseCtx context.Context, n int) {
	t.Helper()
	handler := lim.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handler qui ne fait rien (pas de Write) : c'est le cas
		// d'un stream RST tôt par le client.
	}))
	for i := 0; i < n; i++ {
		ctx, cancel := context.WithCancel(baseCtx)
		cancel() // ctx annulé AVANT serveHTTP
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
		rw := &dummyResponseWriter{header: http.Header{}}
		handler.ServeHTTP(rw, req)
	}
}

type dummyResponseWriter struct {
	header http.Header
}

func (d *dummyResponseWriter) Header() http.Header { return d.header }
func (d *dummyResponseWriter) Write(b []byte) (int, error) {
	return len(b), nil
}
func (d *dummyResponseWriter) WriteHeader(_ int) {}

// --- tests --------------------------------------------------------

func TestConfig_Validate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"disabled-empty-ok", Config{}, false},
		{"enabled-ok", Config{Enabled: true, MaxResetsPerConn: 10, Window: time.Second}, false},
		{"enabled-no-resets", Config{Enabled: true, Window: time.Second}, true},
		{"enabled-resets-too-large", Config{Enabled: true, MaxResetsPerConn: 2_000_000, Window: time.Second}, true},
		{"enabled-no-window", Config{Enabled: true, MaxResetsPerConn: 10}, true},
		{"enabled-window-too-large", Config{Enabled: true, MaxResetsPerConn: 10, Window: 10 * time.Minute}, true},
		{"max-streams-too-large", Config{MaxConcurrentStreams: 200_000}, true},
		{"on-error-invalid", Config{OnError: "kaboom"}, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestUpdate_RejectsInvalidKeepsOld(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, MaxResetsPerConn: 5, Window: time.Second}, nil)
	if err := lim.Update(Config{Enabled: true, MaxResetsPerConn: 0, Window: time.Second}); err == nil {
		t.Fatal("expected validation error")
	}
	if lim.Config().MaxResetsPerConn != 5 {
		t.Errorf("old config lost: %+v", lim.Config())
	}
	_, _, errs := lim.Metrics()
	if errs == 0 {
		t.Error("errors_total should have incremented")
	}
}

func TestMiddleware_DisabledIsPassThrough(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: false}, nil)
	c := &fakeConn{}
	baseCtx := lim.ConnContext(context.Background(), c)
	simulateEarlyCancel(t, lim, baseCtx, 1000)
	if c.closed.Load() {
		t.Error("conn closed while disabled")
	}
	eval, blocked, _ := lim.Metrics()
	if eval != 0 || blocked != 0 {
		t.Errorf("counters moved while disabled: eval=%d blocked=%d", eval, blocked)
	}
}

func TestMiddleware_EarlyCancelCloseAtThreshold(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(0, 0)}
	lim := newLimiter(t, Config{
		Enabled:          true,
		MaxResetsPerConn: 5,
		Window:           time.Minute,
		OnError:          "allow",
	}, clk)
	c := &fakeConn{}
	baseCtx := lim.ConnContext(context.Background(), c)
	// 5 resets : sous le seuil strict (>5), pas de close.
	simulateEarlyCancel(t, lim, baseCtx, 5)
	if c.closed.Load() {
		t.Error("conn closed too early")
	}
	// 6ᵉ reset (> seuil) : close.
	simulateEarlyCancel(t, lim, baseCtx, 1)
	if !c.closed.Load() {
		t.Error("conn should have been closed after exceeding threshold")
	}
	_, blocked, _ := lim.Metrics()
	if blocked != 1 {
		t.Errorf("blocked=%d, want 1", blocked)
	}
}

func TestMiddleware_WindowResets(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(0, 0)}
	lim := newLimiter(t, Config{
		Enabled:          true,
		MaxResetsPerConn: 5,
		Window:           time.Minute,
		OnError:          "allow",
	}, clk)
	c := &fakeConn{}
	baseCtx := lim.ConnContext(context.Background(), c)
	simulateEarlyCancel(t, lim, baseCtx, 5)
	clk.Advance(2 * time.Minute) // fenêtre expirée
	simulateEarlyCancel(t, lim, baseCtx, 5)
	if c.closed.Load() {
		t.Error("conn closed across separate windows")
	}
}

func TestMiddleware_DoesNotCountIfResponseWritten(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{
		Enabled:          true,
		MaxResetsPerConn: 1,
		Window:           time.Minute,
	}, nil)
	c := &fakeConn{}
	// Handler qui écrit IMMÉDIATEMENT 200 OK ; même si ctx est canceled
	// après, on ne doit pas compter.
	h := lim.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for i := 0; i < 10; i++ {
		baseCtx := lim.ConnContext(context.Background(), c)
		ctx, cancel := context.WithCancel(baseCtx)
		cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
		rw := &dummyResponseWriter{header: http.Header{}}
		h.ServeHTTP(rw, req)
	}
	if c.closed.Load() {
		t.Error("conn closed despite handler writing response")
	}
	eval, _, _ := lim.Metrics()
	if eval != 0 {
		t.Errorf("evaluated=%d, want 0 (response written)", eval)
	}
}

func TestOnConnState_CleansUpClosed(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{}, nil)
	c := &fakeConn{}
	_ = lim.ConnContext(context.Background(), c)
	lim.mu.Lock()
	if len(lim.conns) != 1 {
		lim.mu.Unlock()
		t.Fatalf("conns=%d, want 1", len(lim.conns))
	}
	lim.mu.Unlock()
	lim.OnConnState(c, http.StateClosed)
	lim.mu.Lock()
	defer lim.mu.Unlock()
	if len(lim.conns) != 0 {
		t.Errorf("conns=%d, want 0 after Close", len(lim.conns))
	}
}

// TestReproducer_RapidReset_WithoutMitigation : sans middleware,
// le serveur accepte indéfiniment des streams RST tôt — aucun
// blocage. Démontre que la classe d'attaque est réelle (CPU brûlé
// sans contre-mesure).
func TestReproducer_RapidReset_WithoutMitigation(t *testing.T) {
	t.Parallel()
	const N = 30
	handlerCalls := int64(0)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&handlerCalls, 1)
		<-r.Context().Done() // attend l'annulation
	})
	srv, addr, cleanup := startH2CServer(t, handler, nil, nil)
	defer cleanup()
	_ = srv

	floodH2(t, addr, N)
	// On vérifie juste que les handlers ont bien été invoqués
	// (donc des frames HEADERS ont coûté du CPU), preuve que sans
	// mitigation rien ne s'oppose au flood.
	if atomic.LoadInt64(&handlerCalls) == 0 {
		t.Fatal("no handler invocation observed; reproducer setup broken")
	}
}

// TestReproducer_RapidReset_WithMitigation_ClosesConn : avec
// middleware (seuil bas), la connexion est fermée par le serveur
// dès que le seuil de reset est dépassé.
func TestReproducer_RapidReset_WithMitigation_ClosesConn(t *testing.T) {
	t.Parallel()
	reg := metrics.NewInMemory()
	lim, err := New(Config{
		Enabled:          true,
		MaxResetsPerConn: 3,
		Window:           time.Minute,
		OnError:          "allow",
	}, reg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler := lim.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	_, addr, cleanup := startH2CServer(t, handler, lim.ConnContext, lim.OnConnState)
	defer cleanup()

	floodH2(t, addr, 30)

	// Laisse le temps au middleware d'observer les annulations.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, blocked, _ := lim.Metrics(); blocked > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_, blocked, _ := lim.Metrics()
	if blocked == 0 {
		t.Fatalf("expected at least 1 conn close, got blocked=%d", blocked)
	}
}

// startH2CServer démarre un serveur h2c sur 127.0.0.1:0. Retourne
// l'adresse et une fonction de cleanup.
func startH2CServer(
	t *testing.T,
	handler http.Handler,
	connCtx func(context.Context, net.Conn) context.Context,
	onState func(net.Conn, http.ConnState),
) (*http.Server, string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	h2s := &http2.Server{MaxConcurrentStreams: 100}
	srv := &http.Server{
		Handler:     h2c.NewHandler(handler, h2s),
		ConnContext: connCtx,
		ConnState:   onState,
	}
	go func() { _ = srv.Serve(ln) }()
	return srv, ln.Addr().String(), func() {
		_ = srv.Close()
		_ = ln.Close()
	}
}

// floodH2 envoie N requêtes H2 puis annule immédiatement les ctx pour
// déclencher RST_STREAM côté client.
func floodH2(t *testing.T, addr string, n int) {
	t.Helper()
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, target string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, target)
		},
	}
	defer tr.CloseIdleConnections()
	url := "http://" + addr + "/"
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithCancel(context.Background())
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			done := make(chan struct{})
			go func() {
				_, _ = tr.RoundTrip(req)
				close(done)
			}()
			// Petit délai pour laisser HEADERS arriver puis cancel.
			time.Sleep(5 * time.Millisecond)
			cancel()
			<-done
		}()
		// Espacer un peu pour rester sur la même conn TCP (sinon le
		// transport peut ouvrir plusieurs conns en parallèle).
		time.Sleep(2 * time.Millisecond)
	}
	wg.Wait()
}
