package requesthygiene

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func defaultCfg() Config {
	return Config{
		Enabled:         true,
		AllowedMethods:  DefaultAllowedMethods,
		MaxURILength:    2048,
		RejectTECL:      true,
		RejectDupCL:     true,
		RejectBadTE:     true,
		RejectEmptyHost: true,
		OnError:         "deny",
	}
}

// --- reproducer ------------------------------------------------------

// TestReproducer_RequestHygiene_WithoutMitigation prouve qu'un upstream
// non protégé voit arriver des méthodes exotiques et des combinaisons
// d'en-têtes ambiguës (TE+CL = vecteur smuggling classique).
func TestReproducer_RequestHygiene_WithoutMitigation(t *testing.T) {
	t.Parallel()
	var seenMethod, seenTECL bool
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "FOOBAR" {
			seenMethod = true
		}
		if r.Header.Get("Transfer-Encoding") != "" && r.Header.Get("Content-Length") != "" {
			seenTECL = true
		}
		w.WriteHeader(204)
	})

	// méthode exotique
	r1 := httptest.NewRequest("FOOBAR", "/x", nil)
	w1 := httptest.NewRecorder()
	upstream.ServeHTTP(w1, r1)
	if !seenMethod {
		t.Fatal("expected FOOBAR to reach upstream without mitigation")
	}
	// TE + CL ensemble
	r2 := httptest.NewRequest("POST", "/x", strings.NewReader("abc"))
	r2.Header.Set("Transfer-Encoding", "chunked")
	r2.Header.Set("Content-Length", "3")
	w2 := httptest.NewRecorder()
	upstream.ServeHTTP(w2, r2)
	if !seenTECL {
		t.Fatal("expected TE+CL to reach upstream without mitigation")
	}
}

// TestReproducer_RequestHygiene_WithMitigation_Blocks prouve que la
// mitigation rejette ces deux vecteurs en 400.
func TestReproducer_RequestHygiene_WithMitigation_Blocks(t *testing.T) {
	t.Parallel()
	var reached int
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(204)
	})
	lim := newLimiter(t, defaultCfg())
	mw := lim.Middleware(upstream)

	cases := []struct {
		name string
		req  *http.Request
	}{
		{"exotic method", httptest.NewRequest("FOOBAR", "/x", nil)},
		{"TE+CL", func() *http.Request {
			r := httptest.NewRequest("POST", "/x", strings.NewReader("abc"))
			r.Header.Set("Transfer-Encoding", "chunked")
			r.Header.Set("Content-Length", "3")
			return r
		}()},
		{"duplicate CL", func() *http.Request {
			r := httptest.NewRequest("POST", "/x", strings.NewReader("abc"))
			r.Header["Content-Length"] = []string{"3", "5"}
			return r
		}()},
		{"invalid TE", func() *http.Request {
			r := httptest.NewRequest("POST", "/x", strings.NewReader(""))
			r.Header["Transfer-Encoding"] = []string{"gzip"}
			return r
		}()},
		{"long URI", httptest.NewRequest("GET", "/"+strings.Repeat("a", 4096), nil)},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, tc.req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: got %d, want 400", tc.name, w.Code)
		}
	}
	if reached != 0 {
		t.Fatalf("upstream reached %d times, want 0", reached)
	}
	_, blocked, _ := lim.Metrics()
	if blocked < uint64(len(cases)) {
		t.Fatalf("blocked=%d, want >= %d", blocked, len(cases))
	}
}

// --- unit ------------------------------------------------------------

func TestEvaluate_DisabledPassesThrough(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: false})
	r := httptest.NewRequest("FOOBAR", "/", nil)
	if got := lim.Evaluate(r); got != ReasonNone {
		t.Fatalf("disabled should pass through, got %q", got)
	}
}

func TestEvaluate_MethodWhitelist(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, defaultCfg())
	for _, m := range DefaultAllowedMethods {
		r := httptest.NewRequest(m, "/", nil)
		if got := lim.Evaluate(r); got != ReasonNone {
			t.Fatalf("%s should be allowed, got %q", m, got)
		}
	}
	for _, m := range []string{"TRACE", "CONNECT", "FOOBAR", "get" /* case-sensitive */} {
		r := httptest.NewRequest(m, "/", nil)
		if got := lim.Evaluate(r); got != ReasonMethodNotAllowed {
			t.Fatalf("%s should be rejected, got %q", m, got)
		}
	}
}

func TestEvaluate_URITooLong(t *testing.T) {
	t.Parallel()
	cfg := defaultCfg()
	cfg.MaxURILength = 16
	lim := newLimiter(t, cfg)
	if got := lim.Evaluate(httptest.NewRequest("GET", "/short", nil)); got != ReasonNone {
		t.Fatalf("short URI rejected: %q", got)
	}
	if got := lim.Evaluate(httptest.NewRequest("GET", "/"+strings.Repeat("a", 100), nil)); got != ReasonURITooLong {
		t.Fatalf("long URI not rejected: %q", got)
	}
}

func TestEvaluate_TECLConflict(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, defaultCfg())
	r := httptest.NewRequest("POST", "/", strings.NewReader("abc"))
	r.Header.Set("Transfer-Encoding", "chunked")
	r.Header.Set("Content-Length", "3")
	if got := lim.Evaluate(r); got != ReasonTECLConflict {
		t.Fatalf("TE+CL not detected: %q", got)
	}
}

func TestEvaluate_DuplicateContentLength(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, defaultCfg())
	r := httptest.NewRequest("POST", "/", strings.NewReader("abc"))
	r.Header["Content-Length"] = []string{"3", "5"}
	if got := lim.Evaluate(r); got != ReasonDuplicateCL {
		t.Fatalf("duplicate CL not detected: %q", got)
	}
}

func TestEvaluate_InvalidTransferEncoding(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, defaultCfg())
	r := httptest.NewRequest("POST", "/", strings.NewReader(""))
	r.Header["Transfer-Encoding"] = []string{"gzip, chunked"}
	if got := lim.Evaluate(r); got != ReasonInvalidTE {
		t.Fatalf("invalid TE not detected: %q", got)
	}
	// chunked seul : OK
	r2 := httptest.NewRequest("POST", "/", strings.NewReader(""))
	r2.Header["Transfer-Encoding"] = []string{"chunked"}
	if got := lim.Evaluate(r2); got != ReasonNone {
		t.Fatalf("chunked alone rejected: %q", got)
	}
}

func TestEvaluate_EmptyHost(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, defaultCfg())
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "   "
	if got := lim.Evaluate(r); got != ReasonEmptyHost {
		t.Fatalf("empty host not detected: %q", got)
	}
}

func TestConfig_Validate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"disabled empty ok", Config{Enabled: false}, false},
		{"enabled no rule", Config{Enabled: true}, true},
		{"ok", defaultCfg(), false},
		{"bad on_error", Config{Enabled: false, OnError: "yolo"}, true},
		{"lowercase method", Config{Enabled: true, AllowedMethods: []string{"get"}}, true},
		{"empty method entry", Config{Enabled: true, AllowedMethods: []string{""}}, true},
		{"negative max_uri", Config{Enabled: true, AllowedMethods: []string{"GET"}, MaxURILength: -1}, true},
		{"max_uri too large", Config{Enabled: true, AllowedMethods: []string{"GET"}, MaxURILength: 2 << 20}, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestUpdate_RejectsInvalidKeepsOld(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, defaultCfg())
	if err := lim.Update(Config{Enabled: true /* no rule */}); err == nil {
		t.Fatal("Update should reject empty rule set")
	}
	if got := lim.Config().MaxURILength; got != 2048 {
		t.Fatalf("old config should remain, got %d", got)
	}
	_, _, errs := lim.Metrics()
	if errs == 0 {
		t.Fatal("errors_total should have incremented")
	}
}

func TestMiddleware_AllowsConforming(t *testing.T) {
	t.Parallel()
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(200)
	})
	lim := newLimiter(t, defaultCfg())
	mw := lim.Middleware(next)
	r := httptest.NewRequest("GET", "/ok", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)
	if w.Code != 200 || !called {
		t.Fatalf("expected 200/called, got %d called=%v", w.Code, called)
	}
}

// BenchmarkEvaluate_HotPath mesure le coût d'évaluation sur une
// requête conforme (le cas dominant en prod).
func BenchmarkEvaluate_HotPath(b *testing.B) {
	lim, err := New(Config{
		Enabled:        true,
		AllowedMethods: DefaultAllowedMethods,
		MaxURILength:   2048,
		RejectTECL:     true,
		RejectDupCL:    true,
		RejectBadTE:    true,
	}, metrics.NewInMemory())
	if err != nil {
		b.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/v1/users/42", nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lim.Evaluate(r)
	}
}

// BenchmarkEvaluate_Disabled : baseline pass-through.
func BenchmarkEvaluate_Disabled(b *testing.B) {
	lim, err := New(Config{Enabled: false}, metrics.NewInMemory())
	if err != nil {
		b.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/v1/users/42", nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lim.Evaluate(r)
	}
}
