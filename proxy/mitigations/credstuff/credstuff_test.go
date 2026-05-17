package credstuff

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

// ---------------------------------------------------------------------
// Reproducer : credential-stuffing depuis une IP unique sur /login.
// ---------------------------------------------------------------------

// stuffer simule un attaquant qui poste 50 paires login/mot de passe
// en rafale. Loopback only (httptest). Pas de générateur de trafic
// réutilisable — vit dans le fichier de test.
func stuffer(t *testing.T, target, path string, n int) []int {
	t.Helper()
	codes := make([]int, n)
	client := &http.Client{Timeout: 2 * time.Second}
	for i := 0; i < n; i++ {
		req, err := http.NewRequest(http.MethodPost, target+path,
			strings.NewReader("login=admin&password=hunter2"))
		if err != nil {
			t.Fatalf("build req: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do req %d: %v", i, err)
		}
		codes[i] = resp.StatusCode
		_ = resp.Body.Close()
	}
	return codes
}

func TestReproducer_CredStuff_WithoutMitigation(t *testing.T) {
	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			hits.Add(1)
		}
		w.WriteHeader(http.StatusUnauthorized) // mock upstream rejette
	}))
	defer upstream.Close()

	codes := stuffer(t, upstream.URL, "/login", 50)

	if got := hits.Load(); got != 50 {
		t.Fatalf("expected 50 upstream hits without mitigation, got %d", got)
	}
	for i, c := range codes {
		if c != http.StatusUnauthorized {
			t.Fatalf("code[%d] = %d, want 401", i, c)
		}
	}
}

func TestReproducer_CredStuff_WithMitigation_Denies(t *testing.T) {
	var hits atomic.Int64
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			hits.Add(1)
		}
		w.WriteHeader(http.StatusUnauthorized)
	})

	lim, err := New(Config{
		Enabled:              true,
		LoginPaths:           []string{"/login"},
		Methods:              []string{"POST"},
		MaxAttemptsPerMinute: 5, // burst = 5
		Action:               ActionDeny,
	}, metrics.NewInMemory())
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	srv := httptest.NewServer(lim.Middleware(backend))
	defer srv.Close()

	codes := stuffer(t, srv.URL, "/login", 50)

	// 5 premières passent (burst), 45 suivantes refusées (429).
	var allow, denied int
	for _, c := range codes {
		switch c {
		case http.StatusUnauthorized:
			allow++
		case http.StatusTooManyRequests:
			denied++
		}
	}
	if allow != 5 {
		t.Fatalf("expected 5 allowed (burst), got %d", allow)
	}
	if denied != 45 {
		t.Fatalf("expected 45 denied, got %d", denied)
	}
	if hits.Load() != 5 {
		t.Fatalf("expected 5 upstream hits, got %d", hits.Load())
	}
	_, _, _, blocked, _ := lim.Metrics()
	if blocked != 45 {
		t.Fatalf("blocked metric = %d, want 45", blocked)
	}
}

func TestReproducer_CredStuff_WithMitigation_Logs(t *testing.T) {
	var hits atomic.Int64
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	})

	lim, err := New(Config{
		Enabled:              true,
		LoginPaths:           []string{"/login"},
		MaxAttemptsPerMinute: 5,
		Action:               ActionLog,
	}, metrics.NewInMemory())
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	srv := httptest.NewServer(lim.Middleware(backend))
	defer srv.Close()

	_ = stuffer(t, srv.URL, "/login", 50)

	// action=log : tout passe upstream.
	if hits.Load() != 50 {
		t.Fatalf("expected 50 upstream hits with action=log, got %d", hits.Load())
	}
	_, _, logged, blocked, _ := lim.Metrics()
	if blocked != 0 {
		t.Fatalf("blocked = %d, want 0 in log mode", blocked)
	}
	if logged != 45 {
		t.Fatalf("logged = %d, want 45", logged)
	}
}

// ---------------------------------------------------------------------
// Unit tests.
// ---------------------------------------------------------------------

func newTestLimiter(t *testing.T, cfg Config) *Limiter {
	t.Helper()
	lim, err := New(cfg, metrics.NewInMemory())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// Horloge contrôlée pour les tests time-based.
	var fakeNow atomic.Int64
	fakeNow.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	lim.now = func() time.Time { return time.Unix(0, fakeNow.Load()) }
	return lim
}

func TestEvaluate_Disabled_PassesThrough(t *testing.T) {
	lim, _ := New(Config{Enabled: false}, metrics.NewInMemory())
	for i := 0; i < 100; i++ {
		if d := lim.Evaluate("1.2.3.4", "/login", "POST"); d != Allow {
			t.Fatalf("disabled should always Allow, got %v", d)
		}
	}
	ev, _, _, _, _ := lim.Metrics()
	if ev != 0 {
		t.Fatalf("disabled should not increment evaluated, got %d", ev)
	}
}

func TestEvaluate_OutOfScope_PathNotEvaluated(t *testing.T) {
	lim := newTestLimiter(t, Config{
		Enabled:              true,
		LoginPaths:           []string{"/login"},
		MaxAttemptsPerMinute: 5,
	})
	for i := 0; i < 100; i++ {
		if d := lim.Evaluate("1.2.3.4", "/api/products", "GET"); d != Allow {
			t.Fatalf("out-of-path should Allow, got %v", d)
		}
	}
	ev, matched, _, _, _ := lim.Metrics()
	if ev != 0 || matched != 0 {
		t.Fatalf("out-of-scope should not touch metrics, ev=%d matched=%d", ev, matched)
	}
}

func TestEvaluate_OutOfScope_MethodFiltered(t *testing.T) {
	lim := newTestLimiter(t, Config{
		Enabled:              true,
		LoginPaths:           []string{"/login"},
		Methods:              []string{"POST"},
		MaxAttemptsPerMinute: 1,
	})
	// GET sur /login : hors scope car méthode pas POST.
	for i := 0; i < 100; i++ {
		if d := lim.Evaluate("1.2.3.4", "/login", "GET"); d != Allow {
			t.Fatalf("GET should bypass, got %v", d)
		}
	}
	ev, _, _, _, _ := lim.Metrics()
	if ev != 0 {
		t.Fatalf("non-matching method should not increment evaluated, got %d", ev)
	}
}

func TestEvaluate_BurstThenDeny(t *testing.T) {
	lim := newTestLimiter(t, Config{
		Enabled:              true,
		LoginPaths:           []string{"/login"},
		MaxAttemptsPerMinute: 5,
		Action:               ActionDeny,
	})
	for i := 0; i < 5; i++ {
		if d := lim.Evaluate("1.2.3.4", "/login", "POST"); d != Allow {
			t.Fatalf("burst[%d] should Allow, got %v", i, d)
		}
	}
	if d := lim.Evaluate("1.2.3.4", "/login", "POST"); d != Deny {
		t.Fatalf("post-burst should Deny, got %v", d)
	}
}

func TestEvaluate_PerIpIsolation(t *testing.T) {
	lim := newTestLimiter(t, Config{
		Enabled:              true,
		LoginPaths:           []string{"/login"},
		MaxAttemptsPerMinute: 2,
		Action:               ActionDeny,
	})
	// IP A épuise son quota.
	_ = lim.Evaluate("1.1.1.1", "/login", "POST")
	_ = lim.Evaluate("1.1.1.1", "/login", "POST")
	if d := lim.Evaluate("1.1.1.1", "/login", "POST"); d != Deny {
		t.Fatalf("A should be Denied, got %v", d)
	}
	// IP B ne doit pas être impactée.
	if d := lim.Evaluate("2.2.2.2", "/login", "POST"); d != Allow {
		t.Fatalf("B should be Allowed, got %v", d)
	}
}

func TestEvaluate_PrefixMatch(t *testing.T) {
	lim := newTestLimiter(t, Config{
		Enabled:              true,
		LoginPaths:           []string{"/api/auth/"},
		MaxAttemptsPerMinute: 1,
		Action:               ActionDeny,
	})
	// Premier passe.
	if d := lim.Evaluate("1.2.3.4", "/api/auth/token", "POST"); d != Allow {
		t.Fatalf("first should Allow, got %v", d)
	}
	// Second sur sous-chemin différent : même quota, refusé.
	if d := lim.Evaluate("1.2.3.4", "/api/auth/login", "POST"); d != Deny {
		t.Fatalf("second under prefix should Deny, got %v", d)
	}
	// Hors préfixe : passe.
	if d := lim.Evaluate("1.2.3.4", "/api/users", "POST"); d != Allow {
		t.Fatalf("out-of-prefix should Allow, got %v", d)
	}
}

func TestEvaluate_EmptyIp_FailsOpen(t *testing.T) {
	lim := newTestLimiter(t, Config{
		Enabled:              true,
		LoginPaths:           []string{"/login"},
		MaxAttemptsPerMinute: 1,
		Action:               ActionDeny,
	})
	if d := lim.Evaluate("", "/login", "POST"); d != Allow {
		t.Fatalf("empty ip should fail-open Allow, got %v", d)
	}
	_, _, _, _, errs := lim.Metrics()
	if errs != 1 {
		t.Fatalf("errors should be 1, got %d", errs)
	}
}

func TestUpdate_AppliesAndResetsBuckets(t *testing.T) {
	lim := newTestLimiter(t, Config{
		Enabled:              true,
		LoginPaths:           []string{"/login"},
		MaxAttemptsPerMinute: 2,
		Action:               ActionDeny,
	})
	// Épuiser le quota.
	_ = lim.Evaluate("1.2.3.4", "/login", "POST")
	_ = lim.Evaluate("1.2.3.4", "/login", "POST")
	if d := lim.Evaluate("1.2.3.4", "/login", "POST"); d != Deny {
		t.Fatalf("should Deny before update, got %v", d)
	}
	// Update : seuil plus haut + reset bucket.
	if err := lim.Update(Config{
		Enabled:              true,
		LoginPaths:           []string{"/login"},
		MaxAttemptsPerMinute: 10,
		Action:               ActionDeny,
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if d := lim.Evaluate("1.2.3.4", "/login", "POST"); d != Allow {
		t.Fatalf("after update should Allow (bucket reset), got %v", d)
	}
}

func TestUpdate_InvalidKeepsOld(t *testing.T) {
	lim := newTestLimiter(t, Config{
		Enabled:              true,
		LoginPaths:           []string{"/login"},
		MaxAttemptsPerMinute: 2,
		Action:               ActionDeny,
	})
	if err := lim.Update(Config{Enabled: true /* missing LoginPaths */}); err == nil {
		t.Fatalf("expected error on invalid update")
	}
	if cfg := lim.Config(); cfg.MaxAttemptsPerMinute != 2 {
		t.Fatalf("old config should be retained, got %+v", cfg)
	}
	_, _, _, _, errs := lim.Metrics()
	if errs != 1 {
		t.Fatalf("errors should be 1 after invalid update, got %d", errs)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"disabled-empty", Config{}, false},
		{"disabled-bad-action", Config{Action: "tarpit"}, true},
		{"enabled-no-paths", Config{Enabled: true, MaxAttemptsPerMinute: 1}, true},
		{"enabled-empty-path", Config{Enabled: true, LoginPaths: []string{""}, MaxAttemptsPerMinute: 1}, true},
		{"enabled-relative-path", Config{Enabled: true, LoginPaths: []string{"login"}, MaxAttemptsPerMinute: 1}, true},
		{"enabled-zero-attempts", Config{Enabled: true, LoginPaths: []string{"/login"}}, true},
		{"enabled-negative-attempts", Config{Enabled: true, LoginPaths: []string{"/login"}, MaxAttemptsPerMinute: -1}, true},
		{"enabled-over-cap", Config{Enabled: true, LoginPaths: []string{"/login"}, MaxAttemptsPerMinute: maxAttemptsCap + 1}, true},
		{"too-many-paths", Config{Enabled: true, LoginPaths: tooManyPaths(), MaxAttemptsPerMinute: 1}, true},
		{"valid-min", Config{Enabled: true, LoginPaths: []string{"/login"}, MaxAttemptsPerMinute: 1}, false},
		{"valid-full", Config{Enabled: true, LoginPaths: []string{"/login", "/api/auth/"}, Methods: []string{"POST"}, MaxAttemptsPerMinute: 10, Action: ActionDeny}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("want error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func tooManyPaths() []string {
	out := make([]string, maxLoginPaths+1)
	for i := range out {
		out[i] = "/p"
	}
	return out
}

func TestMiddleware_DenyShortCircuits(t *testing.T) {
	var called atomic.Bool
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusOK)
	})
	lim := newTestLimiter(t, Config{
		Enabled:              true,
		LoginPaths:           []string{"/login"},
		MaxAttemptsPerMinute: 1,
		Action:               ActionDeny,
	})
	srv := httptest.NewServer(lim.Middleware(backend))
	defer srv.Close()

	// 1er pass (burst).
	resp, err := http.Post(srv.URL+"/login", "text/plain", strings.NewReader(""))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	// 2e refusé.
	called.Store(false)
	resp, err = http.Post(srv.URL+"/login", "text/plain", strings.NewReader(""))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatalf("expected Retry-After header")
	}
	if called.Load() {
		t.Fatalf("backend should not be called on Deny")
	}
}

func TestMiddleware_OutOfScopePassesThrough(t *testing.T) {
	var called atomic.Bool
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusOK)
	})
	lim := newTestLimiter(t, Config{
		Enabled:              true,
		LoginPaths:           []string{"/login"},
		MaxAttemptsPerMinute: 1,
		Action:               ActionDeny,
	})
	srv := httptest.NewServer(lim.Middleware(backend))
	defer srv.Close()

	for i := 0; i < 50; i++ {
		resp, err := http.Get(srv.URL + "/products")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 out of scope, got %d", resp.StatusCode)
		}
	}
	if !called.Load() {
		t.Fatalf("backend should be called for out-of-scope")
	}
}
