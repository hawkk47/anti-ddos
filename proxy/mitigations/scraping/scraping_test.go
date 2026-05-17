package scraping

import (
	"net/http"
	"net/http/httptest"
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

func defaultUAList() []string {
	return []string{
		"python-requests",
		"scrapy",
		"curl",
		"wget",
		"headlesschrome",
		"phantomjs",
		"selenium",
		"bot",
		"crawler",
		"spider",
	}
}

// --- reproducer ------------------------------------------------------

// TestReproducer_Scraping_WithoutMitigation prouve qu'un scraper
// minimaliste (python-requests, pas d'Accept-Language, pas
// d'Accept-Encoding) atteint l'upstream sans la moindre friction —
// c'est l'état non protégé.
func TestReproducer_Scraping_WithoutMitigation(t *testing.T) {
	t.Parallel()
	served := 0
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served++
		w.WriteHeader(200)
	})
	srv := httptest.NewServer(upstream)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/catalog", nil)
	req.Header.Set("User-Agent", "python-requests/2.31.0")
	// Volontairement : pas d'Accept-Language, pas d'Accept-Encoding.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if served != 1 {
		t.Fatalf("upstream served=%d, want 1 (proves scraper reaches origin)", served)
	}
}

// TestReproducer_Scraping_WithMitigation_Denies prouve qu'avec
// action=deny + signature UA matchée, la requête est refusée 403
// et l'upstream n'est pas appelé.
func TestReproducer_Scraping_WithMitigation_Denies(t *testing.T) {
	t.Parallel()
	upstreamCalled := false
	upstream := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		upstreamCalled = true
	})
	lim := newLimiter(t, Config{
		Enabled:       true,
		UserAgentDeny: defaultUAList(),
		Action:        "deny",
	})
	srv := httptest.NewServer(lim.Middleware(upstream))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/catalog", nil)
	req.Header.Set("User-Agent", "python-requests/2.31.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d, want 403", resp.StatusCode)
	}
	if upstreamCalled {
		t.Fatal("upstream should NOT have been called")
	}
	_, _, _, blocked, _ := lim.Metrics()
	if blocked == 0 {
		t.Fatal("blocked counter should have incremented")
	}
}

// TestReproducer_Scraping_WithMitigation_Logs prouve que action=log
// laisse passer mais incrémente le compteur logged — utile pour
// observer le bruit de fond avant de bloquer.
func TestReproducer_Scraping_WithMitigation_Logs(t *testing.T) {
	t.Parallel()
	served := 0
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served++
		w.WriteHeader(200)
	})
	lim := newLimiter(t, Config{
		Enabled:       true,
		UserAgentDeny: defaultUAList(),
		Action:        "log",
	})
	srv := httptest.NewServer(lim.Middleware(upstream))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/catalog", nil)
	req.Header.Set("User-Agent", "Scrapy/2.11")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || served != 1 {
		t.Fatalf("log mode should pass through: code=%d served=%d", resp.StatusCode, served)
	}
	_, _, logged, _, _ := lim.Metrics()
	if logged == 0 {
		t.Fatal("logged counter should have incremented")
	}
}

// --- unit ------------------------------------------------------------

func TestEvaluate_DisabledPassesThrough(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: false})
	h := http.Header{}
	h.Set("User-Agent", "python-requests/2.31")
	if d, _ := lim.Evaluate(h); d != Allow {
		t.Fatalf("disabled: got %v, want Allow", d)
	}
	ev, m, _, _, _ := lim.Metrics()
	if ev != 0 || m != 0 {
		t.Fatalf("disabled should not touch counters: ev=%d m=%d", ev, m)
	}
}

func TestEvaluate_HumanBrowserAllows(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{
		Enabled:               true,
		UserAgentDeny:         defaultUAList(),
		RequireAcceptLanguage: true,
		RequireAcceptEncoding: true,
		Action:                "deny",
	})
	h := http.Header{}
	h.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "+
		"(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
	h.Set("Accept-Language", "fr-FR,fr;q=0.9,en;q=0.8")
	h.Set("Accept-Encoding", "gzip, deflate, br")
	d, reasons := lim.Evaluate(h)
	if d != Allow {
		t.Fatalf("got %v, want Allow (reasons=%v)", d, reasons)
	}
}

func TestEvaluate_UserAgentMatchCaseInsensitive(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{
		Enabled:       true,
		UserAgentDeny: []string{"scrapy"},
		Action:        "deny",
	})
	h := http.Header{}
	h.Set("User-Agent", "Scrapy/2.11 (+https://scrapy.org)")
	d, reasons := lim.Evaluate(h)
	if d != Deny {
		t.Fatalf("got %v, want Deny", d)
	}
	if len(reasons) != 1 || reasons[0] != "ua:scrapy" {
		t.Fatalf("reasons=%v", reasons)
	}
}

func TestEvaluate_MissingAcceptLanguage(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{
		Enabled:               true,
		RequireAcceptLanguage: true,
		Action:                "log",
	})
	h := http.Header{}
	h.Set("User-Agent", "Mozilla/5.0")
	h.Set("Accept-Encoding", "gzip")
	d, reasons := lim.Evaluate(h)
	if d != Log {
		t.Fatalf("got %v, want Log", d)
	}
	if len(reasons) != 1 || reasons[0] != "missing:accept-language" {
		t.Fatalf("reasons=%v", reasons)
	}
}

func TestEvaluate_MissingAcceptEncoding(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{
		Enabled:               true,
		RequireAcceptEncoding: true,
		Action:                "deny",
	})
	h := http.Header{}
	h.Set("User-Agent", "Mozilla/5.0")
	h.Set("Accept-Language", "en-US")
	d, reasons := lim.Evaluate(h)
	if d != Deny {
		t.Fatalf("got %v, want Deny", d)
	}
	if len(reasons) != 1 || reasons[0] != "missing:accept-encoding" {
		t.Fatalf("reasons=%v", reasons)
	}
}

func TestEvaluate_MultipleSignals(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{
		Enabled:               true,
		UserAgentDeny:         []string{"curl"},
		RequireAcceptLanguage: true,
		Action:                "deny",
	})
	h := http.Header{}
	h.Set("User-Agent", "curl/8.4.0")
	// Pas d'Accept-Language non plus.
	d, reasons := lim.Evaluate(h)
	if d != Deny {
		t.Fatalf("got %v, want Deny", d)
	}
	if len(reasons) != 2 {
		t.Fatalf("reasons=%v, want 2 distinct signals", reasons)
	}
}

func TestEvaluate_EmptyUserAgentNotConsideredAsMatch(t *testing.T) {
	t.Parallel()
	// Pas de regression: si UA est vide, on n'invente pas un match
	// (sinon `strings.Contains("", "")` retournerait true).
	lim := newLimiter(t, Config{
		Enabled:       true,
		UserAgentDeny: []string{"bot"},
		Action:        "deny",
	})
	h := http.Header{}
	d, _ := lim.Evaluate(h)
	if d != Allow {
		t.Fatalf("empty UA with only UA signal should Allow, got %v", d)
	}
}

func TestUpdate_AppliesNewConfig(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{
		Enabled:       true,
		UserAgentDeny: []string{"foo"},
		Action:        "deny",
	})
	h := http.Header{}
	h.Set("User-Agent", "scrapy/2.11")
	if d, _ := lim.Evaluate(h); d != Allow {
		t.Fatalf("before update: got %v, want Allow", d)
	}
	if err := lim.Update(Config{
		Enabled:       true,
		UserAgentDeny: []string{"scrapy"},
		Action:        "deny",
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if d, _ := lim.Evaluate(h); d != Deny {
		t.Fatalf("after update: got %v, want Deny", d)
	}
}

func TestUpdate_RejectsInvalidKeepsOld(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{
		Enabled:       true,
		UserAgentDeny: []string{"scrapy"},
		Action:        "deny",
	})
	if err := lim.Update(Config{Enabled: true}); err == nil {
		t.Fatal("Update should have rejected config without any signal")
	}
	if len(lim.Config().UserAgentDeny) == 0 {
		t.Fatal("old config should remain")
	}
	_, _, _, _, errs := lim.Metrics()
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
		{"disabled is ok", Config{Enabled: false}, false},
		{"ua only", Config{Enabled: true, UserAgentDeny: []string{"bot"}, Action: "deny"}, false},
		{"accept-language only", Config{Enabled: true, RequireAcceptLanguage: true, Action: "log"}, false},
		{"accept-encoding only", Config{Enabled: true, RequireAcceptEncoding: true, Action: "log"}, false},
		{"empty action ok", Config{Enabled: true, UserAgentDeny: []string{"bot"}}, false},
		{"bad action", Config{Enabled: true, UserAgentDeny: []string{"bot"}, Action: "yolo"}, true},
		{"no signal enabled", Config{Enabled: true, Action: "deny"}, true},
		{"empty ua entry", Config{Enabled: true, UserAgentDeny: []string{""}, Action: "deny"}, true},
		{"too many ua entries", Config{Enabled: true, UserAgentDeny: make([]string, 129), Action: "deny"}, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "too many ua entries" {
				for i := range tc.cfg.UserAgentDeny {
					tc.cfg.UserAgentDeny[i] = "x"
				}
			}
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestMiddleware_DenyShortCircuits(t *testing.T) {
	t.Parallel()
	called := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	})
	lim := newLimiter(t, Config{
		Enabled:       true,
		UserAgentDeny: []string{"bot"},
		Action:        "deny",
	})
	srv := httptest.NewServer(lim.Middleware(next))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req.Header.Set("User-Agent", "EvilBot/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || called {
		t.Fatalf("code=%d called=%v", resp.StatusCode, called)
	}
}

func TestMiddleware_LogPassesThrough(t *testing.T) {
	t.Parallel()
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(200)
	})
	lim := newLimiter(t, Config{
		Enabled:       true,
		UserAgentDeny: []string{"bot"},
		Action:        "log",
	})
	srv := httptest.NewServer(lim.Middleware(next))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req.Header.Set("User-Agent", "EvilBot/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || !called {
		t.Fatalf("code=%d called=%v", resp.StatusCode, called)
	}
}
