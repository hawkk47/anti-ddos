package cachepoison

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

func defaultHeaders() []string {
	return []string{
		"X-Forwarded-Host",
		"X-Forwarded-Scheme",
		"X-Original-URL",
		"X-Rewrite-URL",
		"X-Host",
		"X-Forwarded-Server",
		"X-HTTP-Method-Override",
		"X-Method-Override",
		"X-Original-Host",
	}
}

// --- reproducer ------------------------------------------------------

// TestReproducer_CachePoison_WithoutMitigation prouve qu'un attaquant
// peut injecter un header `X-Forwarded-Host` qui atteint l'upstream
// intact. Sur un backend vulnérable (qui réfléchit le header dans des
// URL absolues du HTML mises en cache CDN), c'est le primitif de la
// poisoning de cache façon Kettle 2018.
func TestReproducer_CachePoison_WithoutMitigation(t *testing.T) {
	t.Parallel()
	var seen string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-Forwarded-Host")
		w.WriteHeader(200)
	})
	srv := httptest.NewServer(upstream)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req.Header.Set("X-Forwarded-Host", "evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if seen != "evil.example" {
		t.Fatalf("upstream saw %q, want %q (proves attack reaches origin)", seen, "evil.example")
	}
}

// TestReproducer_CachePoison_WithMitigation_Strips prouve que la
// mitigation retire silencieusement le header avant qu'il atteigne
// l'upstream, et que le compteur stripped s'incrémente.
func TestReproducer_CachePoison_WithMitigation_Strips(t *testing.T) {
	t.Parallel()
	var seen string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-Forwarded-Host")
		w.WriteHeader(200)
	})
	lim := newLimiter(t, Config{Enabled: true, Headers: defaultHeaders(), Action: "strip"})
	srv := httptest.NewServer(lim.Middleware(upstream))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req.Header.Set("X-Forwarded-Host", "evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("got %d, want 200 (strip is silent)", resp.StatusCode)
	}
	if seen != "" {
		t.Fatalf("upstream still saw header: %q", seen)
	}
	_, stripped, _, _ := lim.Metrics()
	if stripped == 0 {
		t.Fatal("stripped counter should have incremented")
	}
}

// TestReproducer_CachePoison_WithMitigation_Denies prouve l'opt-in
// `action: deny` : la requête est rejetée en 400 et l'upstream n'est
// jamais appelé.
func TestReproducer_CachePoison_WithMitigation_Denies(t *testing.T) {
	t.Parallel()
	upstreamCalled := false
	upstream := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		upstreamCalled = true
	})
	lim := newLimiter(t, Config{Enabled: true, Headers: defaultHeaders(), Action: "deny"})
	srv := httptest.NewServer(lim.Middleware(upstream))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req.Header.Set("X-Forwarded-Host", "evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", resp.StatusCode)
	}
	if upstreamCalled {
		t.Fatal("upstream should NOT have been called")
	}
	_, _, blocked, _ := lim.Metrics()
	if blocked == 0 {
		t.Fatal("blocked counter should have incremented")
	}
}

// --- unit ------------------------------------------------------------

func TestEvaluate_DisabledPassesThrough(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: false})
	h := http.Header{}
	h.Set("X-Forwarded-Host", "evil")
	if d, _ := lim.Evaluate(h); d != Allow {
		t.Fatalf("disabled: got %v, want Allow", d)
	}
	ev, st, bl, _ := lim.Metrics()
	if ev != 0 || st != 0 || bl != 0 {
		t.Fatalf("disabled should not touch counters: ev=%d st=%d bl=%d", ev, st, bl)
	}
}

func TestEvaluate_NoDangerousHeaderAllows(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, Headers: defaultHeaders(), Action: "strip"})
	h := http.Header{}
	h.Set("User-Agent", "curl/8.0")
	h.Set("Accept", "*/*")
	d, hits := lim.Evaluate(h)
	if d != Allow {
		t.Fatalf("got %v, want Allow", d)
	}
	if len(hits) != 0 {
		t.Fatalf("hits=%v, want empty", hits)
	}
}

func TestEvaluate_StripActionReportsHits(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, Headers: defaultHeaders(), Action: "strip"})
	h := http.Header{}
	h.Set("X-Forwarded-Host", "evil")
	h.Set("X-Original-URL", "/admin")
	h.Set("User-Agent", "curl/8.0")
	d, hits := lim.Evaluate(h)
	if d != Strip {
		t.Fatalf("got %v, want Strip", d)
	}
	if len(hits) != 2 {
		t.Fatalf("got %d hits, want 2: %v", len(hits), hits)
	}
	_, stripped, _, _ := lim.Metrics()
	if stripped != 2 {
		t.Fatalf("stripped=%d, want 2", stripped)
	}
}

func TestEvaluate_CaseInsensitive(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, Headers: []string{"x-forwarded-host"}, Action: "strip"})
	h := http.Header{}
	h.Set("X-Forwarded-Host", "evil") // http.Header canonicalises on Set
	d, hits := lim.Evaluate(h)
	if d != Strip || len(hits) != 1 {
		t.Fatalf("got d=%v hits=%v, want Strip with 1 hit", d, hits)
	}
}

func TestEvaluate_DenyActionReportsHits(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, Headers: defaultHeaders(), Action: "deny"})
	h := http.Header{}
	h.Set("X-Forwarded-Host", "evil")
	d, hits := lim.Evaluate(h)
	if d != Deny {
		t.Fatalf("got %v, want Deny", d)
	}
	if len(hits) != 1 {
		t.Fatalf("hits=%v, want 1", hits)
	}
}

func TestUpdate_AppliesNewConfig(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, Headers: []string{"X-Foo"}, Action: "strip"})
	h := http.Header{}
	h.Set("X-Forwarded-Host", "evil")
	if d, _ := lim.Evaluate(h); d != Allow {
		t.Fatalf("before update, X-Forwarded-Host not in list: got %v want Allow", d)
	}
	if err := lim.Update(Config{Enabled: true, Headers: []string{"X-Forwarded-Host"}, Action: "strip"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if d, _ := lim.Evaluate(h); d != Strip {
		t.Fatalf("after update: got %v want Strip", d)
	}
}

func TestUpdate_RejectsInvalidKeepsOld(t *testing.T) {
	t.Parallel()
	lim := newLimiter(t, Config{Enabled: true, Headers: defaultHeaders(), Action: "strip"})
	if err := lim.Update(Config{Enabled: true, Headers: nil}); err == nil {
		t.Fatal("Update should have rejected empty Headers")
	}
	if len(lim.Config().Headers) == 0 {
		t.Fatal("old config should remain")
	}
	_, _, _, errs := lim.Metrics()
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
		{"disabled ignores headers", Config{Enabled: false}, false},
		{"ok", Config{Enabled: true, Headers: []string{"X-Foo"}, Action: "strip"}, false},
		{"deny ok", Config{Enabled: true, Headers: []string{"X-Foo"}, Action: "deny"}, false},
		{"empty action ok", Config{Enabled: true, Headers: []string{"X-Foo"}}, false},
		{"bad action", Config{Enabled: true, Headers: []string{"X-Foo"}, Action: "yolo"}, true},
		{"empty headers enabled", Config{Enabled: true}, true},
		{"empty entry", Config{Enabled: true, Headers: []string{""}, Action: "strip"}, true},
		{"too many", Config{Enabled: true, Headers: make([]string, 65), Action: "strip"}, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "too many" {
				for i := range tc.cfg.Headers {
					tc.cfg.Headers[i] = "X-Foo"
				}
			}
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestMiddleware_StripsHeaderSilently(t *testing.T) {
	t.Parallel()
	var seenFwd, seenOriginal string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenFwd = r.Header.Get("X-Forwarded-Host")
		seenOriginal = r.Header.Get("X-Original-URL")
		w.WriteHeader(200)
	})
	lim := newLimiter(t, Config{Enabled: true, Headers: defaultHeaders(), Action: "strip"})
	srv := httptest.NewServer(lim.Middleware(next))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req.Header.Set("X-Forwarded-Host", "evil")
	req.Header.Set("X-Original-URL", "/admin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("got %d want 200", resp.StatusCode)
	}
	if seenFwd != "" || seenOriginal != "" {
		t.Fatalf("upstream still saw headers: fwd=%q orig=%q", seenFwd, seenOriginal)
	}
}

func TestMiddleware_PreservesXForwardedFor(t *testing.T) {
	t.Parallel()
	// XFF n'est PAS dans la liste poisoning (AGENTS.md §6).
	var seen string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(200)
	})
	lim := newLimiter(t, Config{Enabled: true, Headers: defaultHeaders(), Action: "strip"})
	srv := httptest.NewServer(lim.Middleware(next))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if seen != "203.0.113.7" {
		t.Fatalf("XFF should be preserved, got %q", seen)
	}
}
