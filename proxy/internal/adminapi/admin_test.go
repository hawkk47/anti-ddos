package adminapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"anti-ddos/proxy/internal/metrics"
	"anti-ddos/proxy/mitigations/cachepoison"
	"anti-ddos/proxy/mitigations/concurrency"
	"anti-ddos/proxy/mitigations/credstuff"
	"anti-ddos/proxy/mitigations/hashflood"
	"anti-ddos/proxy/mitigations/http2reset"
	"anti-ddos/proxy/mitigations/httpflood"
	"anti-ddos/proxy/mitigations/largeheader"
	"anti-ddos/proxy/mitigations/rangeamp"
	"anti-ddos/proxy/mitigations/requesthygiene"
	"anti-ddos/proxy/mitigations/scraping"
	"anti-ddos/proxy/mitigations/slowloris"
	"anti-ddos/proxy/mitigations/slowpost"
	"anti-ddos/proxy/mitigations/tlsfingerprint"
	"anti-ddos/proxy/mitigations/tlsreneg"
)

func newTestServer(t *testing.T) (*httptest.Server, *slowloris.Limiter) {
	t.Helper()
	reg := metrics.NewInMemory()
	lim, err := slowloris.New(slowloris.Config{Enabled: false}, reg)
	if err != nil {
		t.Fatalf("limiter: %v", err)
	}
	flood, err := httpflood.New(httpflood.Config{}, reg)
	if err != nil {
		t.Fatalf("flood: %v", err)
	}
	hdr, err := largeheader.New(largeheader.Config{}, reg)
	if err != nil {
		t.Fatalf("hdr: %v", err)
	}
	body, err := slowpost.New(slowpost.Config{}, reg)
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	tlsL, err := tlsreneg.New(tlsreneg.Config{}, reg)
	if err != nil {
		t.Fatalf("tls: %v", err)
	}
	h2, err := http2reset.New(http2reset.Config{}, reg)
	if err != nil {
		t.Fatalf("h2: %v", err)
	}
	hash, err := hashflood.New(hashflood.Config{}, reg)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	rng, err := rangeamp.New(rangeamp.Config{}, reg)
	if err != nil {
		t.Fatalf("rangeamp: %v", err)
	}
	cache, err := cachepoison.New(cachepoison.Config{}, reg)
	if err != nil {
		t.Fatalf("cachepoison: %v", err)
	}
	scrap, err := scraping.New(scraping.Config{}, reg)
	if err != nil {
		t.Fatalf("scraping: %v", err)
	}
	cred, err := credstuff.New(credstuff.Config{}, reg)
	if err != nil {
		t.Fatalf("credstuff: %v", err)
	}
	conc, err := concurrency.New(concurrency.Config{}, reg)
	if err != nil {
		t.Fatalf("concurrency: %v", err)
	}
	hyg, err := requesthygiene.New(requesthygiene.Config{}, reg)
	if err != nil {
		t.Fatalf("requesthygiene: %v", err)
	}
	tlsfp, err := tlsfingerprint.New(tlsfingerprint.Config{}, reg)
	if err != nil {
		t.Fatalf("tlsfingerprint: %v", err)
	}
	srv := httptest.NewServer(Handler(lim, flood, hdr, body, tlsL, h2, hash, rng, cache, scrap, cred, conc, hyg, tlsfp, nil, reg))
	t.Cleanup(srv.Close)
	return srv, lim
}

func TestAdmin_HealthOK(t *testing.T) {
	srv, _ := newTestServer(t)
	resp, err := http.Get(srv.URL + "/_admin/v1/health")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d want 200", resp.StatusCode)
	}
}

func TestAdmin_GetConnections(t *testing.T) {
	srv, _ := newTestServer(t)
	resp, err := http.Get(srv.URL + "/_admin/v1/mitigations/connections")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	var payload connectionsPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload.Rules) != 1 || payload.Rules[0].ID != "slowloris" {
		t.Errorf("rules: got %+v", payload.Rules)
	}
}

func TestAdmin_PutAppliesConfig(t *testing.T) {
	srv, lim := newTestServer(t)
	body := connectionsPayload{
		Rev: 7,
		Rules: []connectionsRule{{
			ID:      "slowloris",
			Enabled: true,
			OnError: "allow",
			Params:  connectionsRuleParams{MaxConnsPerIP: 42},
		}},
	}
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/_admin/v1/mitigations/connections", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d want 200, body=%s", resp.StatusCode, raw)
	}
	cfg := lim.Config()
	if cfg.MaxConnsPerIP != 42 || !cfg.Enabled || cfg.OnError != "allow" {
		t.Errorf("config not applied: %+v", cfg)
	}
}

func TestAdmin_PutRejectsInvalidConfig(t *testing.T) {
	srv, lim := newTestServer(t)
	body := connectionsPayload{
		Rules: []connectionsRule{{
			ID:      "slowloris",
			Enabled: true,
			OnError: "kaboom", // invalide
			Params:  connectionsRuleParams{MaxConnsPerIP: 10},
		}},
	}
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/_admin/v1/mitigations/connections", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: got %d want 400", resp.StatusCode)
	}
	// La config initiale doit être préservée (fail-open sur reload).
	if lim.Config().OnError == "kaboom" {
		t.Errorf("invalid config should not have been applied")
	}
}

func TestAdmin_PutRejectsUnknownFields(t *testing.T) {
	srv, _ := newTestServer(t)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/_admin/v1/mitigations/connections",
		bytes.NewBufferString(`{"rev":1,"rules":[],"extra":42}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("got %d want 400 (unknown fields)", resp.StatusCode)
	}
}

func TestAdmin_RejectsNonLoopback(t *testing.T) {
	// Bypass httptest : on appelle directement le middleware avec
	// un RemoteAddr externe.
	lim, _ := slowloris.New(slowloris.Config{}, metrics.NewInMemory())
	flood, _ := httpflood.New(httpflood.Config{}, metrics.NewInMemory())
	hdr, _ := largeheader.New(largeheader.Config{}, metrics.NewInMemory())
	body, _ := slowpost.New(slowpost.Config{}, metrics.NewInMemory())
	tlsL, _ := tlsreneg.New(tlsreneg.Config{}, metrics.NewInMemory())
	h2, _ := http2reset.New(http2reset.Config{}, metrics.NewInMemory())
	hash, _ := hashflood.New(hashflood.Config{}, metrics.NewInMemory())
	rng, _ := rangeamp.New(rangeamp.Config{}, metrics.NewInMemory())
	cache, _ := cachepoison.New(cachepoison.Config{}, metrics.NewInMemory())
	scrap, _ := scraping.New(scraping.Config{}, metrics.NewInMemory())
	cred, _ := credstuff.New(credstuff.Config{}, metrics.NewInMemory())
	conc, _ := concurrency.New(concurrency.Config{}, metrics.NewInMemory())
	hyg, _ := requesthygiene.New(requesthygiene.Config{}, metrics.NewInMemory())
	tlsfp, _ := tlsfingerprint.New(tlsfingerprint.Config{}, metrics.NewInMemory())
	h := Handler(lim, flood, hdr, body, tlsL, h2, hash, rng, cache, scrap, cred, conc, hyg, tlsfp, nil, metrics.NewInMemory())
	req := httptest.NewRequest(http.MethodGet, "/_admin/v1/health", nil)
	req.RemoteAddr = "203.0.113.7:54321"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-loopback should be forbidden, got %d", rec.Code)
	}
}
