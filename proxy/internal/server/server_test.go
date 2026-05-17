package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// startProxy démarre un Server avec port éphémère, retourne son URL et
// une fonction d'arrêt. Loopback uniquement.
func startProxy(t *testing.T, upstreamURL string) (string, func()) {
	t.Helper()
	cfg := Config{
		ListenAddr:        "127.0.0.1:0",
		UpstreamURL:       upstreamURL,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    1 << 14,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.Run(ctx)
		close(done)
	}()
	// Attendre que le listener soit prêt (port :0 ⇒ Addr connu après
	// net.Listen). On poll brièvement pour rester portable.
	deadline := time.Now().Add(2 * time.Second)
	for srv.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if srv.Addr() == "" {
		cancel()
		<-done
		t.Fatalf("server did not start within deadline")
	}
	return "http://" + srv.Addr(), func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("server did not stop within 5s")
		}
	}
}

func TestProxy_ForwardsAndAddsHeaders(t *testing.T) {
	var (
		gotXFF, gotXRI, gotProto, gotHost string
		gotPath                           string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
		gotXRI = r.Header.Get("X-Real-IP")
		gotProto = r.Header.Get("X-Forwarded-Proto")
		gotHost = r.Header.Get("X-Forwarded-Host")
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "hello from upstream")
	}))
	defer upstream.Close()

	proxyURL, stop := startProxy(t, upstream.URL)
	defer stop()

	resp, err := http.Get(proxyURL + "/foo")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from upstream" {
		t.Errorf("body: got %q", string(body))
	}
	if gotPath != "/foo" {
		t.Errorf("path forwarded: got %q want /foo", gotPath)
	}
	if !strings.HasPrefix(gotXFF, "127.0.0.1") {
		t.Errorf("X-Forwarded-For: got %q, want starting with 127.0.0.1", gotXFF)
	}
	if gotXRI != "127.0.0.1" {
		t.Errorf("X-Real-IP: got %q, want 127.0.0.1", gotXRI)
	}
	if gotProto != "http" {
		t.Errorf("X-Forwarded-Proto: got %q, want http", gotProto)
	}
	if gotHost == "" {
		t.Errorf("X-Forwarded-Host should be set")
	}
}

func TestProxy_AppendsExistingXForwardedFor(t *testing.T) {
	var got string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyURL, stop := startProxy(t, upstream.URL)
	defer stop()

	req, err := http.NewRequest(http.MethodGet, proxyURL+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	// Doit être "203.0.113.7, 127.0.0.1" (append, jamais overwrite).
	if !strings.HasPrefix(got, "203.0.113.7") {
		t.Errorf("XFF should preserve incoming value first, got %q", got)
	}
	if !strings.Contains(got, "127.0.0.1") {
		t.Errorf("XFF should append peer IP, got %q", got)
	}
}

func TestProxy_HealthEndpoint(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream should not be called for /_proxy/health")
	}))
	defer upstream.Close()

	proxyURL, stop := startProxy(t, upstream.URL)
	defer stop()

	resp, err := http.Get(proxyURL + "/_proxy/health")
	if err != nil {
		t.Fatalf("GET health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("body: got %q want ok", string(body))
	}
}

func TestProxy_UpstreamDownReturns502(t *testing.T) {
	// Upstream qui n'écoute jamais : adresse loopback réservée mais
	// non bindée → connection refused.
	proxyURL, stop := startProxy(t, "http://127.0.0.1:1") // port 1 = inutilisable
	defer stop()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(proxyURL + "/")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status: got %d want 502 (fail-open ⇒ proxy reste up)", resp.StatusCode)
	}
}

func TestConfig_Validate(t *testing.T) {
	base := Config{
		ListenAddr:        "127.0.0.1:8080",
		UpstreamURL:       "http://127.0.0.1:9000",
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       time.Second,
		WriteTimeout:      time.Second,
		IdleTimeout:       time.Second,
		MaxHeaderBytes:    1024,
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("base config should be valid: %v", err)
	}

	cases := map[string]func(c *Config){
		"empty listen":    func(c *Config) { c.ListenAddr = "" },
		"empty upstream":  func(c *Config) { c.UpstreamURL = "" },
		"bad upstream":    func(c *Config) { c.UpstreamURL = "not-a-url" },
		"zero header to":  func(c *Config) { c.ReadHeaderTimeout = 0 },
		"zero read":       func(c *Config) { c.ReadTimeout = 0 },
		"zero max header": func(c *Config) { c.MaxHeaderBytes = 0 },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := base
			mut(&c)
			if err := c.Validate(); err == nil {
				t.Errorf("expected validation error for %s", name)
			}
		})
	}
}
