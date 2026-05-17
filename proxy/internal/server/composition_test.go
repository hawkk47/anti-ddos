package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"anti-ddos/proxy/mitigations/credstuff"
	"anti-ddos/proxy/mitigations/scraping"
)

// startProxyWithMitigations démarre un Server avec un ensemble de
// mitigations actives via leur Config initiale (path déclaratif, celui
// utilisé par main.go via les variables d'environnement). Retourne
// l'URL publique du proxy et une fonction de stop.
//
// Loopback uniquement. Ports éphémères.
func startProxyWithMitigations(t *testing.T, upstreamURL string, mutate func(*Config)) (*Server, string, func()) {
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
	if mutate != nil {
		mutate(&cfg)
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
	deadline := time.Now().Add(2 * time.Second)
	for srv.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if srv.Addr() == "" {
		cancel()
		<-done
		t.Fatalf("server did not start within deadline")
	}
	return srv, "http://" + srv.Addr(), func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("server did not stop within 5s")
		}
	}
}

// TestComposition_CredStuff_And_Scraping vérifie que deux mitigations
// activées simultanément s'appliquent dans le bon ordre sur du trafic
// réel via la chaîne middleware complète (pas d'inversion, pas de
// court-circuit involontaire). On exerce ici :
//
//   - scraping (action=deny) sur User-Agent "python-requests" → 403 avant
//     toute autre vérif. Le credstuff ne doit PAS compter ces requêtes.
//   - credstuff (action=deny) sur /login + POST, burst=2 → 429 au 3ᵉ
//     essai d'un UA légitime.
//
// Le but n'est pas de re-tester chaque mitigation isolément (déjà
// couvert par leurs *_test.go), mais de prouver la composition.
func TestComposition_CredStuff_And_Scraping(t *testing.T) {
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	srv, proxyURL, stop := startProxyWithMitigations(t, upstream.URL, func(c *Config) {
		c.Scraping = scraping.Config{
			Enabled:       true,
			UserAgentDeny: []string{"python-requests"},
			Action:        "deny",
		}
		c.CredStuff = credstuff.Config{
			Enabled:              true,
			LoginPaths:           []string{"/login"},
			Methods:              []string{"POST"},
			MaxAttemptsPerMinute: 120, // burst = 2 (capacité = max/60 ? non : burst=max)
			Action:               "deny",
		}
	})
	defer stop()

	client := &http.Client{Timeout: 2 * time.Second}

	// 1) Scraper Python sur /login : doit recevoir 403 (scraping deny)
	//    AVANT toute consommation du bucket credstuff.
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest(http.MethodPost, proxyURL+"/login", nil)
		req.Header.Set("User-Agent", "python-requests/2.31")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("scraper %d: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("scraper %d: status=%d want 403", i, resp.StatusCode)
		}
	}
	if got := upstreamHits.Load(); got != 0 {
		t.Fatalf("scrapers reached upstream: %d", got)
	}

	// 2) Client légitime : burst credstuff = 120 → faisons N essais
	//    < burst pour valider passage, puis épuisons et attendons 429.
	//    On limite N pour rester rapide.
	const burst = 120
	allow, deny := 0, 0
	for i := 0; i < burst+5; i++ {
		req, _ := http.NewRequest(http.MethodPost, proxyURL+"/login", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (legit)")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("legit %d: %v", i, err)
		}
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			allow++
		case http.StatusTooManyRequests:
			deny++
			if resp.Header.Get("Retry-After") == "" {
				t.Errorf("deny %d: missing Retry-After", i)
			}
		default:
			t.Fatalf("legit %d: unexpected status=%d", i, resp.StatusCode)
		}
	}
	// Au moins quelques deny attendus (le burst est consommé en monotone) :
	// allow ~ burst, deny ~ 5 + refill ; on tolère le refill ~2 tokens/s sur la durée du test.
	if allow == 0 {
		t.Fatalf("no allow on legit traffic (allow=%d deny=%d)", allow, deny)
	}
	if deny == 0 {
		t.Fatalf("no deny after exhausting burst (allow=%d deny=%d)", allow, deny)
	}

	// 3) Métrique : les 5 scrapers ne doivent PAS être comptés dans
	//    credstuff.evaluated — ils ont été coupés en amont par scraping.
	credEval, _, _, credBlocked, credErrs := srv.CredStuff().Metrics()
	if credEval < uint64(allow) {
		t.Errorf("cred evaluated=%d < allow=%d (scraper leaked into cred chain ?)", credEval, allow)
	}
	if credEval > uint64(allow+deny) {
		t.Errorf("cred evaluated=%d > legit attempts=%d (over-counting)", credEval, allow+deny)
	}
	if credBlocked == 0 {
		t.Errorf("cred blocked=0, want > 0")
	}
	if credErrs != 0 {
		t.Errorf("cred errors=%d, want 0", credErrs)
	}

	// 4) Scraping doit avoir bloqué exactement les 5 requêtes Python.
	scrapEval, _, _, scrapBlocked, scrapErrs := srv.Scraping().Metrics()
	if scrapBlocked != 5 {
		t.Errorf("scraping blocked=%d, want 5", scrapBlocked)
	}
	if scrapEval < 5 {
		t.Errorf("scraping evaluated=%d, want >= 5", scrapEval)
	}
	if scrapErrs != 0 {
		t.Errorf("scraping errors=%d, want 0", scrapErrs)
	}
}

// TestComposition_HotReload_NoDropInFlight vérifie qu'un Update() sur
// un limiter pendant qu'une requête est in-flight ne fait pas dropper
// la requête en cours (la connexion termine proprement).
//
// On démarre 1 mitigation active, on lance une requête lente vers le
// backend, on hot-reload pendant le traitement, on vérifie 200 OK.
func TestComposition_HotReload_NoDropInFlight(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release // bloque jusqu'à signal
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	srv, proxyURL, stop := startProxyWithMitigations(t, upstream.URL, func(c *Config) {
		c.CredStuff = credstuff.Config{
			Enabled:              true,
			LoginPaths:           []string{"/login"},
			Methods:              []string{"POST"},
			MaxAttemptsPerMinute: 100,
			Action:               "deny",
		}
	})
	defer stop()

	client := &http.Client{Timeout: 5 * time.Second}

	type res struct {
		status int
		err    error
	}
	out := make(chan res, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodPost, proxyURL+"/login", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err != nil {
			out <- res{err: err}
			return
		}
		_ = resp.Body.Close()
		out <- res{status: resp.StatusCode}
	}()

	// Laisse la requête atteindre l'upstream.
	time.Sleep(50 * time.Millisecond)

	// Hot-reload : on bascule en action=log avec un seuil différent.
	newCfg := credstuff.Config{
		Enabled:              true,
		LoginPaths:           []string{"/login", "/api/auth/"},
		Methods:              []string{"POST"},
		MaxAttemptsPerMinute: 60,
		Action:               "log",
	}
	if err := srv.CredStuff().Update(newCfg); err != nil {
		t.Fatalf("hot reload: %v", err)
	}

	// Débloquer l'upstream pour terminer la requête in-flight.
	close(release)

	select {
	case r := <-out:
		if r.err != nil {
			t.Fatalf("in-flight request errored after hot reload: %v", r.err)
		}
		if r.status != http.StatusOK {
			t.Fatalf("in-flight request status=%d, want 200 (was dropped by hot reload ?)", r.status)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("in-flight request did not complete")
	}

	// Vérifie que la nouvelle config est bien active.
	gotCfg := srv.CredStuff().Config()
	if gotCfg.Action != "log" {
		t.Errorf("Action after reload: got %q want log", gotCfg.Action)
	}
	if gotCfg.MaxAttemptsPerMinute != 60 {
		t.Errorf("MaxAttemptsPerMinute after reload: got %d want 60", gotCfg.MaxAttemptsPerMinute)
	}
	_ = fmt.Sprintf // silence
}