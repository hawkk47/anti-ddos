package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anti-ddos/proxy/internal/metrics"
	"anti-ddos/proxy/mitigations/cachepoison"
	"anti-ddos/proxy/mitigations/credstuff"
	"anti-ddos/proxy/mitigations/hashflood"
	"anti-ddos/proxy/mitigations/http2reset"
	"anti-ddos/proxy/mitigations/httpflood"
	"anti-ddos/proxy/mitigations/largeheader"
	"anti-ddos/proxy/mitigations/rangeamp"
	"anti-ddos/proxy/mitigations/scraping"
	"anti-ddos/proxy/mitigations/slowpost"
)

// chainBundle regroupe les 9 mitigations HTTP-level (tlsreneg et
// slowloris travaillent au niveau listener/connexion, http2reset
// au niveau du serveur HTTP/2 — ces 3 ne participent pas à la chaîne
// handler).
type chainBundle struct {
	flood   *httpflood.Limiter
	hdr     *largeheader.Limiter
	body    *slowpost.Limiter
	hash    *hashflood.Limiter
	rng     *rangeamp.Limiter
	cache   *cachepoison.Limiter
	scrap   *scraping.Limiter
	cred    *credstuff.Limiter
	h2reset *http2reset.Limiter // créé pour parité d'init mais hors chaîne
}

// permissiveConfigs retourne un set de configs qui activent toutes les
// mitigations mais avec des seuils tels qu'un GET / vanilla passe.
// alt=true décale légèrement les seuils pour qu'Update détecte une
// vraie bascule de pointeur.
func permissiveConfigs(alt bool) (
	httpflood.Config,
	largeheader.Config,
	slowpost.Config,
	hashflood.Config,
	rangeamp.Config,
	cachepoison.Config,
	scraping.Config,
	credstuff.Config,
	http2reset.Config,
) {
	floodCfg := httpflood.Config{
		Enabled:           true,
		RequestsPerSecond: 1_000_000,
		Burst:             1_000_000,
		OnError:           "allow",
	}
	hdrCfg := largeheader.Config{
		Enabled:        true,
		MaxHeaderCount: 1024,
		MaxValueBytes:  16 * 1024,
		OnError:        "allow",
	}
	bodyCfg := slowpost.Config{
		Enabled:           true,
		MaxBodyBytes:      16 * 1024 * 1024,
		MinBytesPerSecond: 1,
		GracePeriod:       30 * time.Second,
		OnError:           "allow",
	}
	hashCfg := hashflood.Config{
		Enabled:        true,
		MaxQueryParams: 10_000,
		OnError:        "allow",
	}
	rngCfg := rangeamp.Config{
		Enabled:   true,
		MaxRanges: 64,
		OnError:   "allow",
	}
	// cachepoison: Headers non matchés par un GET / sans ces headers.
	cacheCfg := cachepoison.Config{
		Enabled: true,
		Headers: []string{"X-Forwarded-Host", "X-Original-URL"},
		Action:  "strip",
	}
	// scraping: signal UA non matché par "Mozilla/5.0 bench".
	scrapCfg := scraping.Config{
		Enabled:       true,
		UserAgentDeny: []string{"python-requests", "curl/", "wget"},
		Action:        "deny",
	}
	// credstuff: hors scope pour GET / (path + method ne matchent pas).
	credCfg := credstuff.Config{
		Enabled:              true,
		LoginPaths:           []string{"/login"},
		Methods:              []string{"POST"},
		MaxAttemptsPerMinute: 10_000,
		Action:               "deny",
	}
	h2Cfg := http2reset.Config{
		Enabled:          true,
		MaxResetsPerConn: 1_000,
		Window:           30 * time.Second,
		OnError:          "allow",
	}

	if alt {
		floodCfg.Burst = 500_000
		hdrCfg.MaxHeaderCount = 512
		hashCfg.MaxQueryParams = 5_000
		rngCfg.MaxRanges = 32
		credCfg.MaxAttemptsPerMinute = 9_000
	}
	return floodCfg, hdrCfg, bodyCfg, hashCfg, rngCfg, cacheCfg, scrapCfg, credCfg, h2Cfg
}

// buildChain construit la chaîne handler dans le même ordre que server.go.
// enabled=false ⇒ Configs zero-value (Enabled:false ⇒ passe-plat).
func buildChain(tb testing.TB, enabled bool) (http.Handler, *chainBundle) {
	tb.Helper()
	reg := metrics.NewInMemory()

	var (
		floodCfg httpflood.Config
		hdrCfg   largeheader.Config
		bodyCfg  slowpost.Config
		hashCfg  hashflood.Config
		rngCfg   rangeamp.Config
		cacheCfg cachepoison.Config
		scrapCfg scraping.Config
		credCfg  credstuff.Config
		h2Cfg    http2reset.Config
	)
	if enabled {
		floodCfg, hdrCfg, bodyCfg, hashCfg, rngCfg, cacheCfg, scrapCfg, credCfg, h2Cfg = permissiveConfigs(false)
	}

	flood := mustNew(tb, func() (*httpflood.Limiter, error) { return httpflood.New(floodCfg, reg) })
	hdr := mustNew(tb, func() (*largeheader.Limiter, error) { return largeheader.New(hdrCfg, reg) })
	body := mustNew(tb, func() (*slowpost.Limiter, error) { return slowpost.New(bodyCfg, reg) })
	hash := mustNew(tb, func() (*hashflood.Limiter, error) { return hashflood.New(hashCfg, reg) })
	rng := mustNew(tb, func() (*rangeamp.Limiter, error) { return rangeamp.New(rngCfg, reg) })
	cache := mustNew(tb, func() (*cachepoison.Limiter, error) { return cachepoison.New(cacheCfg, reg) })
	scrap := mustNew(tb, func() (*scraping.Limiter, error) { return scraping.New(scrapCfg, reg) })
	cred := mustNew(tb, func() (*credstuff.Limiter, error) { return credstuff.New(credCfg, reg) })
	h2reset := mustNew(tb, func() (*http2reset.Limiter, error) { return http2reset.New(h2Cfg, reg) })

	final := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Même ordre que server.go : scraping → cache-poison → hash-flood →
	// range-amp → large-header → http-flood-l7 → cred-stuff → slow-post → next.
	chain := scrap.Middleware(
		cache.Middleware(
			hash.Middleware(
				rng.Middleware(
					hdr.Middleware(
						flood.Middleware(
							cred.Middleware(
								body.Middleware(final),
							),
						),
					),
				),
			),
		),
	)
	return chain, &chainBundle{
		flood: flood, hdr: hdr, body: body, hash: hash, rng: rng,
		cache: cache, scrap: scrap, cred: cred, h2reset: h2reset,
	}
}

func mustNew[T any](tb testing.TB, fn func() (T, error)) T {
	tb.Helper()
	v, err := fn()
	if err != nil {
		tb.Fatalf("New: %v", err)
	}
	return v
}

// BenchmarkChain_AllDisabled mesure l'overhead pur de la chaîne quand
// toutes les mitigations sont désactivées : baseline « coût de souscrire »
// à la chaîne sans rien faire.
func BenchmarkChain_AllDisabled(b *testing.B) {
	chain, _ := buildChain(b, false)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 bench")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		chain.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("status=%d", w.Code)
		}
	}
}

// BenchmarkChain_AllEnabledPermissive : toutes les mitigations actives,
// seuils très hauts (rien ne match). Représentatif d'un déploiement
// avec règles larges sur trafic légitime.
func BenchmarkChain_AllEnabledPermissive(b *testing.B) {
	chain, _ := buildChain(b, true)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 bench")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		chain.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("status=%d", w.Code)
		}
	}
}

// BenchmarkChain_ParallelEnabledPermissive : variante parallèle pour
// détecter la contention (sync.Map, atomic.Pointer, mutex). Toute
// mitigation qui prend un lock global apparaîtra ici en dégradation ns/op.
func BenchmarkChain_ParallelEnabledPermissive(b *testing.B) {
	chain, _ := buildChain(b, true)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("User-Agent", "Mozilla/5.0 bench")
		for pb.Next() {
			w := httptest.NewRecorder()
			chain.ServeHTTP(w, req)
		}
	})
}

// TestHotReload_UnderLoad : N goroutines hammer la chaîne pendant
// qu'un reloader bascule les configs en boucle. Vérifie :
//
//   - aucune panique
//   - aucune erreur métrique
//   - toutes les requêtes terminent en 200 (pas de drop, pas de FP)
//
// Test du contrat hot-reload « pas de drop de trafic en cours ».
func TestHotReload_UnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("skip hot-reload stress in -short mode")
	}

	chain, b := buildChain(t, true)
	srv := httptest.NewServer(chain)
	defer srv.Close()

	var (
		ok       atomic.Int64
		bad      atomic.Int64
		failures atomic.Int64
		stop     atomic.Bool
		wg       sync.WaitGroup
	)

	const workers = 32
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{Timeout: 2 * time.Second}
			for !stop.Load() {
				resp, err := client.Get(srv.URL + "/")
				if err != nil {
					failures.Add(1)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					ok.Add(1)
				} else {
					bad.Add(1)
				}
			}
		}()
	}

	// Reloader : alterne entre 2 configs valides pendant 800ms.
	reloadDeadline := time.Now().Add(800 * time.Millisecond)
	wg.Add(1)
	go func() {
		defer wg.Done()
		toggle := false
		for time.Now().Before(reloadDeadline) {
			toggle = !toggle
			updateAll(t, b, toggle)
			time.Sleep(5 * time.Millisecond)
		}
		stop.Store(true)
	}()

	wg.Wait()

	t.Logf("hot-reload stress: ok=%d bad=%d failures=%d",
		ok.Load(), bad.Load(), failures.Load())

	if ok.Load() == 0 {
		t.Fatalf("no successful requests at all (ok=%d bad=%d fail=%d)",
			ok.Load(), bad.Load(), failures.Load())
	}
	if failures.Load() > 0 {
		t.Fatalf("transport-level failures during hot reload: %d", failures.Load())
	}
	if bad.Load() > 0 {
		t.Fatalf("non-200 responses during hot reload: %d (expected 0)", bad.Load())
	}

	checkNoErrors(t, b)
}

// updateAll pousse une variante alt/non-alt des configs sur chaque limiter.
func updateAll(t *testing.T, b *chainBundle, alt bool) {
	t.Helper()
	floodCfg, hdrCfg, bodyCfg, hashCfg, rngCfg, cacheCfg, scrapCfg, credCfg, h2Cfg := permissiveConfigs(alt)

	if err := b.flood.Update(floodCfg); err != nil {
		t.Errorf("flood update: %v", err)
	}
	if err := b.hdr.Update(hdrCfg); err != nil {
		t.Errorf("hdr update: %v", err)
	}
	if err := b.body.Update(bodyCfg); err != nil {
		t.Errorf("body update: %v", err)
	}
	if err := b.hash.Update(hashCfg); err != nil {
		t.Errorf("hash update: %v", err)
	}
	if err := b.rng.Update(rngCfg); err != nil {
		t.Errorf("rng update: %v", err)
	}
	if err := b.cache.Update(cacheCfg); err != nil {
		t.Errorf("cache update: %v", err)
	}
	if err := b.scrap.Update(scrapCfg); err != nil {
		t.Errorf("scrap update: %v", err)
	}
	if err := b.cred.Update(credCfg); err != nil {
		t.Errorf("cred update: %v", err)
	}
	if err := b.h2reset.Update(h2Cfg); err != nil {
		t.Errorf("h2reset update: %v", err)
	}
}

// checkNoErrors interroge les limiters pour s'assurer qu'aucune erreur
// métrique n'a été comptabilisée (config push invalide, etc.).
func checkNoErrors(t *testing.T, b *chainBundle) {
	t.Helper()
	if _, _, _, _, errs := b.cred.Metrics(); errs != 0 {
		t.Errorf("credstuff errors=%d", errs)
	}
	if _, _, _, _, errs := b.scrap.Metrics(); errs != 0 {
		t.Errorf("scraping errors=%d", errs)
	}
}
