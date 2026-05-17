// Package server implements the HTTP reverse proxy data plane.
//
// Pure-Go, no panic, fail-open : si une mitigation interne échoue,
// la requête passe et l'erreur est loguée. Les vraies mitigations
// (rate-limit, WAF) seront branchées via middlewares ultérieurement.
package server

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"anti-ddos/proxy/internal/adminapi"
	"anti-ddos/proxy/internal/blocklist"
	"anti-ddos/proxy/internal/geoip"
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

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// Config est lue depuis l'environnement par cmd/proxy/main.go.
//
// Aucun seuil n'a de défaut "prod" ; les défauts dev pointent loopback.
type Config struct {
	ListenAddr        string        // ex: "127.0.0.1:8080"
	UpstreamURL       string        // ex: "http://127.0.0.1:9000"
	ReadHeaderTimeout time.Duration // anti-Slowloris (headers)
	ReadTimeout       time.Duration // anti-slow-POST (body complet)
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int // anti-large-header

	// AdminListenAddr : listener séparé pour l'API admin (reload).
	// Doit être loopback (127.0.0.1 ou ::1) ; le middleware refusera
	// toute IP source non loopback de toute façon. Vide ⇒ admin
	// désactivé (utile en test).
	AdminListenAddr string

	// AdminAuthToken : token Bearer attendu sur les routes admin
	// hors `/_admin/v1/health` et `/_admin/v1/metrics`. Vide ⇒ auth
	// désactivée (dev uniquement, refusé au boot si AdminListenAddr
	// n'est pas loopback). Cf. control-plane.instructions.md §Sécurité.
	AdminAuthToken string

	// Slowloris : config de la mitigation per-IP. Chargée depuis
	// configs/base/connections.yaml (via le control plane). Si
	// Enabled=false ou MaxConnsPerIP<=0, pass-through total.
	Slowloris slowloris.Config

	// HTTPFlood : rate-limit L7 per-IP (token bucket). Cf.
	// configs/base/ratelimit.yaml et docs/adr/0003-http-flood-l7-fail-closed.md.
	HTTPFlood httpflood.Config

	// LargeHeader : filtre par-requête sur nombre et taille des headers.
	// Cf. configs/base/headers.yaml. Complémentaire au cap global
	// MaxHeaderBytes (stdlib).
	LargeHeader largeheader.Config

	// SlowPost : mesure le débit du body et coupe si trop lent.
	// Cf. configs/base/bodies.yaml.
	SlowPost slowpost.Config

	// TLSReneg : rate-limit des nouveaux handshakes par IP + assertion
	// d'une config TLS sûre (MinVersion>=1.2, Renegotiation refusée).
	// Cf. configs/base/tls.yaml.
	TLSReneg tlsreneg.Config

	// HTTP2Reset : limite les RST_STREAM précoces par connexion HTTP/2
	// (CVE-2023-44487). Cf. configs/base/http2.yaml.
	HTTP2Reset http2reset.Config

	// HashFlood : plafonne le nombre de paramètres dans la query string
	// pour borner le coût de parsing par requête. Cf. configs/base/hashflood.yaml.
	HashFlood hashflood.Config

	// RangeAmp : plafonne le nombre de ranges dans un header Range pour
	// prévenir l'amplification de type Apache Killer (CVE-2011-3192).
	// Cf. configs/base/rangeamp.yaml.
	RangeAmp rangeamp.Config

	// CachePoison : retire (ou rejette) les request-headers "unkeyed"
	// susceptibles d'empoisonner un cache aval. Cf. configs/base/cachepoison.yaml
	// et J. Kettle, "Practical Web Cache Poisoning" (Black Hat 2018).
	CachePoison cachepoison.Config

	// Scraping : détecte les bots/scrapers naïfs par signature
	// (User-Agent + headers manquants). Cf. configs/base/scraping.yaml.
	Scraping scraping.Config

	// CredStuff : rate-limit strict par IP scopé aux endpoints
	// d'authentification (credential stuffing). Cf. configs/base/credstuff.yaml.
	CredStuff credstuff.Config

	// Concurrency : cap global d'in-flight (load shedding / backpressure).
	// Dernier filet anti-saturation : 503 + Retry-After quand le quota est
	// plein. Cf. configs/base/concurrency.yaml et docs/threat-model.md
	// #concurrency-saturation.
	Concurrency concurrency.Config

	// RequestHygiene : politique d'hygiène HTTP appliquée en tête de
	// chaîne (méthode whitelist, TE+CL anti-smuggling, URI bornée).
	// Cf. configs/base/request-hygiene.yaml et docs/threat-model.md
	// #request-hygiene.
	RequestHygiene requesthygiene.Config

	// TLSFingerprint : empreintes JA3/JA4 du ClientHello + blocklist.
	// Bloque au handshake (GetConfigForClient → ErrBlocked) lorsqu'une
	// terminaison TLS est branchée. Sans TLS terminé côté proxy, la
	// mitigation reste dormante (configurable mais inactive).
	// Cf. configs/base/tls-fingerprint.yaml et docs/threat-model.md
	// #ja3-ja4-fingerprint.
	TLSFingerprint tlsfingerprint.Config
}

// Validate vérifie que la configuration est utilisable.
func (c Config) Validate() error {
	if c.ListenAddr == "" {
		return errors.New("ListenAddr required")
	}
	if c.UpstreamURL == "" {
		return errors.New("UpstreamURL required")
	}
	u, err := url.Parse(c.UpstreamURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("UpstreamURL invalid: %q", c.UpstreamURL)
	}
	if c.ReadHeaderTimeout <= 0 || c.ReadTimeout <= 0 ||
		c.WriteTimeout <= 0 || c.IdleTimeout <= 0 {
		return errors.New("timeouts must be > 0")
	}
	if c.MaxHeaderBytes <= 0 {
		return errors.New("MaxHeaderBytes must be > 0")
	}
	if err := c.Slowloris.Validate(); err != nil {
		return fmt.Errorf("slowloris: %w", err)
	}
	if err := c.HTTPFlood.Validate(); err != nil {
		return fmt.Errorf("http_flood_l7: %w", err)
	}
	if err := c.LargeHeader.Validate(); err != nil {
		return fmt.Errorf("large_header: %w", err)
	}
	if err := c.SlowPost.Validate(); err != nil {
		return fmt.Errorf("slow_post: %w", err)
	}
	if err := c.TLSReneg.Validate(); err != nil {
		return fmt.Errorf("tls_renegotiation_flood: %w", err)
	}
	if err := c.HTTP2Reset.Validate(); err != nil {
		return fmt.Errorf("http2_rapid_reset: %w", err)
	}
	if err := c.HashFlood.Validate(); err != nil {
		return fmt.Errorf("hash_flood: %w", err)
	}
	if err := c.RangeAmp.Validate(); err != nil {
		return fmt.Errorf("range_amplification: %w", err)
	}
	if err := c.CachePoison.Validate(); err != nil {
		return fmt.Errorf("cache_poisoning: %w", err)
	}
	if err := c.Scraping.Validate(); err != nil {
		return fmt.Errorf("scraping_aggressif: %w", err)
	}
	if err := c.CredStuff.Validate(); err != nil {
		return fmt.Errorf("credential_stuffing: %w", err)
	}
	if err := c.Concurrency.Validate(); err != nil {
		return fmt.Errorf("concurrency_cap: %w", err)
	}
	if err := c.RequestHygiene.Validate(); err != nil {
		return fmt.Errorf("request_hygiene: %w", err)
	}
	if err := c.TLSFingerprint.Validate(); err != nil {
		return fmt.Errorf("tls_fingerprint: %w", err)
	}
	return nil
}

// Server est le data plane HTTP.
type Server struct {
	cfg      Config
	log      *slog.Logger
	httpSrv  *http.Server
	adminSrv *http.Server // peut être nil si AdminListenAddr == ""
	metrics  metrics.Registry
	// Slowloris : limiter wrappant le listener (peut être nil si
	// désactivé).
	slowloris   *slowloris.Limiter
	httpflood   *httpflood.Limiter
	largehdr    *largeheader.Limiter
	slowpost    *slowpost.Limiter
	tlsreneg    *tlsreneg.Limiter
	h2reset     *http2reset.Limiter
	hashflood   *hashflood.Limiter
	rangeamp    *rangeamp.Limiter
	cachepois   *cachepoison.Limiter
	scraping    *scraping.Limiter
	credstuff   *credstuff.Limiter
	concurrency *concurrency.Limiter
	reqhygiene  *requesthygiene.Limiter
	tlsfp       *tlsfingerprint.Limiter
	// credBlocklist : blocklist d'IP poussée par le control plane
	// (ADR 0004). Consultée par le middleware credstuff avant le bucket
	// per-IP. Phase 1 : exposée via l'admin, pas encore branchée.
	credBlocklist *blocklist.Set
	// listener exposé pour les tests (port :0 ⇒ port effectif inconnu d'avance).
	listener      net.Listener
	adminListener net.Listener
}

// New construit un Server prêt à Run.
func New(cfg Config, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	upstream, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("parse upstream: %w", err)
	}

	reg := metrics.NewInMemory()
	lim, err := slowloris.New(cfg.Slowloris, reg)
	if err != nil {
		return nil, fmt.Errorf("slowloris init: %w", err)
	}
	floodLim, err := httpflood.New(cfg.HTTPFlood, reg)
	if err != nil {
		return nil, fmt.Errorf("http_flood_l7 init: %w", err)
	}
	hdrLim, err := largeheader.New(cfg.LargeHeader, reg)
	if err != nil {
		return nil, fmt.Errorf("large_header init: %w", err)
	}
	bodyLim, err := slowpost.New(cfg.SlowPost, reg)
	if err != nil {
		return nil, fmt.Errorf("slow_post init: %w", err)
	}
	tlsLim, err := tlsreneg.New(cfg.TLSReneg, reg)
	if err != nil {
		return nil, fmt.Errorf("tls_renegotiation_flood init: %w", err)
	}
	h2Lim, err := http2reset.New(cfg.HTTP2Reset, reg)
	if err != nil {
		return nil, fmt.Errorf("http2_rapid_reset init: %w", err)
	}
	hashLim, err := hashflood.New(cfg.HashFlood, reg)
	if err != nil {
		return nil, fmt.Errorf("hash_flood init: %w", err)
	}
	rangeLim, err := rangeamp.New(cfg.RangeAmp, reg)
	if err != nil {
		return nil, fmt.Errorf("range_amplification init: %w", err)
	}
	cacheLim, err := cachepoison.New(cfg.CachePoison, reg)
	if err != nil {
		return nil, fmt.Errorf("cache_poisoning init: %w", err)
	}
	scrapLim, err := scraping.New(cfg.Scraping, reg)
	if err != nil {
		return nil, fmt.Errorf("scraping_aggressif init: %w", err)
	}
	credLim, err := credstuff.New(cfg.CredStuff, reg)
	if err != nil {
		return nil, fmt.Errorf("credential_stuffing init: %w", err)
	}
	concLim, err := concurrency.New(cfg.Concurrency, reg)
	if err != nil {
		return nil, fmt.Errorf("concurrency_cap init: %w", err)
	}
	hygLim, err := requesthygiene.New(cfg.RequestHygiene, reg)
	if err != nil {
		return nil, fmt.Errorf("request_hygiene init: %w", err)
	}
	tlsfpLim, err := tlsfingerprint.New(cfg.TLSFingerprint, reg)
	if err != nil {
		return nil, fmt.Errorf("tls_fingerprint init: %w", err)
	}
	credBlocklist := blocklist.New(reg)
	// ADR 0004 phase 2 : la blocklist est install\u00e9e d\u00e8s le boot. Sa
	// consultation effective d\u00e9pend de cfg.CredStuff.BlocklistEnabled.
	credLim.SetBlocklist(credBlocklist)

	rp := newReverseProxy(upstream, log)

	mux := http.NewServeMux()
	mux.HandleFunc("/_proxy/health", healthHandler)
	// Le rate-limit L7 enveloppe le reverse proxy mais pas /_proxy/health
	// (sondes de santé doivent rester joignables même en surcharge).
	// Ordre de la chaîne (extérieur → intérieur) :
	//   request-hygiene → scraping → cache-poison → hash-flood → range-amp → large-header → http-flood-l7 → concurrency → cred-stuff → slow-post → reverse proxy.
	// request-hygiene court-circuite tout en amont : une requête malformée
	// (méthode hors-whitelist, TE+CL, URI obscure) est rejetée 400 avant
	// même de consommer le moindre token. scraping court-circuite ensuite :
	// token rate-limit ni cycle de parsing aval. cache-poison nettoie ensuite
	// les headers "unkeyed" pour qu'aucune mitigation downstream ne traite du
	// trafic poisoned. hash-flood et range-amp s'exécutent ensuite : ils rejettent
	// une URL ou un header Range toxiques avant tout autre parsing (cap sur
	// strings.Count, aucun accès map). large-header court-circuite avant de
	// consommer un token rate-limit (paquet hostile = pas récompensé).
	// http-flood-l7 régule le débit per-IP ; concurrency cape l'in-flight
	// *global* (load shedding) — il vient juste après le flood per-IP pour
	// absorber les rafales légitimes ou multi-IP qui passent sous le radar du
	// rate-limit par-source. cred-stuff applique son quota strict path-scopé
	// après. slow-post wrap r.Body donc doit rester au plus près du handler
	// upstream.
	mux.Handle("/", hygLim.Middleware(scrapLim.Middleware(cacheLim.Middleware(hashLim.Middleware(rangeLim.Middleware(hdrLim.Middleware(floodLim.Middleware(concLim.Middleware(credLim.Middleware(bodyLim.Middleware(rp)))))))))))

	// HTTP/2 cleartext (h2c) avec mitigation rapid-reset. h2Lim.Middleware
	// observe les annulations précoces (RST_STREAM côté client) ; h2c.NewHandler
	// route les requêtes HTTP/2 sur le mux. ConnContext/ConnState (plus bas)
	// permettent au middleware de tenir un compteur par connexion TCP.
	h2srv := &http2.Server{MaxConcurrentStreams: h2Lim.MaxConcurrentStreams()}
	// geoIP : compteurs par pays (ISO-3166 alpha-2), tout en haut de la
	// chaîne pour observer aussi les requêtes bloquées par les mitigations.
	geoCounter := geoip.New(reg)
	rootHandler := geoCounter.Middleware(h2Lim.Middleware(h2c.NewHandler(withRecover(log, mux), h2srv)))

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           rootHandler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
		ErrorLog:          slogErrorLog(log),
		ConnContext:       h2Lim.ConnContext,
		ConnState:         h2Lim.OnConnState,
	}

	var adminSrv *http.Server
	if cfg.AdminListenAddr != "" {
		if err := requireAdminLoopback(cfg.AdminListenAddr); err != nil {
			return nil, err
		}
		adminMux := adminapi.Handler(lim, floodLim, hdrLim, bodyLim, tlsLim, h2Lim, hashLim, rangeLim, cacheLim, scrapLim, credLim, concLim, hygLim, tlsfpLim, credBlocklist, reg)
		adminHandler := adminapi.BearerAuth(cfg.AdminAuthToken)(adminMux)
		adminSrv = &http.Server{
			Addr:              cfg.AdminListenAddr,
			Handler:           withRecover(log, adminHandler),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    1 << 14,
			ErrorLog:          slogErrorLog(log),
		}
	}

	return &Server{
		cfg:           cfg,
		log:           log,
		httpSrv:       httpSrv,
		adminSrv:      adminSrv,
		metrics:       reg,
		slowloris:     lim,
		httpflood:     floodLim,
		largehdr:      hdrLim,
		slowpost:      bodyLim,
		tlsreneg:      tlsLim,
		h2reset:       h2Lim,
		hashflood:     hashLim,
		rangeamp:      rangeLim,
		cachepois:     cacheLim,
		scraping:      scrapLim,
		credstuff:     credLim,
		concurrency:   concLim,
		reqhygiene:    hygLim,
		tlsfp:         tlsfpLim,
		credBlocklist: credBlocklist,
	}, nil
}

// Slowloris retourne le limiter pour reload à chaud.
func (s *Server) Slowloris() *slowloris.Limiter { return s.slowloris }

// HTTPFlood retourne le limiter L7 pour reload à chaud.
func (s *Server) HTTPFlood() *httpflood.Limiter { return s.httpflood }

// LargeHeader retourne le limiter de headers pour reload à chaud.
func (s *Server) LargeHeader() *largeheader.Limiter { return s.largehdr }

// SlowPost retourne le limiter de body pour reload à chaud.
func (s *Server) SlowPost() *slowpost.Limiter { return s.slowpost }

// TLSReneg retourne le limiter TLS pour reload à chaud.
func (s *Server) TLSReneg() *tlsreneg.Limiter { return s.tlsreneg }

// HTTP2Reset retourne le limiter HTTP/2 rapid-reset pour reload à chaud.
func (s *Server) HTTP2Reset() *http2reset.Limiter { return s.h2reset }

// HashFlood retourne le limiter hash-flood pour reload à chaud.
func (s *Server) HashFlood() *hashflood.Limiter { return s.hashflood }

// RangeAmp retourne le limiter range-amplification pour reload à chaud.
func (s *Server) RangeAmp() *rangeamp.Limiter { return s.rangeamp }

// CachePoison retourne le limiter cache-poisoning pour reload à chaud.
func (s *Server) CachePoison() *cachepoison.Limiter { return s.cachepois }

// Scraping retourne le limiter scraping-aggressif pour reload à chaud.
func (s *Server) Scraping() *scraping.Limiter { return s.scraping }

// CredStuff retourne le limiter credential-stuffing pour reload à chaud.
func (s *Server) CredStuff() *credstuff.Limiter { return s.credstuff }

// Concurrency retourne le limiter concurrency-cap pour reload à chaud.
func (s *Server) Concurrency() *concurrency.Limiter { return s.concurrency }

// RequestHygiene retourne le limiter request-hygiene pour reload à chaud.
func (s *Server) RequestHygiene() *requesthygiene.Limiter { return s.reqhygiene }

// TLSFingerprint retourne le limiter JA3/JA4 pour reload à chaud.
// La mitigation reste dormante tant qu'une terminaison TLS n'est pas
// branchée (GetConfigForClient n'est pas câblé sur *http.Server.TLSConfig
// dans le mode h2c actuel — cf. docs/threat-model.md#ja3-ja4-fingerprint).
func (s *Server) TLSFingerprint() *tlsfingerprint.Limiter { return s.tlsfp }

// CredBlocklist retourne la blocklist d'IP pour le credential-stuffing
// (ADR 0004). Phase 1 : expos\u00e9e via l'admin pour permettre au control
// plane de pousser des entr\u00e9es ; pas encore consult\u00e9e par le middleware.
func (s *Server) CredBlocklist() *blocklist.Set { return s.credBlocklist }

// Metrics retourne la registry interne (pour /metrics futur).
func (s *Server) Metrics() metrics.Registry { return s.metrics }

// Run écoute, sert, et termine proprement quand ctx est annulé.
// Retourne nil sur arrêt propre, error sinon.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.ListenAddr, err)
	}
	s.listener = ln
	// Ordre des wrappers (extérieur → intérieur) :
	//   tls-reneg : rate-limit des nouveaux Accept par IP (rejette
	//               tôt avant tout traitement applicatif).
	//   slowloris : compte les connexions simultanées par IP.
	wrapped := s.tlsreneg.WrapListener(ln)
	wrapped = s.slowloris.Wrap(wrapped)

	if s.adminSrv != nil {
		aln, err := net.Listen("tcp", s.cfg.AdminListenAddr)
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("listen admin %s: %w", s.cfg.AdminListenAddr, err)
		}
		s.adminListener = aln
		s.log.Info("admin listening", "addr", aln.Addr().String())
	}

	s.log.Info("listening",
		"addr", ln.Addr().String(),
		"upstream", s.cfg.UpstreamURL,
		"slowloris_enabled", s.cfg.Slowloris.Enabled,
		"slowloris_max_per_ip", s.cfg.Slowloris.MaxConnsPerIP,
	)

	errCh := make(chan error, 2)
	go func() {
		errCh <- s.httpSrv.Serve(wrapped)
	}()
	if s.adminSrv != nil {
		go func() {
			errCh <- s.adminSrv.Serve(s.adminListener)
		}()
	}

	select {
	case <-ctx.Done():
		s.log.Info("shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var errs []error
		if err := s.httpSrv.Shutdown(shutdownCtx); err != nil {
			errs = append(errs, fmt.Errorf("shutdown: %w", err))
		}
		if s.adminSrv != nil {
			if err := s.adminSrv.Shutdown(shutdownCtx); err != nil {
				errs = append(errs, fmt.Errorf("admin shutdown: %w", err))
			}
		}
		return errors.Join(errs...)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// Addr retourne l'adresse réelle d'écoute (utile en test avec port :0).
// Retourne "" si Run n'a pas encore commencé à écouter.
func (s *Server) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// AdminAddr retourne l'adresse réelle d'écoute admin ("" si pas configurée).
func (s *Server) AdminAddr() string {
	if s.adminListener == nil {
		return ""
	}
	return s.adminListener.Addr().String()
}

// healthHandler répond 200 OK pour les sondes de santé.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// withRecover protège le serveur de tout panic dans un handler.
// Conformément à la règle fail-open + no-panic du data plane.
func withRecover(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Error("handler panic recovered",
					"err", fmt.Sprint(rec),
					"path", r.URL.Path,
					"method", r.Method,
				)
				// Réponse générique 502 ; on ne fuit aucun détail interne.
				if !headerSent(w) {
					http.Error(w, "bad gateway", http.StatusBadGateway)
				}
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// newReverseProxy construit un reverse proxy stdlib avec :
//   - X-Forwarded-For : append (jamais overwrite) — règle proxy-data-plane
//   - X-Forwarded-Proto, X-Real-IP : ajoutés
//   - timeouts transport, pas de connexion KeepAlive infinie
//   - error handler qui logue et renvoie 502 (fail-open côté upstream :
//     si l'upstream tombe, on retourne 502, on ne crash pas).
func newReverseProxy(upstream *url.URL, log *slog.Logger) *httputil.ReverseProxy {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.SetXForwarded() // ajoute X-Forwarded-For/Host/Proto

			// X-Real-IP : IP du peer (avant ajout XFF).
			if host, _, err := net.SplitHostPort(pr.In.RemoteAddr); err == nil {
				pr.Out.Header.Set("X-Real-IP", host)
			}

			// Garantir append-only sur XFF (SetXForwarded gère déjà
			// l'append si la requête entrante en avait un — on
			// re-vérifie pour être explicite).
			if existing := pr.In.Header.Get("X-Forwarded-For"); existing != "" {
				pr.Out.Header.Set("X-Forwarded-For", appendXFF(existing, pr.In.RemoteAddr))
			}
		},
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Warn("upstream error",
				"err", err.Error(),
				"path", r.URL.Path,
				"method", r.Method,
			)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
	return rp
}

// appendXFF ajoute l'IP du peer à un X-Forwarded-For existant.
func appendXFF(existing, remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return existing
	}
	return existing + ", " + host
}

// headerSent : best-effort pour éviter d'écrire sur une réponse déjà
// committée. Le stdlib ne l'expose pas directement ; on fait un test
// défensif.
func headerSent(w http.ResponseWriter) bool {
	type checker interface{ Written() bool }
	if c, ok := w.(checker); ok {
		return c.Written()
	}
	return false
}

// slogErrorLog wrappe un *slog.Logger pour http.Server.ErrorLog.
func slogErrorLog(log *slog.Logger) *stdlog.Logger {
	return stdlog.New(&httpStdWriter{log: log}, "", 0)
}

// requireAdminLoopback fail-fast au boot : l'admin API doit binder
// loopback. C'est une règle dure (cf. adminapi/admin.go: middleware
// loopbackOnly qui rejette 403 toute IP source non loopback). Si on
// laissait passer un bind 0.0.0.0, toutes les requêtes seraient 403
// sans qu'on comprenne pourquoi — mieux vaut refuser au boot.
//
// Le Bearer (cfg.AdminAuthToken) est une défense en profondeur qui
// s'ajoute à loopback-only mais ne le remplace pas.
func requireAdminLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("admin listen address invalid %q: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("admin listen address %q binds all interfaces; must be loopback (127.0.0.0/8 or ::1)", addr)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("admin listen address %q is non-loopback; must be 127.0.0.0/8 or ::1", addr)
}

type httpStdWriter struct{ log *slog.Logger }

// Write satisfait io.Writer ; http.Server passe par log.Logger.Output.
func (h *httpStdWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	h.log.Warn("http.Server", "msg", msg)
	return len(p), nil
}
