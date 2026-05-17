// Package credstuff implémente une mitigation credential-stuffing :
// rate-limit strict par IP, **scopé aux endpoints d'authentification**
// configurés (préfixes de path + méthodes optionnelles).
//
// Modèle d'attaque : l'attaquant rejoue massivement des paires
// (login, password) issues de fuites précédentes contre un endpoint
// `/login`, `/api/auth/*`, etc. Les requêtes sont individuellement
// banales (HTTP valide, taille normale) — seul le **taux d'essais
// d'authentification** par IP est anormal. Le rate-limit global
// `http-flood-l7` est trop permissif pour ce cas : un attaquant
// peut tenir un débit modéré (10–50 req/s) qui passe sous le radar
// flood mais réalise des dizaines de milliers de tests/heure.
//
// AVERTISSEMENT — défense en surface. Contre du credential-stuffing
// **distribué** (botnet, proxies résidentiels rotatifs), un seuil
// per-IP ne suffit pas : il faut une couche comportementale
// (CAPTCHA, MFA, device fingerprint, contrôles applicatifs sur le
// compte cible). Ce module bloque les attaquants depuis peu d'IPs,
// ce qui est la majorité du bruit de fond credential-stuffing.
// Voir docs/threat-model.md#credential-stuffing.
//
// Mitigation : token bucket par IP, alimenté uniquement quand le
// path matche un préfixe `login_paths` ET (si configuré) que la
// méthode est dans `methods`. Hors scope : pass-through total sans
// même incrémenter `evaluated`.
//
// Mode d'erreur : **fail-open**. IP non parsable → la requête passe,
// `errors_total` est incrémenté. Conforme à la règle projet (un bug
// du mitigateur ne doit jamais bloquer le trafic légitime).
//
// Pure-Go, no panic, no allocation par requête (sync.Map + atomics).
//
// Cf. .github/instructions/proxy-data-plane.instructions.md
package credstuff

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"anti-ddos/proxy/internal/blocklist"
	"anti-ddos/proxy/internal/metrics"
)

// Limites de configuration (anti-explosion mémoire / DoS via config).
const (
	maxLoginPaths   = 32
	maxLoginPathLen = 256
	maxMethods      = 8
	maxMethodLen    = 16
	maxAttemptsCap  = 10_000 // borne haute : > 10k/min/IP est aberrant
)

// Action : comportement quand le quota est dépassé.
const (
	ActionLog  = "log"
	ActionDeny = "deny" // défaut
)

// Config est la configuration runtime de la mitigation.
type Config struct {
	// Enabled active la mitigation. Si false : pass-through total.
	Enabled bool
	// LoginPaths : préfixes de path (case-sensitive, comme les URLs HTTP)
	// scopant la mitigation. Une requête dont le path ne commence par
	// AUCUN de ces préfixes est ignorée. Au moins un élément requis
	// quand Enabled.
	LoginPaths []string
	// Methods : méthodes HTTP filtrées (uppercase). Vide = toutes.
	// Défaut conseillé : []string{"POST"}.
	Methods []string
	// MaxAttemptsPerMinute : nombre maximum de tentatives autorisées
	// par IP sur les login paths, par fenêtre d'une minute. > 0 quand
	// Enabled, <= maxAttemptsCap.
	MaxAttemptsPerMinute int
	// Action : "log" ou "deny" (défaut "deny" — credential stuffing
	// est une attaque ciblée, on bloque par défaut).
	Action string
	// BlocklistEnabled active la consultation de la blocklist d'IP
	// poussée par le control plane (ADR 0004). Si false (défaut), seul
	// le rate-limit per-IP v1.1 s'applique. La blocklist effective
	// (entrées + version) est injectée via SetBlocklist au boot ; ce
	// flag décide juste si on la consulte sur le chemin chaud.
	BlocklistEnabled bool
}

// Validate vérifie qu'une config est utilisable.
func (c Config) Validate() error {
	switch c.Action {
	case "", ActionLog, ActionDeny:
	default:
		return fmt.Errorf("Action must be %q or %q", ActionLog, ActionDeny)
	}
	if !c.Enabled {
		return nil
	}
	if len(c.LoginPaths) == 0 {
		return errors.New("LoginPaths must contain at least one entry when enabled")
	}
	if len(c.LoginPaths) > maxLoginPaths {
		return fmt.Errorf("LoginPaths exceeds %d entries", maxLoginPaths)
	}
	for i, p := range c.LoginPaths {
		if p == "" {
			return fmt.Errorf("LoginPaths[%d] is empty", i)
		}
		if len(p) > maxLoginPathLen {
			return fmt.Errorf("LoginPaths[%d] exceeds %d chars", i, maxLoginPathLen)
		}
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("LoginPaths[%d] must start with '/'", i)
		}
	}
	if len(c.Methods) > maxMethods {
		return fmt.Errorf("Methods exceeds %d entries", maxMethods)
	}
	for i, m := range c.Methods {
		if m == "" {
			return fmt.Errorf("Methods[%d] is empty", i)
		}
		if len(m) > maxMethodLen {
			return fmt.Errorf("Methods[%d] exceeds %d chars", i, maxMethodLen)
		}
	}
	if c.MaxAttemptsPerMinute <= 0 {
		return errors.New("MaxAttemptsPerMinute must be > 0 when enabled")
	}
	if c.MaxAttemptsPerMinute > maxAttemptsCap {
		return fmt.Errorf("MaxAttemptsPerMinute exceeds cap %d", maxAttemptsCap)
	}
	return nil
}

// internalConfig : version précalculée de Config pour le hot path.
// Méthodes uppercase, Action booléenisé, RPS dérivé.
type internalConfig struct {
	cfg        Config
	methods    []string // uppercase, "" si toutes méthodes acceptées
	denyAction bool
	rps        float64 // MaxAttemptsPerMinute / 60
	burst      float64 // MaxAttemptsPerMinute (rafale = quota plein)
}

func buildInternal(cfg Config) *internalConfig {
	ic := &internalConfig{
		cfg:        cfg,
		denyAction: cfg.Action == "" || cfg.Action == ActionDeny,
		rps:        float64(cfg.MaxAttemptsPerMinute) / 60.0,
		burst:      float64(cfg.MaxAttemptsPerMinute),
	}
	if len(cfg.Methods) > 0 {
		ic.methods = make([]string, len(cfg.Methods))
		for i, m := range cfg.Methods {
			ic.methods[i] = strings.ToUpper(m)
		}
	}
	return ic
}

// Decision : résultat d'une évaluation.
type Decision int

const (
	// Allow : laisser passer (hors scope OU quota dispo).
	Allow Decision = iota
	// Log : quota dépassé, action=log → on laisse passer mais on compte.
	Log
	// Deny : quota dépassé, action=deny → 429.
	Deny
)

// Limiter applique le rate-limit credential-stuffing. Sûr en concurrence.
type Limiter struct {
	state atomic.Pointer[internalConfig]

	buckets sync.Map // map[string]*bucket

	// blocklist : IPs interdites poussées par le control plane (ADR 0004).
	// nil-safe : tant que SetBlocklist n'a pas été appelé, le lookup est
	// skippé. Atomic pour autoriser un swap futur sans verrou.
	blocklist atomic.Pointer[blocklist.Set]

	now func() time.Time // injectable pour les tests

	reg metrics.Registry

	evaluated     metrics.Counter
	matched       metrics.Counter
	logged        metrics.Counter
	blocked       metrics.Counter
	blocklistHits metrics.Counter
	errs          metrics.Counter
	duration      metrics.Histogram
}

// bucket : état token bucket d'une IP.
type bucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// New construit un Limiter.
func New(cfg Config, reg metrics.Registry) (*Limiter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if reg == nil {
		reg = metrics.NewInMemory()
	}
	l := &Limiter{
		now:           time.Now,
		reg:           reg,
		evaluated:     reg.Counter("mitigation_credential_stuffing_evaluated_total"),
		matched:       reg.Counter("mitigation_credential_stuffing_matched_total"),
		logged:        reg.Counter("mitigation_credential_stuffing_logged_total"),
		blocked:       reg.Counter("mitigation_credential_stuffing_blocked_total"),
		blocklistHits: reg.Counter("mitigation_credential_stuffing_blocklist_hits_total"),
		errs:          reg.Counter("mitigation_credential_stuffing_errors_total"),
		duration:      reg.Histogram("mitigation_credential_stuffing_duration_seconds"),
	}
	l.state.Store(buildInternal(cfg))
	return l, nil
}

// Update remplace atomiquement la configuration. Fail-open : sur
// config invalide, l'ancienne reste active et errors_total++.
func (l *Limiter) Update(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		l.errs.Inc()
		return err
	}
	l.state.Store(buildInternal(cfg))
	// On purge les buckets : un changement de seuil ne doit pas
	// garder des quotas obsolètes. Pas critique perf (op rare).
	l.buckets.Range(func(k, _ any) bool {
		l.buckets.Delete(k)
		return true
	})
	return nil
}

// Config retourne un snapshot de la configuration active.
func (l *Limiter) Config() Config { return l.state.Load().cfg }

// SetBlocklist installe (ou remplace) la blocklist d'IP consultée
// quand Config.BlocklistEnabled est vrai. Passer nil désactive la
// consultation (utile en test). Opération atomique : safe à chaud.
func (l *Limiter) SetBlocklist(bl *blocklist.Set) {
	l.blocklist.Store(bl)
}

// Blocklist retourne la blocklist installée (peut être nil).
func (l *Limiter) Blocklist() *blocklist.Set { return l.blocklist.Load() }

// Metrics retourne (evaluated, matched, logged, blocked, errors).
func (l *Limiter) Metrics() (uint64, uint64, uint64, uint64, uint64) {
	return l.evaluated.Value(), l.matched.Value(),
		l.logged.Value(), l.blocked.Value(), l.errs.Value()
}

// BlocklistHits retourne le compteur d'IPs bloquées par la blocklist
// (sous-ensemble de blocked).
func (l *Limiter) BlocklistHits() uint64 { return l.blocklistHits.Value() }

// Evaluate décide si une requête depuis ip sur path/method doit être
// acceptée. Hors scope (path/method non matchés) : retour Allow sans
// incrémenter `evaluated` (allocation-free, pas de touch sur les
// métriques pour minimiser le coût du chemin chaud non-login).
func (l *Limiter) Evaluate(ip, path, method string) Decision {
	ic := l.state.Load()
	if !ic.cfg.Enabled {
		return Allow
	}
	if !matchPath(path, ic.cfg.LoginPaths) {
		return Allow
	}
	if !matchMethod(method, ic.methods) {
		return Allow
	}

	// Dans scope : on compte.
	start := l.now()
	defer func() { l.duration.Observe(l.now().Sub(start).Seconds()) }()
	l.evaluated.Inc()
	l.matched.Inc()

	if ip == "" {
		// Fail-open : on laisse passer, errors++.
		l.errs.Inc()
		return Allow
	}

	// Blocklist (ADR 0004) : consultée avant le bucket per-IP. Une IP
	// blocklistée court-circuite le quota classique. Fail-open : si la
	// blocklist n'est pas installée (nil) ou si l'IP n'est pas parsable,
	// on retombe sur le rate-limit v1.1.
	if ic.cfg.BlocklistEnabled {
		if bl := l.blocklist.Load(); bl != nil {
			if addr, err := netip.ParseAddr(ip); err == nil {
				if _, hit := bl.Lookup(addr); hit {
					l.blocklistHits.Inc()
					if ic.denyAction {
						l.blocked.Inc()
						return Deny
					}
					l.logged.Inc()
					return Log
				}
			}
		}
	}

	b := l.bucketFor(ip, ic)
	now := l.now()
	b.mu.Lock()
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * ic.rps
		if b.tokens > ic.burst {
			b.tokens = ic.burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens -= 1
		b.mu.Unlock()
		return Allow
	}
	b.mu.Unlock()

	if ic.denyAction {
		l.blocked.Inc()
		return Deny
	}
	l.logged.Inc()
	return Log
}

func matchPath(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func matchMethod(method string, methods []string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}

func (l *Limiter) bucketFor(ip string, ic *internalConfig) *bucket {
	if v, ok := l.buckets.Load(ip); ok {
		return v.(*bucket)
	}
	nb := &bucket{tokens: ic.burst, last: l.now()}
	actual, _ := l.buckets.LoadOrStore(ip, nb)
	return actual.(*bucket)
}

// Middleware enveloppe un http.Handler. Sur Deny → 429 + Retry-After.
// Sur Log et Allow → next.ServeHTTP.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		switch l.Evaluate(ip, r.URL.Path, r.Method) {
		case Deny:
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many authentication attempts", http.StatusTooManyRequests)
			return
		case Allow, Log:
			next.ServeHTTP(w, r)
		}
	})
}

// clientIP extrait l'IP du client (host de RemoteAddr).
// Retourne "" si parsing échoue ⇒ fail-open (errors++).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if ip := net.ParseIP(r.RemoteAddr); ip != nil {
			return r.RemoteAddr
		}
		return ""
	}
	if net.ParseIP(host) == nil {
		return ""
	}
	return host
}
