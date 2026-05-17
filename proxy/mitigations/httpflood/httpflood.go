// Package httpflood implémente une mitigation rate-limit HTTP L7 par
// IP source (token bucket).
//
// Modèle d'attaque : un attaquant inonde le proxy de requêtes HTTP
// valides depuis une IP (ou un petit ensemble) à un rythme dépassant
// la capacité de l'upstream. Contrairement à Slowloris, les requêtes
// sont complètes — c'est le débit qui sature CPU / upstream / sockets.
//
// Mitigation : token bucket par IP. Chaque requête consomme 1 token ;
// la cadence de remplissage est configurable. Quand le bucket est
// vide, la requête reçoit 429 (Too Many Requests).
//
// Mode d'erreur : **fail-closed**. Si la mitigation est activée et
// qu'une erreur interne survient (config invalide, parse RemoteAddr
// échoué), la requête est refusée avec 503. Cf. docs/adr/0003-http-flood-l7-fail-closed.md.
//
// Pure-Go, no panic, no allocation par requête (sync.Map + atomics
// sur les buckets).
//
// Cf. .github/instructions/proxy-data-plane.instructions.md
//
//	docs/threat-model.md#http-flood-l7
package httpflood

import (
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

// Config est la configuration runtime de la mitigation.
//
// Tous les seuils viennent de configs/base/ratelimit.yaml et sont
// poussés ici via Limiter.Update (hot-reload).
type Config struct {
	// Enabled active la mitigation. Si false : pass-through total.
	Enabled bool
	// RequestsPerSecond : cadence de remplissage du bucket par IP.
	// > 0. Représente le débit soutenu autorisé.
	RequestsPerSecond float64
	// Burst : capacité maximale du bucket (rafale instantanée
	// tolérée). >= 1.
	Burst int
	// OnError : "allow" (fail-open) ou "deny" (fail-closed). Défaut
	// pour cette mitigation = "deny". Cf. ADR 0003.
	OnError string
}

// Validate vérifie qu'une config est utilisable.
func (c Config) Validate() error {
	if c.OnError != "" && c.OnError != "allow" && c.OnError != "deny" {
		return errors.New(`OnError must be "allow" or "deny"`)
	}
	if c.Enabled {
		if c.RequestsPerSecond <= 0 {
			return errors.New("RequestsPerSecond must be > 0 when enabled")
		}
		if c.Burst < 1 {
			return errors.New("Burst must be >= 1 when enabled")
		}
	}
	return nil
}

// Limiter applique le rate-limit per-IP. Sûr en concurrence.
type Limiter struct {
	cfg atomic.Pointer[Config]

	// buckets : map[ip]*bucket. sync.Map évite la contention sur
	// le hot path (lookup fréquent, write rare au premier hit).
	buckets sync.Map

	now func() time.Time // injectable pour les tests

	reg metrics.Registry

	evaluated metrics.Counter
	blocked   metrics.Counter
	errs      metrics.Counter
	duration  metrics.Histogram
}

// bucket : état token bucket d'une IP. Tous les accès passent par
// le mutex (taille du critical section ~10 ns, négligeable vs syscall HTTP).
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
		now:       time.Now,
		reg:       reg,
		evaluated: reg.Counter("mitigation_http_flood_l7_evaluated_total"),
		blocked:   reg.Counter("mitigation_http_flood_l7_blocked_total"),
		errs:      reg.Counter("mitigation_http_flood_l7_errors_total"),
		duration:  reg.Histogram("mitigation_http_flood_l7_duration_seconds"),
	}
	c := cfg
	l.cfg.Store(&c)
	return l, nil
}

// Update remplace atomiquement la configuration. Sur erreur,
// l'ancienne reste active (fail-open sur reload — même comportement
// que slowloris : un reload buggé ne doit pas dégrader la prod).
func (l *Limiter) Update(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		l.errs.Inc()
		return err
	}
	c := cfg
	l.cfg.Store(&c)
	return nil
}

// Config retourne un snapshot de la configuration active.
func (l *Limiter) Config() Config { return *l.cfg.Load() }

// Metrics retourne la registry injectée.
func (l *Limiter) Metrics() metrics.Registry { return l.reg }

// Decision : résultat d'une évaluation.
type Decision int

const (
	// Allow : laisser passer.
	Allow Decision = iota
	// Deny : refuser (quota dépassé OU erreur interne en mode deny).
	Deny
)

// Evaluate décide si une requête depuis ip doit être acceptée.
// Sûr en concurrence. Aucune allocation sur le hot path après le
// premier hit par IP.
func (l *Limiter) Evaluate(ip string) Decision {
	start := l.now()
	defer func() { l.duration.Observe(l.now().Sub(start).Seconds()) }()
	l.evaluated.Inc()

	cfg := *l.cfg.Load()
	if !cfg.Enabled {
		return Allow
	}
	if ip == "" {
		// IP non identifiable : fail-closed par défaut si configuré.
		l.errs.Inc()
		if cfg.OnError == "allow" {
			return Allow
		}
		l.blocked.Inc()
		return Deny
	}

	b := l.bucketFor(ip, cfg)
	now := l.now()
	b.mu.Lock()
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * cfg.RequestsPerSecond
		if b.tokens > float64(cfg.Burst) {
			b.tokens = float64(cfg.Burst)
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens -= 1
		b.mu.Unlock()
		return Allow
	}
	b.mu.Unlock()
	l.blocked.Inc()
	return Deny
}

// bucketFor retourne (ou crée) le bucket de ip. Premier hit : bucket
// plein (Burst tokens) pour autoriser la rafale initiale.
func (l *Limiter) bucketFor(ip string, cfg Config) *bucket {
	if v, ok := l.buckets.Load(ip); ok {
		return v.(*bucket)
	}
	nb := &bucket{tokens: float64(cfg.Burst), last: l.now()}
	actual, _ := l.buckets.LoadOrStore(ip, nb)
	return actual.(*bucket)
}

// Middleware enveloppe un http.Handler pour appliquer le rate-limit.
// Sur Deny, répond 429 (quota) ou 503 (erreur interne fail-closed)
// et n'appelle PAS next.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if l.Evaluate(ip) == Deny {
			// On distingue quota (429) vs erreur interne (503).
			// L'erreur interne se traduit par ip == "" OU
			// blocage avec bucket plein-mais-erreur. Pour MVP :
			// ip vide ⇒ 503, sinon ⇒ 429.
			if ip == "" {
				http.Error(w, "service unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP extrait l'IP du client depuis la requête. En production,
// derrière un LB, on lira X-Forwarded-For ; pour MVP, on prend
// RemoteAddr directement (le proxy est en frontal).
//
// Retourne "" si parsing échoue ⇒ déclenche le mode fail-closed.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// Peut-être adresse sans port (rare). Tester en l'état.
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
