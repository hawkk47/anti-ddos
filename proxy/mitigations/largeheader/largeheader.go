// Package largeheader implémente la mitigation `large-header`.
//
// Vecteur : un client envoie des headers HTTP énormes (cookies de
// plusieurs Mo, User-Agent géant) ou un nombre démesuré de headers
// distincts, pour saturer la mémoire du proxy ou faire dégénérer
// l'algorithme de parsing.
//
// Le stdlib Go pose déjà une borne globale via `Server.MaxHeaderBytes`
// (défaut 1 MiB) — appliquée AVANT que les handlers ne s'exécutent.
// Cette mitigation ajoute deux contrôles plus granulaires que stdlib
// n'expose pas :
//
//   - max_header_count   : nombre maximal d'entrées Header distinctes.
//   - max_value_bytes    : taille maximale de la valeur d'un header.
//
// Refus → HTTP 431 Request Header Fields Too Large.
//
// Mode `on_error` :
//   - "allow" (défaut, conforme AGENTS.md §3 fail-open data plane)
//   - "deny"  (opt-in)
//
// Pure-Go, cross-platform, allocation-light.
package largeheader

import (
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

// Config décrit la règle large-header.
type Config struct {
	Enabled        bool   `json:"enabled"`
	MaxHeaderCount int    `json:"max_header_count"`
	MaxValueBytes  int    `json:"max_value_bytes"`
	OnError        string `json:"on_error"` // "allow" | "deny"
}

// Validate retourne une erreur si la config est inutilisable.
func (c Config) Validate() error {
	if c.Enabled {
		if c.MaxHeaderCount < 1 {
			return errors.New("max_header_count must be >= 1 when enabled")
		}
		if c.MaxHeaderCount > 10_000 {
			return fmt.Errorf("max_header_count %d > 10000 (sanity cap)", c.MaxHeaderCount)
		}
		if c.MaxValueBytes < 1 {
			return errors.New("max_value_bytes must be >= 1 when enabled")
		}
		if c.MaxValueBytes > 16*1024*1024 {
			return fmt.Errorf("max_value_bytes %d > 16 MiB (sanity cap)", c.MaxValueBytes)
		}
	}
	switch c.OnError {
	case "", "allow", "deny":
	default:
		return fmt.Errorf("on_error must be allow|deny, got %q", c.OnError)
	}
	return nil
}

// Decision encode la sortie d'Evaluate.
type Decision int

const (
	// Allow : la requête passe.
	Allow Decision = iota
	// Deny : la requête doit être rejetée (HTTP 431).
	Deny
)

// Limiter applique la règle large-header.
//
// L'objet est sûr en concurrence. La config est swappable à chaud via
// Update sans drop de requêtes en cours (atomic.Pointer).
type Limiter struct {
	cfg     atomic.Pointer[Config]
	metrics struct {
		evaluated metrics.Counter
		blocked   metrics.Counter
		errors    metrics.Counter
		duration  metrics.Histogram
	}
	now func() time.Time
}

// New construit un Limiter avec la config initiale et enregistre les
// métriques dans reg.
func New(cfg Config, reg metrics.Registry) (*Limiter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("largeheader: invalid initial config: %w", err)
	}
	l := &Limiter{now: time.Now}
	c := cfg
	l.cfg.Store(&c)
	l.metrics.evaluated = reg.Counter("mitigation_large_header_evaluated_total")
	l.metrics.blocked = reg.Counter("mitigation_large_header_blocked_total")
	l.metrics.errors = reg.Counter("mitigation_large_header_errors_total")
	l.metrics.duration = reg.Histogram("mitigation_large_header_duration_seconds")
	return l, nil
}

// Update remplace atomiquement la config. Fail-open sur erreur :
// l'ancienne config reste active.
func (l *Limiter) Update(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		l.metrics.errors.Inc()
		return fmt.Errorf("largeheader: invalid config: %w", err)
	}
	c := cfg
	l.cfg.Store(&c)
	return nil
}

// Config retourne une copie de la config courante.
func (l *Limiter) Config() Config {
	return *l.cfg.Load()
}

// Metrics expose les compteurs pour debug/admin.
func (l *Limiter) Metrics() (evaluated, blocked, errs uint64) {
	return l.metrics.evaluated.Value(), l.metrics.blocked.Value(), l.metrics.errors.Value()
}

// Evaluate inspecte les headers et décide. Allocation-free (parcours
// du map uniquement).
func (l *Limiter) Evaluate(h http.Header) Decision {
	start := l.now()
	defer func() { l.metrics.duration.Observe(l.now().Sub(start).Seconds()) }()

	cfg := l.cfg.Load()
	if !cfg.Enabled {
		return Allow
	}
	l.metrics.evaluated.Inc()

	count := 0
	for _, values := range h {
		count++
		if count > cfg.MaxHeaderCount {
			l.metrics.blocked.Inc()
			return Deny
		}
		for _, v := range values {
			if len(v) > cfg.MaxValueBytes {
				l.metrics.blocked.Inc()
				return Deny
			}
		}
	}
	return Allow
}

// Middleware retourne un http.Handler qui filtre les requêtes avant
// de les passer à next. Sur Deny, répond HTTP 431.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch l.Evaluate(r.Header) {
		case Allow:
			next.ServeHTTP(w, r)
		case Deny:
			http.Error(w, "request header fields too large", http.StatusRequestHeaderFieldsTooLarge)
		}
	})
}
