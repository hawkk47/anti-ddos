// Package rangeamp implémente la mitigation `range-amplification`.
//
// Vecteur historique : CVE-2011-3192 ("Apache Killer", S. Kingsley
// 2011). Le client envoie un header `Range: bytes=0-,0-1,0-2,...,0-N`
// avec un grand nombre de ranges qui se recouvrent. Le serveur doit
// produire une réponse `multipart/byteranges` qui copie le contenu
// pour chaque range, multipliant la sortie au-delà de la taille du
// fichier original (amplification x10 à x100 sur les cibles
// vulnérables — Apache httpd 1.3/2.x avant 2.2.20).
//
// La défense est triviale et bon marché : compter les ranges dans le
// header avant tout traitement, plafonner à `max_ranges`.
// `strings.Count(header, ",") + 1` est O(longueur header) et n'alloue
// rien. Le coût upstream du parsing puis du multipart n'est jamais
// payé si on rejette tôt.
//
// La RFC 9110 §14.1.2 autorise explicitement le serveur à refuser une
// requête Range "if the entity-tags or range specifications are
// invalid". On répond HTTP 416 Range Not Satisfiable.
//
// Mode `on_error` :
//   - "allow" (défaut, conforme AGENTS.md §3 fail-open data plane)
//   - "deny"  (opt-in)
//
// Pure-Go, cross-platform, allocation-free.
package rangeamp

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

// Config décrit la règle range-amplification.
type Config struct {
	Enabled   bool   `json:"enabled"`
	MaxRanges int    `json:"max_ranges"`
	OnError   string `json:"on_error"` // "allow" | "deny"
}

// Validate retourne une erreur si la config est inutilisable.
func (c Config) Validate() error {
	if c.Enabled {
		if c.MaxRanges < 1 {
			return errors.New("max_ranges must be >= 1 when enabled")
		}
		if c.MaxRanges > 1_000 {
			return fmt.Errorf("max_ranges %d > 1000 (sanity cap)", c.MaxRanges)
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
	// Deny : la requête doit être rejetée (HTTP 416).
	Deny
)

// Limiter applique la règle range-amplification.
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

// New construit un Limiter et enregistre les métriques dans reg.
func New(cfg Config, reg metrics.Registry) (*Limiter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("rangeamp: invalid initial config: %w", err)
	}
	l := &Limiter{now: time.Now}
	c := cfg
	l.cfg.Store(&c)
	l.metrics.evaluated = reg.Counter("mitigation_range_amp_evaluated_total")
	l.metrics.blocked = reg.Counter("mitigation_range_amp_blocked_total")
	l.metrics.errors = reg.Counter("mitigation_range_amp_errors_total")
	l.metrics.duration = reg.Histogram("mitigation_range_amp_duration_seconds")
	return l, nil
}

// Update remplace atomiquement la config. Fail-open sur erreur :
// l'ancienne config reste active.
func (l *Limiter) Update(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		l.metrics.errors.Inc()
		return fmt.Errorf("rangeamp: invalid config: %w", err)
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

// countRanges retourne le nombre de ranges déclarés dans un header
// `Range`. Une valeur vide → 0 (pas de header Range).
//
// On compte les virgules : RFC 9110 §14.1.1 définit "ranges-specifier
// = range-unit "=" range-set" où range-set est une liste séparée par
// `,`. Le préfixe `bytes=` ne contient pas de virgule, donc le compte
// brut convient sans allocation.
func countRanges(rangeHeader string) int {
	if rangeHeader == "" {
		return 0
	}
	return strings.Count(rangeHeader, ",") + 1
}

// Evaluate inspecte un header Range et décide. Allocation-free.
func (l *Limiter) Evaluate(rangeHeader string) Decision {
	start := l.now()
	defer func() { l.metrics.duration.Observe(l.now().Sub(start).Seconds()) }()

	cfg := l.cfg.Load()
	if !cfg.Enabled {
		return Allow
	}
	l.metrics.evaluated.Inc()

	if countRanges(rangeHeader) > cfg.MaxRanges {
		l.metrics.blocked.Inc()
		return Deny
	}
	return Allow
}

// Middleware retourne un http.Handler qui filtre les requêtes avant
// de les passer à next. Sur Deny, répond HTTP 416 Range Not Satisfiable.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch l.Evaluate(r.Header.Get("Range")) {
		case Allow:
			next.ServeHTTP(w, r)
		case Deny:
			http.Error(w, "too many byte-ranges", http.StatusRequestedRangeNotSatisfiable)
		}
	})
}
