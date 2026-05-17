// Package hashflood implémente la mitigation `hash-flood`.
//
// Vecteur historique : un attaquant envoie une requête avec un grand
// nombre de paramètres dont les clés ont été choisies pour entrer en
// collision dans la hash map du serveur. Le coût de parsing dégénère
// alors en O(n²) au lieu d'O(n) (CVE-2011-3414 PHP, CVE-2012-5371 Ruby,
// etc.).
//
// La map native de Go est immunisée contre les collisions
// *algorithmiques* depuis ses premières versions : la seed du hasher
// est randomisée par processus et le hasher (AES-NI / wyhash) n'est
// pas inversible publiquement. Le pire cas reste donc O(n) amorti.
//
// Le résidu d'attaque exploitable contre un service Go est purement
// *quantitatif* : forcer le serveur à parser, URL-décoder et stocker
// N entrées dans `url.Values` pour chaque requête, ce qui coûte du CPU
// et de la mémoire (allocations de strings) même sans collision.
//
// Cette mitigation plafonne le nombre de paramètres distincts dans la
// query string avant que le handler ne parse quoi que ce soit. Le
// comptage est ultra-bon-marché : `strings.Count(rawQuery, "&") + 1`,
// sans allocation ni parsing complet.
//
// Le pendant pour les **headers** (max_header_count) est couvert par
// `proxy/mitigations/largeheader`. Le pendant pour le body POST form
// est borné indirectement par `proxy/mitigations/bodies` (taille) et
// `slowpost` (débit). Une future mitigation pourra ajouter un compte
// explicite sur form-urlencoded une fois le coût de parse maîtrisé.
//
// Refus → HTTP 400 Bad Request (URL malformée du point de vue du
// proxy : trop de paramètres pour notre politique).
//
// Mode `on_error` :
//   - "allow" (défaut, conforme AGENTS.md §3 fail-open data plane)
//   - "deny"  (opt-in)
//
// Pure-Go, cross-platform, allocation-free.
package hashflood

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

// Config décrit la règle hash-flood.
type Config struct {
	Enabled        bool   `json:"enabled"`
	MaxQueryParams int    `json:"max_query_params"`
	OnError        string `json:"on_error"` // "allow" | "deny"
}

// Validate retourne une erreur si la config est inutilisable.
func (c Config) Validate() error {
	if c.Enabled {
		if c.MaxQueryParams < 1 {
			return errors.New("max_query_params must be >= 1 when enabled")
		}
		if c.MaxQueryParams > 10_000 {
			return fmt.Errorf("max_query_params %d > 10000 (sanity cap)", c.MaxQueryParams)
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
	// Deny : la requête doit être rejetée (HTTP 400).
	Deny
)

// Limiter applique la règle hash-flood.
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
		return nil, fmt.Errorf("hashflood: invalid initial config: %w", err)
	}
	l := &Limiter{now: time.Now}
	c := cfg
	l.cfg.Store(&c)
	l.metrics.evaluated = reg.Counter("mitigation_hash_flood_evaluated_total")
	l.metrics.blocked = reg.Counter("mitigation_hash_flood_blocked_total")
	l.metrics.errors = reg.Counter("mitigation_hash_flood_errors_total")
	l.metrics.duration = reg.Histogram("mitigation_hash_flood_duration_seconds")
	return l, nil
}

// Update remplace atomiquement la config. Fail-open sur erreur :
// l'ancienne config reste active.
func (l *Limiter) Update(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		l.metrics.errors.Inc()
		return fmt.Errorf("hashflood: invalid config: %w", err)
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

// countParams retourne le nombre de paramètres distincts dans une
// query string sans la parser. Une chaîne vide → 0.
//
// Conforme à `net/url.ParseQuery` qui ne traite plus que `&` comme
// séparateur depuis Go 1.17 (drop du legacy `;`).
func countParams(rawQuery string) int {
	if rawQuery == "" {
		return 0
	}
	return strings.Count(rawQuery, "&") + 1
}

// Evaluate inspecte la query string et décide. Allocation-free.
func (l *Limiter) Evaluate(rawQuery string) Decision {
	start := l.now()
	defer func() { l.metrics.duration.Observe(l.now().Sub(start).Seconds()) }()

	cfg := l.cfg.Load()
	if !cfg.Enabled {
		return Allow
	}
	l.metrics.evaluated.Inc()

	if countParams(rawQuery) > cfg.MaxQueryParams {
		l.metrics.blocked.Inc()
		return Deny
	}
	return Allow
}

// Middleware retourne un http.Handler qui filtre les requêtes avant
// de les passer à next. Sur Deny, répond HTTP 400.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch l.Evaluate(r.URL.RawQuery) {
		case Allow:
			next.ServeHTTP(w, r)
		case Deny:
			http.Error(w, "too many query parameters", http.StatusBadRequest)
		}
	})
}
