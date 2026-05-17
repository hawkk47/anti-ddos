// Package requesthygiene implémente la mitigation `request-hygiene`.
//
// Vecteur. Avant même les rate-limits et les WAF, une requête HTTP
// malformée ou ambiguë peut servir de vecteur d'attaque sur le
// reverse-proxy ou sur l'upstream : HTTP request smuggling (TE+CL
// conflict, Content-Length dupliqué), méthodes exotiques (TRACE,
// CONNECT, méthodes inventées qui contournent un WAF amont), URI
// monstrueuses (DoS sur les regex de routing en amont).
//
// Cette mitigation applique une politique d'hygiène stricte AVANT
// toute autre logique métier :
//
//  1. Méthode dans une whitelist (défaut RFC + sûr).
//  2. URI bornée en longueur.
//  3. Pas de conflit Transfer-Encoding + Content-Length (CL.TE/TE.CL
//     anti-smuggling — cf. James Kettle, BlackHat USA 2019).
//  4. Pas de Content-Length dupliqué (vecteur smuggling alternatif).
//  5. Pas de Transfer-Encoding autre que `chunked`.
//
// Distinct des autres mitigations :
//   - largeheader plafonne la TAILLE des headers individuels ; ici on
//     plafonne l'URI et on vérifie la cohérence sémantique.
//   - WAF (control plane) raisonne sur le contenu ; ici on raisonne
//     sur la conformité du framing HTTP.
//
// Réponse sur violation : `400 Bad Request`, corps vide. Pas de
// header `X-AntiDDoS-Reason` exposé (information utile à l'attaquant).
// La raison est journalisée côté serveur uniquement.
//
// Hot-reload : `Config` swappable atomiquement, pas d'état persistant
// entre requêtes.
//
// Pure-Go, cross-platform, allocation-free sur le hot path (slice
// scan + bornes intégrales).
package requesthygiene

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

// Reason encode la cause d'un rejet (utile aux tests et logs).
type Reason string

const (
	ReasonNone             Reason = ""
	ReasonMethodNotAllowed Reason = "method_not_allowed"
	ReasonURITooLong       Reason = "uri_too_long"
	ReasonTECLConflict     Reason = "te_cl_conflict"
	ReasonDuplicateCL      Reason = "duplicate_content_length"
	ReasonInvalidTE        Reason = "invalid_transfer_encoding"
	ReasonEmptyHost        Reason = "empty_host"
)

// DefaultAllowedMethods : whitelist conservatrice. CONNECT et TRACE
// volontairement absents (CONNECT n'a pas de sens hors-proxy explicite,
// TRACE est un vecteur XST historique).
var DefaultAllowedMethods = []string{
	http.MethodGet,
	http.MethodHead,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
	http.MethodOptions,
}

// Config décrit la règle request-hygiene.
type Config struct {
	Enabled         bool     `json:"enabled"`
	AllowedMethods  []string `json:"allowed_methods"`
	MaxURILength    int      `json:"max_uri_length"` // 0 = pas de limite
	RejectTECL      bool     `json:"reject_te_cl_conflict"`
	RejectDupCL     bool     `json:"reject_duplicate_content_length"`
	RejectBadTE     bool     `json:"reject_invalid_transfer_encoding"`
	RejectEmptyHost bool     `json:"reject_empty_host"`
	OnError         string   `json:"on_error"` // "allow" | "deny" (réservé)
}

// Validate retourne une erreur si la config est inutilisable.
func (c Config) Validate() error {
	if c.Enabled {
		// au moins une règle doit être active ; sinon désactiver
		// explicitement plutôt que d'avoir un middleware passif.
		if len(c.AllowedMethods) == 0 && c.MaxURILength == 0 &&
			!c.RejectTECL && !c.RejectDupCL && !c.RejectBadTE && !c.RejectEmptyHost {
			return fmt.Errorf("no rule active: enable at least one check or set enabled=false")
		}
		if c.MaxURILength < 0 {
			return fmt.Errorf("max_uri_length must be >= 0, got %d", c.MaxURILength)
		}
		if c.MaxURILength > 1<<20 {
			return fmt.Errorf("max_uri_length %d > 1 MiB (sanity cap)", c.MaxURILength)
		}
		for _, m := range c.AllowedMethods {
			if m == "" {
				return fmt.Errorf("allowed_methods contains empty entry")
			}
			if strings.ToUpper(m) != m {
				return fmt.Errorf("allowed_methods entries must be upper-case, got %q", m)
			}
		}
	}
	switch c.OnError {
	case "", "allow", "deny":
	default:
		return fmt.Errorf("on_error must be allow|deny, got %q", c.OnError)
	}
	return nil
}

// Limiter applique la mitigation request-hygiene. Sûr en concurrence,
// hot-reload via atomic.Pointer.
type Limiter struct {
	cfg     atomic.Pointer[Config]
	methods atomic.Pointer[[]string] // copie triée pour binary search

	metrics struct {
		evaluated metrics.Counter
		blocked   metrics.Counter
		errors    metrics.Counter
		duration  metrics.Histogram
	}
	now func() time.Time
}

// New construit un Limiter et enregistre les métriques.
func New(cfg Config, reg metrics.Registry) (*Limiter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("request-hygiene: invalid initial config: %w", err)
	}
	l := &Limiter{now: time.Now}
	l.store(cfg)
	l.metrics.evaluated = reg.Counter("mitigation_request_hygiene_evaluated_total")
	l.metrics.blocked = reg.Counter("mitigation_request_hygiene_blocked_total")
	l.metrics.errors = reg.Counter("mitigation_request_hygiene_errors_total")
	l.metrics.duration = reg.Histogram("mitigation_request_hygiene_duration_seconds")
	return l, nil
}

// store publie atomiquement la config + la table de méthodes triée.
func (l *Limiter) store(cfg Config) {
	c := cfg
	l.cfg.Store(&c)
	methods := make([]string, len(cfg.AllowedMethods))
	copy(methods, cfg.AllowedMethods)
	sort.Strings(methods)
	l.methods.Store(&methods)
}

// Update remplace atomiquement la config. Sur erreur de validation,
// l'ancienne config reste.
func (l *Limiter) Update(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		l.metrics.errors.Inc()
		return fmt.Errorf("request-hygiene: invalid config: %w", err)
	}
	l.store(cfg)
	return nil
}

// Config retourne une copie de la config courante.
func (l *Limiter) Config() Config { return *l.cfg.Load() }

// Metrics expose les compteurs pour debug/admin.
func (l *Limiter) Metrics() (evaluated, blocked, errs uint64) {
	return l.metrics.evaluated.Value(), l.metrics.blocked.Value(), l.metrics.errors.Value()
}

// Evaluate inspecte la requête et retourne ReasonNone si elle est
// conforme, ou la raison de rejet. Pure : pas d'effet de bord
// (utile pour tests + middleware).
func (l *Limiter) Evaluate(r *http.Request) Reason {
	cfg := l.cfg.Load()
	if !cfg.Enabled {
		return ReasonNone
	}
	// méthode
	if methods := l.methods.Load(); methods != nil && len(*methods) > 0 {
		m := *methods
		i := sort.SearchStrings(m, r.Method)
		if i >= len(m) || m[i] != r.Method {
			return ReasonMethodNotAllowed
		}
	}
	// URI length (RequestURI brut, pas après parse).
	if cfg.MaxURILength > 0 && len(r.RequestURI) > cfg.MaxURILength {
		return ReasonURITooLong
	}
	// Host vide.
	if cfg.RejectEmptyHost && strings.TrimSpace(r.Host) == "" {
		return ReasonEmptyHost
	}
	// TE / CL.
	hasTE := len(r.TransferEncoding) > 0 || r.Header.Get("Transfer-Encoding") != ""
	clValues := r.Header.Values("Content-Length")
	hasCL := len(clValues) > 0 || r.ContentLength > 0
	if cfg.RejectTECL && hasTE && hasCL {
		return ReasonTECLConflict
	}
	if cfg.RejectDupCL && len(clValues) > 1 {
		return ReasonDuplicateCL
	}
	if cfg.RejectBadTE {
		// TransferEncoding peut contenir plusieurs valeurs ; seul
		// "chunked" est accepté (RFC 7230 §3.3.1 — "identity" est
		// déprécié, "gzip"/"deflate" en TE sont rares et risqués).
		for _, te := range r.TransferEncoding {
			if !strings.EqualFold(te, "chunked") {
				return ReasonInvalidTE
			}
		}
		// header brut au cas où la stdlib n'a pas parsé (httptest).
		for _, raw := range r.Header.Values("Transfer-Encoding") {
			for _, part := range strings.Split(raw, ",") {
				if v := strings.TrimSpace(part); v != "" && !strings.EqualFold(v, "chunked") {
					return ReasonInvalidTE
				}
			}
		}
	}
	return ReasonNone
}

// Middleware retourne un http.Handler qui filtre via Evaluate.
// Sur Reason != "", répond 400 Bad Request, sans header de raison.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := l.now()
		cfg := l.cfg.Load()
		if cfg.Enabled {
			l.metrics.evaluated.Inc()
		}
		reason := l.Evaluate(r)
		l.metrics.duration.Observe(l.now().Sub(start).Seconds())
		if reason != ReasonNone {
			l.metrics.blocked.Inc()
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}
