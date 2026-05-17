// Package cachepoison implémente la mitigation `cache-poisoning`.
//
// Vecteur de référence : J. Kettle, "Practical Web Cache Poisoning"
// (Black Hat USA 2018). Un attaquant envoie une requête vers une URL
// cacheable en injectant un header "unkeyed" (non inclus dans la
// clé de cache du CDN/reverse-cache aval) qui influence pourtant la
// réponse générée par l'origin. Exemples bien connus :
//
//   - `X-Forwarded-Host: evil.com` réfléchi dans un canonical link
//     ou dans des URL absolues du HTML → tous les utilisateurs
//     suivants reçoivent les liens empoisonnés.
//   - `X-Original-URL: /admin` interprété par Symfony / IIS pour
//     contourner les ACLs front.
//   - `X-HTTP-Method-Override: PUT` qui transforme un GET cacheable
//     en mutation côté backend.
//
// Voir aussi Omer Gil "Web Cache Deception" (2017) pour le pattern
// `/profile.php/fake.css`, traité par d'autres règles (path
// normalization, hors scope ici).
//
// Défense : pour chaque header listé comme "poisoning" dans la
// config, soit on le strippe avant de forwarder à l'upstream
// (`action: strip`, défaut), soit on rejette la requête en 400
// (`action: deny`, opt-in). Le proxy applique aussi des headers
// d'audit (`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Real-IP`) :
// **ne jamais** lister ceux-là dans `headers`.
//
// Pure-Go, cross-platform, allocation-free sur le chemin chaud quand
// aucun header dangereux n'est présent.
package cachepoison

import (
	"errors"
	"fmt"
	"net/http"
	"net/textproto"
	"sync/atomic"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

// Action décide quoi faire quand un header dangereux est détecté.
type Action string

const (
	// ActionStrip : retirer silencieusement le header avant forward.
	ActionStrip Action = "strip"
	// ActionDeny : refuser la requête (HTTP 400).
	ActionDeny Action = "deny"
)

// Config décrit la règle cache-poisoning.
type Config struct {
	Enabled bool     `json:"enabled"`
	Headers []string `json:"headers"`
	Action  string   `json:"action"` // "strip" | "deny"
}

// Validate retourne une erreur si la config est inutilisable.
func (c Config) Validate() error {
	if c.Enabled {
		if len(c.Headers) == 0 {
			return errors.New("headers must be non-empty when enabled")
		}
		if len(c.Headers) > 64 {
			return fmt.Errorf("headers count %d > 64 (sanity cap)", len(c.Headers))
		}
		for _, h := range c.Headers {
			if h == "" {
				return errors.New("headers must not contain empty entries")
			}
			if len(h) > 128 {
				return fmt.Errorf("header name %q too long", h)
			}
		}
	}
	switch c.Action {
	case "", string(ActionStrip), string(ActionDeny):
	default:
		return fmt.Errorf("action must be strip|deny, got %q", c.Action)
	}
	return nil
}

// Decision encode la sortie d'Evaluate.
type Decision int

const (
	// Allow : aucun header dangereux, requête forwardée telle quelle.
	Allow Decision = iota
	// Strip : au moins un header dangereux trouvé et à retirer.
	Strip
	// Deny : action=deny et au moins un header dangereux trouvé.
	Deny
)

// internalConfig contient la version canonicalisée des noms de header
// (forme `Mime-Header`) précalculée pour éviter toute allocation sur
// le chemin chaud.
type internalConfig struct {
	cfg        Config
	canonical  []string
	denyAction bool
}

func buildInternal(cfg Config) *internalConfig {
	ic := &internalConfig{cfg: cfg, denyAction: cfg.Action == string(ActionDeny)}
	if cfg.Enabled {
		ic.canonical = make([]string, len(cfg.Headers))
		for i, h := range cfg.Headers {
			ic.canonical[i] = textproto.CanonicalMIMEHeaderKey(h)
		}
	}
	return ic
}

// Limiter applique la règle cache-poisoning.
//
// L'objet est sûr en concurrence. La config est swappable à chaud via
// Update sans drop de requêtes en cours (atomic.Pointer).
type Limiter struct {
	state   atomic.Pointer[internalConfig]
	metrics struct {
		evaluated metrics.Counter
		stripped  metrics.Counter // nb total de headers individuels retirés
		blocked   metrics.Counter // nb de requêtes rejetées (action=deny)
		errors    metrics.Counter
		duration  metrics.Histogram
	}
	now func() time.Time
}

// New construit un Limiter et enregistre les métriques dans reg.
func New(cfg Config, reg metrics.Registry) (*Limiter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("cachepoison: invalid initial config: %w", err)
	}
	l := &Limiter{now: time.Now}
	l.state.Store(buildInternal(cfg))
	l.metrics.evaluated = reg.Counter("mitigation_cache_poison_evaluated_total")
	l.metrics.stripped = reg.Counter("mitigation_cache_poison_stripped_total")
	l.metrics.blocked = reg.Counter("mitigation_cache_poison_blocked_total")
	l.metrics.errors = reg.Counter("mitigation_cache_poison_errors_total")
	l.metrics.duration = reg.Histogram("mitigation_cache_poison_duration_seconds")
	return l, nil
}

// Update remplace atomiquement la config. Fail-open sur erreur :
// l'ancienne config reste active.
func (l *Limiter) Update(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		l.metrics.errors.Inc()
		return fmt.Errorf("cachepoison: invalid config: %w", err)
	}
	l.state.Store(buildInternal(cfg))
	return nil
}

// Config retourne une copie de la config courante.
func (l *Limiter) Config() Config {
	return l.state.Load().cfg
}

// Metrics expose les compteurs pour debug/admin.
func (l *Limiter) Metrics() (evaluated, stripped, blocked, errs uint64) {
	return l.metrics.evaluated.Value(), l.metrics.stripped.Value(),
		l.metrics.blocked.Value(), l.metrics.errors.Value()
}

// Evaluate inspecte les headers d'une requête et retourne :
//   - la décision (Allow, Strip, Deny) ;
//   - la liste des headers dangereux trouvés (forme canonique) pour
//     que le caller puisse les supprimer. Slice partagée avec un
//     buffer interne — ne pas conserver de référence après retour.
//
// Allocation-free si headers est vide.
func (l *Limiter) Evaluate(headers http.Header) (Decision, []string) {
	start := l.now()
	defer func() { l.metrics.duration.Observe(l.now().Sub(start).Seconds()) }()

	st := l.state.Load()
	if !st.cfg.Enabled {
		return Allow, nil
	}
	l.metrics.evaluated.Inc()

	var hits []string
	for _, h := range st.canonical {
		if _, ok := headers[h]; ok {
			hits = append(hits, h)
		}
	}
	if len(hits) == 0 {
		return Allow, nil
	}
	if st.denyAction {
		l.metrics.blocked.Inc()
		return Deny, hits
	}
	l.metrics.stripped.Add(uint64(len(hits)))
	return Strip, hits
}

// Middleware retourne un http.Handler qui filtre les requêtes avant
// de les passer à next.
//
// Sur Strip : retire chaque header dangereux et continue.
// Sur Deny  : répond HTTP 400 Bad Request.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decision, hits := l.Evaluate(r.Header)
		switch decision {
		case Allow:
			next.ServeHTTP(w, r)
		case Strip:
			for _, h := range hits {
				r.Header.Del(h)
			}
			next.ServeHTTP(w, r)
		case Deny:
			http.Error(w, "request contains forbidden header", http.StatusBadRequest)
		}
	})
}
