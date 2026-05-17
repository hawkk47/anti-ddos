// Package scraping implémente la mitigation `scraping-aggressif`.
//
// Vecteur : un bot/scraper aspire le contenu du site (prix, catalogue,
// articles, données utilisateurs publiques) à un rythme et un volume
// disproportionnés. Contrairement à un flood L7 où l'objectif est
// l'épuisement, ici l'objectif est l'extraction — le bot reste
// "poli" en débit mais émet une signature distinguable d'un client
// humain.
//
// Stratégie de détection (signature-based, pas comportementale) :
//
//   - User-Agent : substring match (insensible à la casse) contre
//     une liste configurable de marqueurs connus
//     (`python-requests`, `scrapy`, `curl`, `wget`, `headlesschrome`,
//     `phantomjs`, `selenium`, `bot`, `crawler`, `spider`, …).
//     Substring uniquement, **pas de regex** : la regex en config
//     est une surface ReDoS et complexifie la validation Windows/
//     Linux ; un attaquant qui veut contourner change de toute
//     façon de User-Agent.
//   - Accept-Language manquant : tous les navigateurs grand public
//     en envoient un. Optionnel via `require_accept_language`.
//   - Accept-Encoding manquant : idem, optionnel via
//     `require_accept_encoding`.
//
// Stratégie de réaction :
//
//   - `action: log` (défaut) : laisse passer, incrémente
//     `mitigation_scraping_logged_total`. Sert au pilote d'observer
//     le bruit de fond avant d'activer un blocage.
//   - `action: deny` : répond HTTP 403 Forbidden immédiatement.
//
// **Pas une protection anti-scraper sérieuse.** Cette règle filtre
// les bots naïfs (script kiddie, indexeur mal configuré). Un
// scraper déterminé spoofe trivialement User-Agent + Accept-*. Pour
// du scraping persistant il faut une couche comportementale
// (rate-limit par session, fingerprint TLS, JS challenge) — non
// livrée dans cette version.
//
// Pure-Go, cross-platform. Allocation-free quand `Enabled=false`
// et quand aucun signal ne matche.
package scraping

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

// Action décide quoi faire quand au moins un signal matche.
type Action string

const (
	// ActionLog : laisse passer, incrémente le compteur logged.
	ActionLog Action = "log"
	// ActionDeny : refuse la requête (HTTP 403).
	ActionDeny Action = "deny"
)

// Config décrit la règle scraping.
type Config struct {
	Enabled bool `json:"enabled"`
	// UserAgentDeny : substrings (case-insensitive) déclencheurs.
	UserAgentDeny []string `json:"user_agent_deny"`
	// RequireAcceptLanguage : si true, une requête sans header
	// Accept-Language matche.
	RequireAcceptLanguage bool `json:"require_accept_language"`
	// RequireAcceptEncoding : si true, une requête sans header
	// Accept-Encoding matche.
	RequireAcceptEncoding bool `json:"require_accept_encoding"`
	// Action : "log" (défaut) ou "deny".
	Action string `json:"action"`
}

// Validate retourne une erreur si la config est inutilisable.
func (c Config) Validate() error {
	if c.Enabled {
		hasSignal := len(c.UserAgentDeny) > 0 ||
			c.RequireAcceptLanguage ||
			c.RequireAcceptEncoding
		if !hasSignal {
			return errors.New("at least one signal must be enabled " +
				"(user_agent_deny / require_accept_language / require_accept_encoding)")
		}
		if len(c.UserAgentDeny) > 128 {
			return fmt.Errorf("user_agent_deny count %d > 128 (sanity cap)",
				len(c.UserAgentDeny))
		}
		for _, p := range c.UserAgentDeny {
			if p == "" {
				return errors.New("user_agent_deny must not contain empty entries")
			}
			if len(p) > 128 {
				return fmt.Errorf("user_agent_deny entry %q too long", p)
			}
		}
	}
	switch c.Action {
	case "", string(ActionLog), string(ActionDeny):
	default:
		return fmt.Errorf("action must be log|deny, got %q", c.Action)
	}
	return nil
}

// Decision encode la sortie d'Evaluate.
type Decision int

const (
	// Allow : aucun signal, requête forwardée telle quelle.
	Allow Decision = iota
	// Log : au moins un signal mais action=log → forward + métrique.
	Log
	// Deny : au moins un signal et action=deny → refus 403.
	Deny
)

// internalConfig contient les substrings UA déjà mis en lowercase
// pour éviter toute allocation sur le chemin chaud.
type internalConfig struct {
	cfg        Config
	uaLower    []string
	denyAction bool
}

func buildInternal(cfg Config) *internalConfig {
	ic := &internalConfig{cfg: cfg, denyAction: cfg.Action == string(ActionDeny)}
	if cfg.Enabled && len(cfg.UserAgentDeny) > 0 {
		ic.uaLower = make([]string, len(cfg.UserAgentDeny))
		for i, p := range cfg.UserAgentDeny {
			ic.uaLower[i] = strings.ToLower(p)
		}
	}
	return ic
}

// Limiter applique la règle scraping.
//
// L'objet est sûr en concurrence. Config swappable à chaud via Update
// sans drop de requêtes en cours (atomic.Pointer).
type Limiter struct {
	state   atomic.Pointer[internalConfig]
	metrics struct {
		evaluated metrics.Counter
		matched   metrics.Counter // requêtes ayant au moins un signal
		logged    metrics.Counter // matched && action=log
		blocked   metrics.Counter // matched && action=deny
		errors    metrics.Counter
		duration  metrics.Histogram
	}
	now func() time.Time
}

// New construit un Limiter et enregistre les métriques dans reg.
func New(cfg Config, reg metrics.Registry) (*Limiter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("scraping: invalid initial config: %w", err)
	}
	l := &Limiter{now: time.Now}
	l.state.Store(buildInternal(cfg))
	l.metrics.evaluated = reg.Counter("mitigation_scraping_evaluated_total")
	l.metrics.matched = reg.Counter("mitigation_scraping_matched_total")
	l.metrics.logged = reg.Counter("mitigation_scraping_logged_total")
	l.metrics.blocked = reg.Counter("mitigation_scraping_blocked_total")
	l.metrics.errors = reg.Counter("mitigation_scraping_errors_total")
	l.metrics.duration = reg.Histogram("mitigation_scraping_duration_seconds")
	return l, nil
}

// Update remplace atomiquement la config. Fail-open : l'ancienne
// config reste active sur erreur.
func (l *Limiter) Update(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		l.metrics.errors.Inc()
		return fmt.Errorf("scraping: invalid config: %w", err)
	}
	l.state.Store(buildInternal(cfg))
	return nil
}

// Config retourne une copie de la config courante.
func (l *Limiter) Config() Config {
	return l.state.Load().cfg
}

// Metrics expose les compteurs pour debug/admin.
func (l *Limiter) Metrics() (evaluated, matched, logged, blocked, errs uint64) {
	return l.metrics.evaluated.Value(),
		l.metrics.matched.Value(),
		l.metrics.logged.Value(),
		l.metrics.blocked.Value(),
		l.metrics.errors.Value()
}

// Evaluate inspecte les headers et retourne :
//   - la décision (Allow, Log, Deny) ;
//   - la liste des raisons matchées (préfixées : "ua:<pattern>",
//     "missing:accept-language", "missing:accept-encoding").
//     Slice partagée avec un buffer interne du caller via append —
//     ne pas conserver de référence après retour.
//
// Allocation-free quand Enabled=false ou quand aucun signal ne
// matche.
func (l *Limiter) Evaluate(headers http.Header) (Decision, []string) {
	start := l.now()
	defer func() { l.metrics.duration.Observe(l.now().Sub(start).Seconds()) }()

	st := l.state.Load()
	if !st.cfg.Enabled {
		return Allow, nil
	}
	l.metrics.evaluated.Inc()

	var reasons []string
	if len(st.uaLower) > 0 {
		ua := strings.ToLower(headers.Get("User-Agent"))
		if ua != "" {
			for _, p := range st.uaLower {
				if strings.Contains(ua, p) {
					reasons = append(reasons, "ua:"+p)
					break // un seul match UA suffit, évite N^2 sur UA long
				}
			}
		}
	}
	if st.cfg.RequireAcceptLanguage && headers.Get("Accept-Language") == "" {
		reasons = append(reasons, "missing:accept-language")
	}
	if st.cfg.RequireAcceptEncoding && headers.Get("Accept-Encoding") == "" {
		reasons = append(reasons, "missing:accept-encoding")
	}

	if len(reasons) == 0 {
		return Allow, nil
	}
	l.metrics.matched.Inc()
	if st.denyAction {
		l.metrics.blocked.Inc()
		return Deny, reasons
	}
	l.metrics.logged.Inc()
	return Log, reasons
}

// Middleware retourne un http.Handler qui filtre les requêtes avant
// next.
//
// Sur Log : continue (la raison est observable via les métriques).
// Sur Deny : répond HTTP 403 Forbidden.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decision, _ := l.Evaluate(r.Header)
		switch decision {
		case Allow, Log:
			next.ServeHTTP(w, r)
		case Deny:
			http.Error(w, "forbidden", http.StatusForbidden)
		}
	})
}
