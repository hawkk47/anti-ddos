// Package http2reset implémente la mitigation `http2-rapid-reset`
// (CVE-2023-44487).
//
// Vecteur. Le client HTTP/2 ouvre un grand nombre de streams puis
// envoie immédiatement RST_STREAM sur chacun, sans attendre la
// réponse. Chaque création/annulation de stream consomme du CPU
// côté serveur (allocation goroutine, parsing HPACK, mise en file
// d'attente). Avec quelques milliers de cycles open/reset par
// seconde, un seul client peut saturer un cœur.
//
// La stdlib ne donne pas de hook direct sur les frames RST_STREAM,
// mais un stream annulé tôt par le client se traduit dans le handler
// par `r.Context().Err() == context.Canceled` AVANT que le handler
// n'ait écrit la moindre réponse. Cette mitigation tient un compteur
// par connexion TCP de ces annulations précoces ; au-delà d'un seuil
// dans une fenêtre glissante, la connexion est fermée immédiatement.
//
// On expose en plus `MaxConcurrentStreams` pour configurer le
// `http2.Server` sous-jacent (deuxième ligne de défense imposée par
// le serveur lui-même).
//
// Mode `on_error` : "allow" (défaut, fail-open AGENTS.md §3) ou
// "deny". Le compteur reste réalimenté quoi qu'il arrive ; seul le
// comportement sur erreur de validation au reload est concerné.
//
// Pure-Go, cross-platform, sans cgo.
package http2reset

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

// Config décrit la règle http2-rapid-reset.
type Config struct {
	Enabled bool `json:"enabled"`
	// MaxResetsPerConn : nombre maximum d'annulations précoces de
	// stream tolérées par connexion sur une fenêtre Window.
	MaxResetsPerConn int `json:"max_resets_per_conn"`
	// Window : durée de la fenêtre glissante (reset du compteur).
	Window time.Duration `json:"window"`
	// MaxConcurrentStreams : valeur à appliquer au http2.Server
	// (SETTINGS_MAX_CONCURRENT_STREAMS). 0 = défaut du moteur.
	MaxConcurrentStreams uint32 `json:"max_concurrent_streams"`
	OnError              string `json:"on_error"`
}

// Validate retourne une erreur si la config est inutilisable.
func (c Config) Validate() error {
	if c.Enabled {
		if c.MaxResetsPerConn < 1 {
			return errors.New("max_resets_per_conn must be >= 1 when enabled")
		}
		if c.MaxResetsPerConn > 1_000_000 {
			return fmt.Errorf("max_resets_per_conn %d > 1e6 (sanity cap)", c.MaxResetsPerConn)
		}
		if c.Window <= 0 || c.Window > 5*time.Minute {
			return fmt.Errorf("window must be in (0, 5min], got %v", c.Window)
		}
	}
	if c.MaxConcurrentStreams > 100_000 {
		return fmt.Errorf("max_concurrent_streams %d > 1e5 (sanity cap)", c.MaxConcurrentStreams)
	}
	switch c.OnError {
	case "", "allow", "deny":
	default:
		return fmt.Errorf("on_error must be allow|deny, got %q", c.OnError)
	}
	return nil
}

// connState : état par connexion TCP. Sûr en concurrence (Limiter
// utilise un Mutex global pour les transitions de fenêtre).
type connState struct {
	conn        net.Conn
	resets      int64 // protégé par Limiter.mu
	windowStart time.Time
	closed      atomic.Bool
}

// Limiter applique http2-rapid-reset. Sûr en concurrence ;
// hot-reloadable via Update.
type Limiter struct {
	cfg     atomic.Pointer[Config]
	metrics struct {
		evaluated metrics.Counter // 1 par early-cancel observé
		blocked   metrics.Counter // 1 par connexion close pour reset flood
		errors    metrics.Counter
		duration  metrics.Histogram
	}
	mu    sync.Mutex
	conns map[*connState]struct{}
	now   func() time.Time
}

// ctxKey type-safe pour stocker le connState dans le ctx de requête.
type ctxKey struct{}

// New construit un Limiter et enregistre les métriques.
func New(cfg Config, reg metrics.Registry) (*Limiter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("http2reset: invalid initial config: %w", err)
	}
	l := &Limiter{now: time.Now, conns: make(map[*connState]struct{})}
	c := cfg
	l.cfg.Store(&c)
	l.metrics.evaluated = reg.Counter("mitigation_http2_rapid_reset_evaluated_total")
	l.metrics.blocked = reg.Counter("mitigation_http2_rapid_reset_blocked_total")
	l.metrics.errors = reg.Counter("mitigation_http2_rapid_reset_errors_total")
	l.metrics.duration = reg.Histogram("mitigation_http2_rapid_reset_duration_seconds")
	return l, nil
}

// Update remplace atomiquement la config. Fail-open sur erreur.
func (l *Limiter) Update(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		l.metrics.errors.Inc()
		return fmt.Errorf("http2reset: invalid config: %w", err)
	}
	c := cfg
	l.cfg.Store(&c)
	return nil
}

// Config retourne une copie de la config courante.
func (l *Limiter) Config() Config { return *l.cfg.Load() }

// Metrics expose les compteurs.
func (l *Limiter) Metrics() (evaluated, blocked, errs uint64) {
	return l.metrics.evaluated.Value(), l.metrics.blocked.Value(), l.metrics.errors.Value()
}

// MaxConcurrentStreams expose la valeur courante pour le http2.Server.
// 0 = défaut du moteur (laisser http2 choisir).
func (l *Limiter) MaxConcurrentStreams() uint32 {
	return l.cfg.Load().MaxConcurrentStreams
}

// ConnContext est destiné à http.Server.ConnContext. Il crée un état
// par connexion et l'attache au ctx pour que le middleware puisse le
// retrouver.
func (l *Limiter) ConnContext(ctx context.Context, c net.Conn) context.Context {
	cs := &connState{conn: c, windowStart: l.now()}
	l.mu.Lock()
	l.conns[cs] = struct{}{}
	l.mu.Unlock()
	return context.WithValue(ctx, ctxKey{}, cs)
}

// OnConnState est destiné à http.Server.ConnState. Il libère l'état
// quand la connexion passe en Closed/Hijacked.
func (l *Limiter) OnConnState(c net.Conn, s http.ConnState) {
	if s != http.StateClosed && s != http.StateHijacked {
		return
	}
	l.mu.Lock()
	for cs := range l.conns {
		if cs.conn == c {
			delete(l.conns, cs)
			break
		}
	}
	l.mu.Unlock()
}

// responseObserver : wrapper de http.ResponseWriter qui tracke si le
// handler a au moins commencé à écrire une réponse (WriteHeader/Write).
type responseObserver struct {
	http.ResponseWriter
	written atomic.Bool
}

func (o *responseObserver) WriteHeader(code int) {
	o.written.Store(true)
	o.ResponseWriter.WriteHeader(code)
}

func (o *responseObserver) Write(b []byte) (int, error) {
	o.written.Store(true)
	return o.ResponseWriter.Write(b)
}

// Middleware observe les annulations de stream précoces et ferme la
// connexion si le seuil est dépassé.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := l.cfg.Load()
		if !cfg.Enabled {
			next.ServeHTTP(w, r)
			return
		}
		obs := &responseObserver{ResponseWriter: w}
		next.ServeHTTP(obs, r)

		// Early-cancel : contexte annulé ET aucune réponse écrite.
		if r.Context().Err() == nil || obs.written.Load() {
			return
		}
		cs, _ := r.Context().Value(ctxKey{}).(*connState)
		if cs == nil {
			// ConnContext non câblé : pas de comptage par-conn possible.
			// On laisse passer (fail-open implicite).
			return
		}
		l.metrics.evaluated.Inc()
		start := l.now()
		shouldClose := false
		l.mu.Lock()
		// Fenêtre glissante : reset si expirée.
		if l.now().Sub(cs.windowStart) > cfg.Window {
			cs.resets = 0
			cs.windowStart = l.now()
		}
		cs.resets++
		if cs.resets > int64(cfg.MaxResetsPerConn) {
			shouldClose = !cs.closed.Swap(true)
		}
		l.mu.Unlock()
		l.metrics.duration.Observe(l.now().Sub(start).Seconds())

		if shouldClose {
			l.metrics.blocked.Inc()
			_ = cs.conn.Close()
		}
	})
}
