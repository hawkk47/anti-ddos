// Package slowpost implémente la mitigation `slow-post`.
//
// Vecteur : le client annonce un Content-Length non-nul puis envoie
// le body un octet à la fois pour mobiliser longtemps un slot du
// serveur (variante Slowloris sur le body plutôt que les headers).
//
// Le stdlib Go pose `Server.ReadTimeout` (timeout total) — utile mais
// grossier : trop court il casse les vrais uploads, trop long il
// laisse passer l'attaque. Cette mitigation ajoute deux contrôles :
//
//   - max_body_bytes        : cap dur sur la taille du body.
//   - min_bytes_per_second  : débit minimum exigé après la période
//     de grâce. Sous le seuil, on coupe.
//
// Sur violation, le Read renvoie une erreur ; le stdlib HTTP server
// ferme la connexion et libère le slot.
//
// Mode `on_error` : "allow" (défaut, fail-open AGENTS.md §3) ou "deny".
//
// Pure-Go, cross-platform, allocation-light.
package slowpost

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

// Config décrit la règle slow-post.
type Config struct {
	Enabled           bool          `json:"enabled"`
	MaxBodyBytes      int64         `json:"max_body_bytes"`
	MinBytesPerSecond int           `json:"min_bytes_per_second"`
	GracePeriod       time.Duration `json:"grace_period"`
	OnError           string        `json:"on_error"`
}

// Validate retourne une erreur si la config est inutilisable.
func (c Config) Validate() error {
	if c.Enabled {
		if c.MaxBodyBytes < 1 {
			return errors.New("max_body_bytes must be >= 1 when enabled")
		}
		if c.MaxBodyBytes > 1024*1024*1024 { // 1 GiB
			return fmt.Errorf("max_body_bytes %d > 1 GiB (sanity cap)", c.MaxBodyBytes)
		}
		if c.MinBytesPerSecond < 1 {
			return errors.New("min_bytes_per_second must be >= 1 when enabled")
		}
		if c.GracePeriod < 0 || c.GracePeriod > 60*time.Second {
			return fmt.Errorf("grace_period must be in [0, 60s], got %v", c.GracePeriod)
		}
	}
	switch c.OnError {
	case "", "allow", "deny":
	default:
		return fmt.Errorf("on_error must be allow|deny, got %q", c.OnError)
	}
	return nil
}

// ErrSlowPost est l'erreur renvoyée au handler upstream quand le débit
// du body chute sous le seuil. Le stdlib HTTP server propage en
// fermant la connexion.
var ErrSlowPost = errors.New("slowpost: body rate below threshold")

// Limiter applique la règle slow-post. Sûr en concurrence ;
// hot-reloadable via Update.
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

// New construit un Limiter et enregistre les métriques.
func New(cfg Config, reg metrics.Registry) (*Limiter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("slowpost: invalid initial config: %w", err)
	}
	l := &Limiter{now: time.Now}
	c := cfg
	l.cfg.Store(&c)
	l.metrics.evaluated = reg.Counter("mitigation_slow_post_evaluated_total")
	l.metrics.blocked = reg.Counter("mitigation_slow_post_blocked_total")
	l.metrics.errors = reg.Counter("mitigation_slow_post_errors_total")
	l.metrics.duration = reg.Histogram("mitigation_slow_post_duration_seconds")
	return l, nil
}

// Update remplace atomiquement la config. Fail-open sur erreur.
func (l *Limiter) Update(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		l.metrics.errors.Inc()
		return fmt.Errorf("slowpost: invalid config: %w", err)
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

// Middleware retourne un http.Handler qui wrappe r.Body pour mesurer
// le débit. Si Content-Length absent ou 0, pass-through.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := l.cfg.Load()
		if !cfg.Enabled || r.Body == nil || r.ContentLength == 0 {
			next.ServeHTTP(w, r)
			return
		}
		l.metrics.evaluated.Inc()
		start := l.now()
		defer func() { l.metrics.duration.Observe(l.now().Sub(start).Seconds()) }()

		// Cap dur sur la taille du body. http.MaxBytesReader renvoie
		// une erreur sur Read si dépassé ; stdlib réagit en 400/413.
		body := http.MaxBytesReader(w, r.Body, cfg.MaxBodyBytes)
		r.Body = &slowReader{
			r:           body,
			now:         l.now,
			start:       start,
			minRate:     cfg.MinBytesPerSecond,
			grace:       cfg.GracePeriod,
			onViolation: l.metrics.blocked.Inc,
		}
		next.ServeHTTP(w, r)
	})
}

// slowReader enrobe r.Body pour vérifier le débit minimum après la
// période de grâce. Pas thread-safe — chaque requête a son instance.
type slowReader struct {
	r           io.ReadCloser
	now         func() time.Time
	start       time.Time
	read        int64
	minRate     int           // bytes/s
	grace       time.Duration // tolérance initiale
	violated    bool
	onViolation func()
}

func (s *slowReader) Read(p []byte) (int, error) {
	if s.violated {
		return 0, ErrSlowPost
	}
	n, err := s.r.Read(p)
	if n > 0 {
		s.read += int64(n)
	}
	elapsed := s.now().Sub(s.start)
	if elapsed > s.grace {
		// On exige minRate bytes/s en moyenne depuis le DÉBUT (pas
		// depuis la fin de la grace). Simple et stable.
		expected := int64(float64(s.minRate) * elapsed.Seconds())
		if s.read < expected {
			s.violated = true
			if s.onViolation != nil {
				s.onViolation()
			}
			return n, ErrSlowPost
		}
	}
	return n, err
}

func (s *slowReader) Close() error { return s.r.Close() }
