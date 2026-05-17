// Package tlsreneg implémente la mitigation `tls-renegotiation-flood`.
//
// Contexte. En TLS 1.3 la renégociation n'existe plus (remplacée par
// KeyUpdate / post-handshake auth). En TLS 1.2 la renégociation
// client-initiée existe et a été le vecteur historique de l'attaque
// (CVE-2011-1473) : le coût CPU asymétrique côté serveur permet à un
// seul client de saturer un core en envoyant des ClientHello en boucle.
//
// Côté pure-Go, le stdlib refuse par défaut la renégociation
// client-initiée (`tls.Config.Renegotiation = tls.RenegotiateNever`).
// Ce package :
//
//  1. Force et asserte cette configuration via `BuildTLSConfig`
//     (MinVersion >= 1.2, Renegotiation interdite).
//  2. Rate-limite les NOUVEAUX handshakes par IP via un wrapper de
//     `net.Listener` (token bucket). Couvre aussi un flood TCP/TLS
//     pur où chaque attaquant ouvre/ferme massivement.
//
// Pure-Go, cross-platform, allocation-light. Fail-open par défaut
// (AGENTS.md §3) : si le wrapper tombe en erreur on accept la conn.
package tlsreneg

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

// Config décrit la règle tls-renegotiation-flood.
type Config struct {
	Enabled                  bool    `json:"enabled"`
	MinTLSVersion            string  `json:"min_tls_version"` // "1.2" | "1.3"
	HandshakesPerSecondPerIP float64 `json:"handshakes_per_second_per_ip"`
	Burst                    int     `json:"burst"`
	OnError                  string  `json:"on_error"`
}

// Validate retourne une erreur si la config est inutilisable.
func (c Config) Validate() error {
	if c.Enabled {
		switch c.MinTLSVersion {
		case "1.2", "1.3":
		default:
			return fmt.Errorf("min_tls_version must be 1.2 or 1.3, got %q", c.MinTLSVersion)
		}
		if c.HandshakesPerSecondPerIP <= 0 || c.HandshakesPerSecondPerIP > 1e6 {
			return fmt.Errorf("handshakes_per_second_per_ip must be in (0, 1e6], got %v",
				c.HandshakesPerSecondPerIP)
		}
		if c.Burst < 1 || c.Burst > 100000 {
			return fmt.Errorf("burst must be in [1, 100000], got %d", c.Burst)
		}
	}
	switch c.OnError {
	case "", "allow", "deny":
	default:
		return fmt.Errorf("on_error must be allow|deny, got %q", c.OnError)
	}
	return nil
}

// minTLSVersionUint retourne la version stdlib correspondante.
func (c Config) minTLSVersionUint() uint16 {
	if c.MinTLSVersion == "1.3" {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

// Limiter applique la mitigation.
type Limiter struct {
	cfg     atomic.Pointer[Config]
	metrics struct {
		evaluated metrics.Counter
		blocked   metrics.Counter
		errors    metrics.Counter
		duration  metrics.Histogram
	}
	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New construit un Limiter et enregistre les métriques.
func New(cfg Config, reg metrics.Registry) (*Limiter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("tlsreneg: invalid initial config: %w", err)
	}
	l := &Limiter{
		buckets: make(map[string]*bucket),
		now:     time.Now,
	}
	c := cfg
	l.cfg.Store(&c)
	l.metrics.evaluated = reg.Counter("mitigation_tls_renegotiation_flood_evaluated_total")
	l.metrics.blocked = reg.Counter("mitigation_tls_renegotiation_flood_blocked_total")
	l.metrics.errors = reg.Counter("mitigation_tls_renegotiation_flood_errors_total")
	l.metrics.duration = reg.Histogram("mitigation_tls_renegotiation_flood_duration_seconds")
	return l, nil
}

// Update remplace atomiquement la config. Fail-open sur erreur.
func (l *Limiter) Update(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		l.metrics.errors.Inc()
		return fmt.Errorf("tlsreneg: invalid config: %w", err)
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

// BuildTLSConfig retourne un *tls.Config sûr (MinVersion respectée,
// renégociation refusée, ciphers stdlib par défaut). cert peut être
// zero — l'appelant est responsable de fournir les certificats.
func (l *Limiter) BuildTLSConfig(certs []tls.Certificate) *tls.Config {
	cfg := l.cfg.Load()
	return &tls.Config{
		MinVersion:    cfg.minTLSVersionUint(),
		Renegotiation: tls.RenegotiateNever,
		Certificates:  certs,
	}
}

// allow consulte le bucket de remoteIP et décide si on accepte un
// nouveau handshake. Retourne true si autorisé.
func (l *Limiter) allow(remoteIP string) bool {
	cfg := l.cfg.Load()
	if !cfg.Enabled {
		return true
	}
	l.metrics.evaluated.Inc()
	t := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[remoteIP]
	if !ok {
		b = &bucket{tokens: float64(cfg.Burst), last: t}
		l.buckets[remoteIP] = b
	}
	elapsed := t.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * cfg.HandshakesPerSecondPerIP
		if b.tokens > float64(cfg.Burst) {
			b.tokens = float64(cfg.Burst)
		}
		b.last = t
	}
	if b.tokens < 1 {
		l.metrics.blocked.Inc()
		return false
	}
	b.tokens--
	return true
}

// WrapListener enveloppe ln pour rate-limiter les Accept par IP. Si
// Enabled=false, retourne ln tel quel.
func (l *Limiter) WrapListener(ln net.Listener) net.Listener {
	if !l.cfg.Load().Enabled {
		return ln
	}
	return &rateLimitedListener{Listener: ln, lim: l}
}

type rateLimitedListener struct {
	net.Listener
	lim *Limiter
}

func (r *rateLimitedListener) Accept() (net.Conn, error) {
	for {
		c, err := r.Listener.Accept()
		if err != nil {
			return nil, err
		}
		start := r.lim.now()
		ip := remoteIP(c.RemoteAddr())
		if ip == "" {
			// IP indéterminable : fail-open ou fail-closed ?
			// Défaut projet = fail-open ; mais on incrémente errors.
			r.lim.metrics.errors.Inc()
			r.lim.metrics.duration.Observe(r.lim.now().Sub(start).Seconds())
			return c, nil
		}
		if !r.lim.allow(ip) {
			_ = c.Close()
			r.lim.metrics.duration.Observe(r.lim.now().Sub(start).Seconds())
			continue
		}
		r.lim.metrics.duration.Observe(r.lim.now().Sub(start).Seconds())
		return c, nil
	}
}

// remoteIP extrait l'IP d'un net.Addr ("host:port"). Vide si parsing
// échoue.
func remoteIP(a net.Addr) string {
	if a == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return ""
	}
	return host
}

// ErrBlocked est retourné par les helpers de test pour signaler un
// rejet rate-limit (utile uniquement pour les tests unitaires).
var ErrBlocked = errors.New("tlsreneg: handshake rate exceeded for IP")
