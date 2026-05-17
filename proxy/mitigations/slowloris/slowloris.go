// Package slowloris implémente une mitigation par plafond de connexions
// concurrentes par IP source.
//
// Modèle d'attaque : un client ouvre N connexions TCP, envoie des en-têtes
// HTTP partiels très lentement (1 octet toutes les X secondes) pour
// occuper indéfiniment des slots de connexion / FDs et empêcher les
// clients légitimes de se connecter.
//
// Mitigation : limiter le nombre de connexions simultanées par IP au
// niveau accept(). Les connexions qui dépassent le quota sont fermées
// immédiatement.
//
// Mode d'erreur : fail-open. Si la configuration est désactivée
// (Enabled=false) ou MaxConnsPerIP <= 0, le wrapper laisse tout passer.
//
// Pure-Go, no panic, no allocation par requête (map d'état partagée
// avec mutex court).
//
// Cf. .github/instructions/proxy-data-plane.instructions.md
//
//	docs/threat-model.md#slowloris
package slowloris

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

// Config est la configuration runtime de la mitigation.
//
// Tous les seuils viennent de configs/base/connections.yaml et sont
// poussés ici via Limiter.Update (hot-reload). Aucun défaut "prod" en
// dur.
type Config struct {
	// Enabled active la mitigation. Si false : pass-through total.
	Enabled bool
	// MaxConnsPerIP : nombre maximum de connexions concurrentes
	// acceptées depuis une même IP. <= 0 ⇒ illimité (pass-through).
	MaxConnsPerIP int
	// OnError : "allow" (fail-open, défaut) ou "deny" (fail-closed).
	// Pour cette mitigation, "deny" n'a pas d'effet pratique : la
	// limite est exacte, il n'y a pas de chemin d'erreur asynchrone.
	// Le champ est présent pour cohérence avec le schéma général.
	OnError string
}

// Validate vérifie qu'une config est utilisable.
func (c Config) Validate() error {
	if c.OnError != "" && c.OnError != "allow" && c.OnError != "deny" {
		return errors.New(`OnError must be "allow" or "deny"`)
	}
	if c.MaxConnsPerIP < 0 {
		return errors.New("MaxConnsPerIP must be >= 0")
	}
	return nil
}

// Limiter applique le plafond per-IP. Sûr en concurrence.
//
// Hot-reload : Update() peut être appelé à tout moment ; les
// connexions déjà acceptées ne sont pas fermées rétroactivement
// (pas de drop sur reload — règle proxy-data-plane).
type Limiter struct {
	cfg atomic.Pointer[Config]

	mu     sync.Mutex
	counts map[string]int

	reg metrics.Registry

	// Métriques (4, conformément au skill).
	evaluated metrics.Counter
	blocked   metrics.Counter
	errs      metrics.Counter
	duration  metrics.Histogram
}

// New construit un Limiter avec la config donnée.
func New(cfg Config, reg metrics.Registry) (*Limiter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if reg == nil {
		reg = metrics.NewInMemory()
	}
	l := &Limiter{
		counts:    make(map[string]int),
		reg:       reg,
		evaluated: reg.Counter("mitigation_slowloris_evaluated_total"),
		blocked:   reg.Counter("mitigation_slowloris_blocked_total"),
		errs:      reg.Counter("mitigation_slowloris_errors_total"),
		duration:  reg.Histogram("mitigation_slowloris_duration_seconds"),
	}
	c := cfg
	l.cfg.Store(&c)
	return l, nil
}

// Update remplace atomiquement la configuration. Renvoie une erreur
// si la nouvelle config est invalide ; l'ancienne reste active
// (fail-open sur reload).
func (l *Limiter) Update(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		l.errs.Inc()
		return err
	}
	c := cfg
	l.cfg.Store(&c)
	return nil
}

// snapshot retourne la config courante (pointeur immuable).
func (l *Limiter) snapshot() Config { return *l.cfg.Load() }

// Config retourne un snapshot de la configuration active. Sûr en
// concurrence.
func (l *Limiter) Config() Config { return l.snapshot() }

// allow tente de réserver un slot pour ip. Retourne true si la
// connexion est acceptée, false si elle dépasse le quota.
func (l *Limiter) allow(ip string) bool {
	start := time.Now()
	defer func() { l.duration.Observe(time.Since(start).Seconds()) }()
	l.evaluated.Inc()

	cfg := l.snapshot()
	if !cfg.Enabled || cfg.MaxConnsPerIP <= 0 {
		return true // pass-through
	}

	l.mu.Lock()
	cur := l.counts[ip]
	if cur >= cfg.MaxConnsPerIP {
		l.mu.Unlock()
		l.blocked.Inc()
		return false
	}
	l.counts[ip] = cur + 1
	l.mu.Unlock()
	return true
}

// release libère un slot (appelé sur Conn.Close).
func (l *Limiter) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if v := l.counts[ip]; v > 1 {
		l.counts[ip] = v - 1
	} else {
		delete(l.counts, ip)
	}
}

// Active retourne le nombre de connexions actuellement comptées pour ip.
// Exposé pour les tests et l'observabilité (pas de hot path).
func (l *Limiter) Active(ip string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.counts[ip]
}

// Metrics retourne la registry injectée à New().
func (l *Limiter) Metrics() metrics.Registry { return l.reg }

// Wrap enveloppe un net.Listener ; Accept() rejette les connexions
// qui dépassent le quota. Les connexions retournées sont des
// net.Conn standard dont Close() libère le slot.
func (l *Limiter) Wrap(ln net.Listener) net.Listener {
	return &limitedListener{Listener: ln, l: l}
}

type limitedListener struct {
	net.Listener
	l *Limiter
}

func (ll *limitedListener) Accept() (net.Conn, error) {
	for {
		c, err := ll.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := remoteIP(c)
		if !ll.l.allow(ip) {
			// Connexion rejetée : on ferme immédiatement et on en
			// accepte une nouvelle. Pas de panic, fail-open en cas
			// d'erreur de Close (best-effort).
			_ = c.Close()
			continue
		}
		return &trackedConn{Conn: c, ip: ip, l: ll.l}, nil
	}
}

// trackedConn libère le slot une seule fois sur Close.
type trackedConn struct {
	net.Conn
	ip   string
	l    *Limiter
	once sync.Once
}

func (t *trackedConn) Close() error {
	t.once.Do(func() { t.l.release(t.ip) })
	return t.Conn.Close()
}

// remoteIP extrait l'IP textuelle depuis l'adresse distante.
// Retourne "unknown" si parsing échoue (fail-open : un IP non
// parsable est traité comme un bucket distinct, pas comme un blocage).
func remoteIP(c net.Conn) string {
	addr := c.RemoteAddr()
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "unknown"
	}
	return host
}
