// Package handshakeguard détecte les connexions TCP "half-open
// applicatives" : la session TCP est établie (3-way handshake OK)
// mais aucun octet utile n'arrive dans la fenêtre HandshakeWindow.
//
// Modèle d'attaque : un attaquant ouvre des dizaines de milliers de
// connexions et n'envoie jamais le ClientHello TLS ou la première
// ligne HTTP. Sans cette mitigation, chaque connexion occupe une
// goroutine + un FD jusqu'au ReadHeaderTimeout, ce qui rend l'attaque
// très bon marché (équivalent fonctionnel d'un SYN-flood post-handshake).
//
// Mitigation : on enveloppe chaque connexion acceptée d'une Deadline
// "premier octet". Si aucun Read n'arrive avant cette deadline, la
// connexion est fermée. Les abandons sont comptés par IP et, au-delà
// d'un seuil par fenêtre glissante, l'IP est signalée à un Reporter
// (typiquement ipreputation) pour blocage temporaire.
//
// Mode d'erreur : fail-open. Si la deadline ne peut être posée
// (SetReadDeadline en erreur), la connexion passe sans surveillance.
//
// Pure-Go, no panic, no cgo. SetReadDeadline est cross-platform et
// universel sur net.Conn.
package handshakeguard

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"anti-ddos/proxy/internal/metrics"
	"anti-ddos/proxy/internal/netshield"
)

// Reporter est l'interface de notification (ipreputation).
type Reporter interface {
	BlockIP(ip net.IP, ttl time.Duration)
}

// Config est la configuration runtime.
type Config struct {
	Enabled bool
	// HandshakeWindow : durée max entre Accept() et premier octet
	// lu. >0 quand activé.
	HandshakeWindow time.Duration
	// AbandonThreshold : nombre d'abandons toléré par IP dans la
	// fenêtre ObserveWindow avant de signaler. >=1 si activé.
	AbandonThreshold int
	// ObserveWindow : fenêtre glissante de comptage. >0 si activé.
	ObserveWindow time.Duration
	// ReportTTL : durée du signalement vers le Reporter. <=0 ⇒
	// pas de signalement (mitigation purement défensive locale).
	ReportTTL time.Duration
	// OnError : "allow" (défaut) ou "deny".
	OnError string
}

// Validate vérifie la cohérence des champs.
func (c Config) Validate() error {
	if c.OnError != "" && c.OnError != "allow" && c.OnError != "deny" {
		return errors.New(`OnError must be "allow" or "deny"`)
	}
	if c.Enabled {
		if c.HandshakeWindow <= 0 {
			return errors.New("HandshakeWindow must be > 0 when enabled")
		}
		if c.AbandonThreshold < 1 {
			return errors.New("AbandonThreshold must be >= 1 when enabled")
		}
		if c.ObserveWindow <= 0 {
			return errors.New("ObserveWindow must be > 0 when enabled")
		}
	}
	if c.ReportTTL < 0 {
		return errors.New("ReportTTL must be >= 0")
	}
	return nil
}

// Limiter applique la mitigation.
type Limiter struct {
	cfg    atomic.Pointer[Config]
	mu     sync.Mutex
	events map[string][]time.Time // ip ⇒ timestamps d'abandons récents

	report atomic.Pointer[Reporter]
	now    func() time.Time

	reg metrics.Registry

	evaluated metrics.Counter
	blocked   metrics.Counter // = abandons détectés
	errs      metrics.Counter
	duration  metrics.Histogram
}

// New construit un Limiter.
func New(cfg Config, reg metrics.Registry) (*Limiter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if reg == nil {
		reg = metrics.NewInMemory()
	}
	l := &Limiter{
		events:    make(map[string][]time.Time),
		now:       time.Now,
		reg:       reg,
		evaluated: reg.Counter("mitigation_handshake_guard_evaluated_total"),
		blocked:   reg.Counter("mitigation_handshake_guard_blocked_total"),
		errs:      reg.Counter("mitigation_handshake_guard_errors_total"),
		duration:  reg.Histogram("mitigation_handshake_guard_duration_seconds"),
	}
	c := cfg
	l.cfg.Store(&c)
	return l, nil
}

// Update remplace la config.
func (l *Limiter) Update(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		l.errs.Inc()
		return err
	}
	c := cfg
	l.cfg.Store(&c)
	return nil
}

// Config retourne un snapshot.
func (l *Limiter) Config() Config { return *l.cfg.Load() }

// Metrics retourne la registry.
func (l *Limiter) Metrics() metrics.Registry { return l.reg }

// SetReporter branche un reporter (typiquement ipreputation).
func (l *Limiter) SetReporter(r Reporter) {
	if r == nil {
		l.report.Store(nil)
		return
	}
	l.report.Store(&r)
}

// recordAbandon enregistre un abandon et déclenche éventuellement un report.
func (l *Limiter) recordAbandon(ip net.IP) {
	l.blocked.Inc()
	if ip == nil || netshield.IsPrivateOrLoopback(ip) {
		return
	}
	cfg := l.Config()
	key := ip.String()
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()
	stamps := l.events[key]
	cutoff := now.Add(-cfg.ObserveWindow)
	kept := stamps[:0]
	for _, t := range stamps {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	if len(kept) > cfg.AbandonThreshold {
		kept = kept[len(kept)-cfg.AbandonThreshold:]
	}
	l.events[key] = kept

	if len(kept) >= cfg.AbandonThreshold && cfg.ReportTTL > 0 {
		rp := l.report.Load()
		if rp != nil {
			(*rp).BlockIP(ip, cfg.ReportTTL)
		}
	}
}

// WrapListener enveloppe un net.Listener.
func (l *Limiter) WrapListener(ln net.Listener) net.Listener {
	return &hgListener{Listener: ln, l: l}
}

type hgListener struct {
	net.Listener
	l *Limiter
}

func (hl *hgListener) Accept() (net.Conn, error) {
	c, err := hl.Listener.Accept()
	if err != nil {
		return nil, err
	}
	cfg := hl.l.Config()
	hl.l.evaluated.Inc()
	if !cfg.Enabled {
		return c, nil
	}
	if err := c.SetReadDeadline(time.Now().Add(cfg.HandshakeWindow)); err != nil {
		// Fail-open : pas de surveillance, conn rendue telle quelle.
		hl.l.errs.Inc()
		return c, nil
	}
	ip := netshield.ParseAddr(c.RemoteAddr())
	return &guardedConn{Conn: c, l: hl.l, ip: ip}, nil
}

// guardedConn lève la deadline au premier Read réussi et reporte
// un abandon si la première lecture timeout ou est fermée à zéro octet.
type guardedConn struct {
	net.Conn
	l         *Limiter
	ip        net.IP
	once      sync.Once
	firstRead atomic.Bool
}

func (g *guardedConn) Read(p []byte) (int, error) {
	n, err := g.Conn.Read(p)
	if n > 0 && !g.firstRead.Swap(true) {
		// Premier octet utile : on retire la deadline.
		_ = g.Conn.SetReadDeadline(time.Time{})
	}
	if err != nil && !g.firstRead.Load() {
		g.once.Do(func() { g.l.recordAbandon(g.ip) })
	}
	return n, err
}

func (g *guardedConn) Close() error {
	if !g.firstRead.Load() {
		g.once.Do(func() { g.l.recordAbandon(g.ip) })
	}
	return g.Conn.Close()
}
