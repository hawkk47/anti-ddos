// Package geoblockl4 bloque les connexions TCP en fonction du code
// pays ISO-3166 de l'IP source, AVANT toute terminaison TLS ou tout
// traitement HTTP.
//
// Modèle d'attaque : opérations de DDoS / reconnaissance orchestrées
// depuis des juridictions hors-périmètre commercial du service.
// Bloquer au niveau L4 évite de payer le coût d'un handshake TLS
// (signature ECDSA/RSA + AEAD) sur du trafic qui sera de toute façon
// rejeté plus tard.
//
// Mitigation : lookup phuslu/iploc (base embarquée, pur-Go) sur
// chaque Accept() ; refus si le pays est dans Block ou hors d'Allow
// quand Allow est non vide.
//
// Mode d'erreur : fail-open. Une IP loopback / privée / inconnue
// passe (jamais bloquée par géo).
package geoblockl4

import (
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/phuslu/iploc"

	"anti-ddos/proxy/internal/metrics"
	"anti-ddos/proxy/internal/netshield"
)

// Config est la configuration runtime.
type Config struct {
	Enabled bool
	// Allow : liste de codes pays (ISO-3166-1 alpha-2 majuscule) autorisés.
	// Vide ⇒ pas de filtre allow.
	Allow []string
	// Block : codes pays refusés. Prioritaire sur Allow (Allow + Block = Block).
	Block []string
	// OnError : "allow" (défaut) ou "deny".
	OnError string
}

// Validate.
func (c Config) Validate() error {
	if c.OnError != "" && c.OnError != "allow" && c.OnError != "deny" {
		return errors.New(`OnError must be "allow" or "deny"`)
	}
	for _, cc := range c.Allow {
		if len(strings.TrimSpace(cc)) != 2 {
			return errors.New("Allow entries must be ISO-3166 alpha-2 codes")
		}
	}
	for _, cc := range c.Block {
		if len(strings.TrimSpace(cc)) != 2 {
			return errors.New("Block entries must be ISO-3166 alpha-2 codes")
		}
	}
	return nil
}

type resolved struct {
	cfg   Config
	allow map[string]struct{}
	block map[string]struct{}
}

// Limiter.
type Limiter struct {
	state atomic.Pointer[resolved]
	reg   metrics.Registry

	evaluated metrics.Counter
	blocked   metrics.Counter
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
		reg:       reg,
		evaluated: reg.Counter("mitigation_geoblock_l4_evaluated_total"),
		blocked:   reg.Counter("mitigation_geoblock_l4_blocked_total"),
		errs:      reg.Counter("mitigation_geoblock_l4_errors_total"),
		duration:  reg.Histogram("mitigation_geoblock_l4_duration_seconds"),
	}
	l.store(cfg)
	return l, nil
}

func (l *Limiter) store(cfg Config) {
	allow := make(map[string]struct{}, len(cfg.Allow))
	for _, cc := range cfg.Allow {
		allow[strings.ToUpper(strings.TrimSpace(cc))] = struct{}{}
	}
	block := make(map[string]struct{}, len(cfg.Block))
	for _, cc := range cfg.Block {
		block[strings.ToUpper(strings.TrimSpace(cc))] = struct{}{}
	}
	l.state.Store(&resolved{cfg: cfg, allow: allow, block: block})
}

// Update.
func (l *Limiter) Update(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		l.errs.Inc()
		return err
	}
	l.store(cfg)
	return nil
}

// Config retourne un snapshot.
func (l *Limiter) Config() Config { return l.state.Load().cfg }

// Metrics retourne la registry.
func (l *Limiter) Metrics() metrics.Registry { return l.reg }

// LookupCountry expose la résolution pays pour les tests et le diag.
// Loopback/privé ⇒ "LO", inconnu ⇒ "ZZ".
func LookupCountry(ip net.IP) string {
	if ip == nil {
		return "ZZ"
	}
	if netshield.IsPrivateOrLoopback(ip) {
		return "LO"
	}
	raw := iploc.Country(ip)
	if len(raw) != 2 {
		return "ZZ"
	}
	return strings.ToUpper(string(raw))
}

// IsBlocked applique la politique.
func (l *Limiter) IsBlocked(ip net.IP) bool {
	start := time.Now()
	defer func() { l.duration.Observe(time.Since(start).Seconds()) }()
	l.evaluated.Inc()

	st := l.state.Load()
	if !st.cfg.Enabled {
		return false
	}
	if ip == nil || netshield.IsPrivateOrLoopback(ip) {
		return false
	}
	cc := LookupCountry(ip)
	if cc == "LO" {
		return false
	}
	if _, bad := st.block[cc]; bad {
		l.blocked.Inc()
		return true
	}
	if len(st.allow) > 0 {
		if _, ok := st.allow[cc]; !ok {
			l.blocked.Inc()
			return true
		}
	}
	return false
}

// WrapListener enveloppe un net.Listener.
func (l *Limiter) WrapListener(ln net.Listener) net.Listener {
	return &gbListener{Listener: ln, l: l}
}

type gbListener struct {
	net.Listener
	l *Limiter
}

func (gl *gbListener) Accept() (net.Conn, error) {
	for {
		c, err := gl.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := netshield.ParseAddr(c.RemoteAddr())
		if gl.l.IsBlocked(ip) {
			_ = c.Close()
			continue
		}
		return c, nil
	}
}
