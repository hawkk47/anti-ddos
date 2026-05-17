// Package synflood implémente une mitigation L3/L4 par rate-limit du
// taux d'acceptation TCP (Accept/s) par IP source ET par sous-réseau,
// via token bucket.
//
// Modèle d'attaque : déluge de SYN / nouvelles connexions TCP
// (post-SYN-cookie) destinées à épuiser l'accept queue applicative,
// le pool de goroutines, ou simplement à occuper le CPU du proxy.
// On ne peut pas filtrer au niveau SYN sans kernel (eBPF/XDP non
// portable cf. ADR 0002) mais on peut **borner le débit d'Accept()**
// effectifs : la connexion qui dépasse la cadence est immédiatement
// fermée, et son IP marquée comme suspecte (déléguée à ipreputation
// quand câblée).
//
// Mitigation : token bucket par IP + par /24 (ou /48). Le débit
// agrégé par sous-réseau attrape les attaques multi-IP au sein d'un
// même opérateur botnet.
//
// Mode d'erreur : fail-open. Une IP non parsable n'est pas comptée.
//
// Pure-Go, no panic. sync.Map sur le hot path comme httpflood pour
// éviter la contention.
package synflood

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"anti-ddos/proxy/internal/metrics"
	"anti-ddos/proxy/internal/netshield"
)

// Reporter est l'interface que synflood appelle pour signaler les
// IP qui ont dépassé le quota. Permet de découpler de ipreputation
// (qu'on injecte côté server.go via SetReporter).
type Reporter interface {
	BlockIP(ip net.IP, ttl time.Duration)
}

// Config est la configuration runtime.
type Config struct {
	Enabled bool
	// AcceptsPerSecondPerIP : débit soutenu d'Accept par IP. >0.
	AcceptsPerSecondPerIP float64
	// BurstPerIP : capacité du bucket par IP. >=1.
	BurstPerIP int
	// AcceptsPerSecondPerSubnet : débit soutenu par /24 (ou /48).
	// <=0 ⇒ pas de quota subnet.
	AcceptsPerSecondPerSubnet float64
	// BurstPerSubnet : capacité du bucket subnet. >=1 si rate>0.
	BurstPerSubnet int
	// ReportTTL : si non nul et un reporter est branché, les IP qui
	// dépassent sont signalées pour ce TTL. <=0 ⇒ pas de report.
	ReportTTL time.Duration
	// OnError : "allow" (défaut) ou "deny".
	OnError string
}

// Validate vérifie qu'une config est utilisable.
func (c Config) Validate() error {
	if c.OnError != "" && c.OnError != "allow" && c.OnError != "deny" {
		return errors.New(`OnError must be "allow" or "deny"`)
	}
	if c.Enabled {
		if c.AcceptsPerSecondPerIP <= 0 {
			return errors.New("AcceptsPerSecondPerIP must be > 0")
		}
		if c.BurstPerIP < 1 {
			return errors.New("BurstPerIP must be >= 1")
		}
		if c.AcceptsPerSecondPerSubnet > 0 && c.BurstPerSubnet < 1 {
			return errors.New("BurstPerSubnet must be >= 1 when rate>0")
		}
	}
	if c.ReportTTL < 0 {
		return errors.New("ReportTTL must be >= 0")
	}
	return nil
}

// bucket : token bucket protégé par mutex.
type bucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// Limiter applique le rate-limit. Sûr en concurrence.
type Limiter struct {
	cfg     atomic.Pointer[Config]
	ipBuck  sync.Map // ip   → *bucket
	subBuck sync.Map // sub  → *bucket
	report  atomic.Pointer[Reporter]
	now     func() time.Time

	reg metrics.Registry

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
		now:       time.Now,
		reg:       reg,
		evaluated: reg.Counter("mitigation_syn_flood_evaluated_total"),
		blocked:   reg.Counter("mitigation_syn_flood_blocked_total"),
		errs:      reg.Counter("mitigation_syn_flood_errors_total"),
		duration:  reg.Histogram("mitigation_syn_flood_duration_seconds"),
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

func (l *Limiter) takeFrom(m *sync.Map, key string, rate float64, burst int) bool {
	v, _ := m.LoadOrStore(key, &bucket{tokens: float64(burst), last: l.now()})
	b := v.(*bucket)
	b.mu.Lock()
	defer b.mu.Unlock()
	now := l.now()
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rate
		cap := float64(burst)
		if b.tokens > cap {
			b.tokens = cap
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// allow décide si une nouvelle connexion depuis ip peut être acceptée.
func (l *Limiter) allow(ip net.IP) bool {
	start := l.now()
	defer func() { l.duration.Observe(time.Since(start).Seconds()) }()
	l.evaluated.Inc()

	cfg := l.Config()
	if !cfg.Enabled {
		return true
	}
	if ip == nil || netshield.IsPrivateOrLoopback(ip) {
		return true
	}
	if !l.takeFrom(&l.ipBuck, ip.String(), cfg.AcceptsPerSecondPerIP, cfg.BurstPerIP) {
		l.blocked.Inc()
		l.report1(ip, cfg)
		return false
	}
	if cfg.AcceptsPerSecondPerSubnet > 0 {
		if !l.takeFrom(&l.subBuck, netshield.SubnetKey(ip),
			cfg.AcceptsPerSecondPerSubnet, cfg.BurstPerSubnet) {
			l.blocked.Inc()
			l.report1(ip, cfg)
			return false
		}
	}
	return true
}

func (l *Limiter) report1(ip net.IP, cfg Config) {
	if cfg.ReportTTL <= 0 {
		return
	}
	rp := l.report.Load()
	if rp == nil {
		return
	}
	(*rp).BlockIP(ip, cfg.ReportTTL)
}

// WrapListener enveloppe un net.Listener.
func (l *Limiter) WrapListener(ln net.Listener) net.Listener {
	return &sfListener{Listener: ln, l: l}
}

type sfListener struct {
	net.Listener
	l *Limiter
}

func (sl *sfListener) Accept() (net.Conn, error) {
	for {
		c, err := sl.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := netshield.ParseAddr(c.RemoteAddr())
		if !sl.l.allow(ip) {
			_ = c.Close()
			continue
		}
		return c, nil
	}
}
