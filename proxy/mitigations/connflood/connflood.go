// Package connflood implémente une mitigation L3/L4 par plafond du
// nombre de connexions TCP concurrentes par IP source ET par
// sous-réseau (/24 IPv4, /48 IPv6).
//
// Modèle d'attaque : un botnet ouvre des milliers de connexions
// TCP simultanées depuis quelques IP — ou une plage entière — pour
// épuiser les FDs / mémoire socket du proxy avant même que la
// couche applicative ne soit sollicitée. Différent de Slowloris :
// ici c'est le volume brut de connexions ouvertes qui sature, pas
// la durée d'une connexion individuelle.
//
// Mitigation : compteurs (IP, subnet) sous mutex ; toute Accept()
// qui ferait dépasser un des deux plafonds ferme la connexion.
//
// Mode d'erreur : fail-open. Une IP non parsable n'est pas comptée
// (laisse passer plutôt que d'agréger à tort sur "unknown").
//
// Pure-Go, no panic, no cgo. Hot path ~3 ops map + 1 mutex.
package connflood

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"anti-ddos/proxy/internal/metrics"
	"anti-ddos/proxy/internal/netshield"
)

// Config est la configuration runtime.
type Config struct {
	Enabled bool
	// MaxConnsPerIP : plafond par IP source. <=0 ⇒ illimité par IP.
	MaxConnsPerIP int
	// MaxConnsPerSubnet : plafond par sous-réseau (/24 ou /48).
	// <=0 ⇒ illimité par sous-réseau.
	MaxConnsPerSubnet int
	// OnError : "allow" (défaut) ou "deny".
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
	if c.MaxConnsPerSubnet < 0 {
		return errors.New("MaxConnsPerSubnet must be >= 0")
	}
	return nil
}

// Limiter applique les plafonds. Sûr en concurrence.
type Limiter struct {
	cfg atomic.Pointer[Config]

	mu     sync.Mutex
	perIP  map[string]int
	perSub map[string]int

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
		perIP:     make(map[string]int),
		perSub:    make(map[string]int),
		reg:       reg,
		evaluated: reg.Counter("mitigation_conn_flood_evaluated_total"),
		blocked:   reg.Counter("mitigation_conn_flood_blocked_total"),
		errs:      reg.Counter("mitigation_conn_flood_errors_total"),
		duration:  reg.Histogram("mitigation_conn_flood_duration_seconds"),
	}
	c := cfg
	l.cfg.Store(&c)
	return l, nil
}

// Update remplace atomiquement la configuration.
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

// reserve tente de comptabiliser une nouvelle connexion. Retourne
// (true, key, subnet) si la connexion est acceptée.
func (l *Limiter) reserve(ip net.IP) (bool, string, string) {
	start := time.Now()
	defer func() { l.duration.Observe(time.Since(start).Seconds()) }()
	l.evaluated.Inc()

	cfg := l.Config()
	if !cfg.Enabled {
		return true, "", ""
	}
	if ip == nil || netshield.IsPrivateOrLoopback(ip) {
		return true, "", ""
	}
	ipKey := ip.String()
	subKey := netshield.SubnetKey(ip)

	l.mu.Lock()
	defer l.mu.Unlock()
	if cfg.MaxConnsPerIP > 0 && l.perIP[ipKey] >= cfg.MaxConnsPerIP {
		l.blocked.Inc()
		return false, "", ""
	}
	if cfg.MaxConnsPerSubnet > 0 && l.perSub[subKey] >= cfg.MaxConnsPerSubnet {
		l.blocked.Inc()
		return false, "", ""
	}
	l.perIP[ipKey]++
	l.perSub[subKey]++
	return true, ipKey, subKey
}

func (l *Limiter) release(ipKey, subKey string) {
	if ipKey == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if v := l.perIP[ipKey]; v > 1 {
		l.perIP[ipKey] = v - 1
	} else {
		delete(l.perIP, ipKey)
	}
	if v := l.perSub[subKey]; v > 1 {
		l.perSub[subKey] = v - 1
	} else {
		delete(l.perSub, subKey)
	}
}

// ActiveIP retourne le nombre de connexions comptées pour ip.
func (l *Limiter) ActiveIP(ip string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.perIP[ip]
}

// ActiveSubnet retourne le nombre de connexions pour la clé subnet.
func (l *Limiter) ActiveSubnet(subKey string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.perSub[subKey]
}

// WrapListener enveloppe un net.Listener.
func (l *Limiter) WrapListener(ln net.Listener) net.Listener {
	return &cfListener{Listener: ln, l: l}
}

type cfListener struct {
	net.Listener
	l *Limiter
}

func (c *cfListener) Accept() (net.Conn, error) {
	for {
		raw, err := c.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := netshield.ParseAddr(raw.RemoteAddr())
		ok, ipKey, subKey := c.l.reserve(ip)
		if !ok {
			_ = raw.Close()
			continue
		}
		return &countedConn{Conn: raw, l: c.l, ipKey: ipKey, subKey: subKey}, nil
	}
}

type countedConn struct {
	net.Conn
	l      *Limiter
	ipKey  string
	subKey string
	once   sync.Once
}

func (cc *countedConn) Close() error {
	cc.once.Do(func() { cc.l.release(cc.ipKey, cc.subKey) })
	return cc.Conn.Close()
}
