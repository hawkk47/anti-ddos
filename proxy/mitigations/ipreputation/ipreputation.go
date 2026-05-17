// Package ipreputation implémente une mitigation L3/L4 par réputation
// d'IP source : allowlist + blocklist statiques (CIDR) chargées
// depuis la config, plus une blocklist dynamique alimentée à chaud
// par les autres mitigations (synflood, handshakeguard, etc.) avec
// une TTL d'expiration.
//
// Modèle d'attaque : trafic provenant de plages d'IP connues comme
// hostiles (botnets, scanners, ranges déjà incriminées dans des
// vagues récentes).
//
// Mitigation : refus de l'Accept() TCP pour toute IP source qui :
//   - n'est pas dans l'allowlist (si l'allowlist est non vide et le
//     mode "strict" actif), OU
//   - est dans la blocklist statique, OU
//   - est dans la blocklist dynamique (et l'entrée n'a pas expiré).
//
// Mode d'erreur : fail-open. Si la config est désactivée ou l'IP
// non parsable, la connexion passe. La blocklist a priorité sur
// l'allowlist (allow + block = block).
//
// Pure-Go, no panic, no cgo. Le hot path est un parcours linéaire
// du CIDRSet statique + une lecture map[string] sous RWMutex (la
// dynamique reste bornée par MaxDynamicEntries).
package ipreputation

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"anti-ddos/proxy/internal/metrics"
	"anti-ddos/proxy/internal/netshield"
)

// Config est la configuration runtime de la mitigation.
type Config struct {
	Enabled bool
	// Allowlist : CIDR autorisées d'office. Si AllowlistStrict=true
	// et la liste est non vide, toute IP hors allowlist est refusée.
	Allowlist []string
	// AllowlistStrict : si true, les IP hors allowlist sont bloquées.
	// Si false (défaut), l'allowlist sert uniquement à exempter
	// certaines IP des blocklists statique/dynamique.
	AllowlistStrict bool
	// Blocklist : CIDR refusées en permanence.
	Blocklist []string
	// MaxDynamicEntries : plafond du nombre d'IP dans la blocklist
	// dynamique (anti-DoS sur le mitigateur lui-même). <=0 ⇒ 100000.
	MaxDynamicEntries int
	// DefaultBlockTTL : durée par défaut d'un blocage dynamique
	// quand l'appelant ne précise pas. <=0 ⇒ 5 min.
	DefaultBlockTTL time.Duration
	// OnError : "allow" (défaut) ou "deny".
	OnError string
}

// Validate vérifie qu'une config est utilisable.
func (c Config) Validate() error {
	if c.OnError != "" && c.OnError != "allow" && c.OnError != "deny" {
		return errors.New(`OnError must be "allow" or "deny"`)
	}
	if _, err := netshield.NewCIDRSet(c.Allowlist); err != nil {
		return err
	}
	if _, err := netshield.NewCIDRSet(c.Blocklist); err != nil {
		return err
	}
	if c.MaxDynamicEntries < 0 {
		return errors.New("MaxDynamicEntries must be >= 0")
	}
	if c.DefaultBlockTTL < 0 {
		return errors.New("DefaultBlockTTL must be >= 0")
	}
	return nil
}

// resolved : tuple immuable construit après Validate().
type resolved struct {
	cfg   Config
	allow *netshield.CIDRSet
	block *netshield.CIDRSet
	ttl   time.Duration
	cap   int
}

// Limiter applique la réputation. Sûr en concurrence.
type Limiter struct {
	state atomic.Pointer[resolved]

	mu  sync.RWMutex
	dyn map[string]time.Time // ip ⇒ expires-at

	now func() time.Time
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
		dyn:       make(map[string]time.Time),
		now:       time.Now,
		reg:       reg,
		evaluated: reg.Counter("mitigation_ip_reputation_evaluated_total"),
		blocked:   reg.Counter("mitigation_ip_reputation_blocked_total"),
		errs:      reg.Counter("mitigation_ip_reputation_errors_total"),
		duration:  reg.Histogram("mitigation_ip_reputation_duration_seconds"),
	}
	if err := l.applyConfig(cfg); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Limiter) applyConfig(cfg Config) error {
	allow, err := netshield.NewCIDRSet(cfg.Allowlist)
	if err != nil {
		return err
	}
	block, err := netshield.NewCIDRSet(cfg.Blocklist)
	if err != nil {
		return err
	}
	ttl := cfg.DefaultBlockTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	cap := cfg.MaxDynamicEntries
	if cap <= 0 {
		cap = 100_000
	}
	l.state.Store(&resolved{cfg: cfg, allow: allow, block: block, ttl: ttl, cap: cap})
	return nil
}

// Update remplace atomiquement la configuration.
func (l *Limiter) Update(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		l.errs.Inc()
		return err
	}
	if err := l.applyConfig(cfg); err != nil {
		l.errs.Inc()
		return err
	}
	return nil
}

// Config retourne la config courante.
func (l *Limiter) Config() Config { return l.state.Load().cfg }

// Metrics retourne la registry.
func (l *Limiter) Metrics() metrics.Registry { return l.reg }

// BlockIP ajoute (ou rafraîchit) une IP dans la blocklist dynamique
// pour la durée ttl. ttl <=0 ⇒ DefaultBlockTTL. No-op si la config
// est désactivée.
func (l *Limiter) BlockIP(ip net.IP, ttl time.Duration) {
	if ip == nil {
		return
	}
	st := l.state.Load()
	if !st.cfg.Enabled {
		return
	}
	if ttl <= 0 {
		ttl = st.ttl
	}
	exp := l.now().Add(ttl)
	key := ip.String()

	l.mu.Lock()
	defer l.mu.Unlock()
	// GC paresseuse + cap.
	if len(l.dyn) >= st.cap {
		l.gcLocked()
	}
	if len(l.dyn) >= st.cap {
		// Toujours plein : on remplace l'entrée la plus ancienne au lieu
		// de panic / refus silencieux.
		var oldestK string
		var oldestT time.Time
		for k, v := range l.dyn {
			if oldestK == "" || v.Before(oldestT) {
				oldestK = k
				oldestT = v
			}
		}
		delete(l.dyn, oldestK)
	}
	l.dyn[key] = exp
}

// gcLocked supprime les entrées expirées. Doit être appelée sous l.mu.
func (l *Limiter) gcLocked() {
	now := l.now()
	for k, exp := range l.dyn {
		if !exp.After(now) {
			delete(l.dyn, k)
		}
	}
}

// IsBlocked applique la politique complète et retourne true si la
// connexion doit être refusée.
func (l *Limiter) IsBlocked(ip net.IP) bool {
	start := l.now()
	defer func() { l.duration.Observe(time.Since(start).Seconds()) }()
	l.evaluated.Inc()

	st := l.state.Load()
	if !st.cfg.Enabled {
		return false
	}
	if ip == nil {
		// Fail-open ou fail-closed selon OnError.
		if st.cfg.OnError == "deny" {
			l.blocked.Inc()
			return true
		}
		return false
	}
	// Loopback / privé : jamais filtré (santé locale).
	if netshield.IsPrivateOrLoopback(ip) {
		return false
	}
	inAllow := st.allow.Contains(ip)
	if st.cfg.AllowlistStrict && st.allow.Len() > 0 && !inAllow {
		l.blocked.Inc()
		return true
	}
	if inAllow {
		// L'allowlist exempte des blocklists.
		return false
	}
	if st.block.Contains(ip) {
		l.blocked.Inc()
		return true
	}
	// Blocklist dynamique.
	l.mu.RLock()
	exp, ok := l.dyn[ip.String()]
	l.mu.RUnlock()
	if ok && exp.After(start) {
		l.blocked.Inc()
		return true
	}
	return false
}

// DynamicSize retourne le nombre d'entrées dans la blocklist
// dynamique (exposé pour les tests et /admin).
func (l *Limiter) DynamicSize() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.dyn)
}

// WrapListener enveloppe un net.Listener. Accept() rejette
// silencieusement (ferme la conn) les IP bloquées.
func (l *Limiter) WrapListener(ln net.Listener) net.Listener {
	return &filteredListener{Listener: ln, l: l}
}

type filteredListener struct {
	net.Listener
	l *Limiter
}

func (fl *filteredListener) Accept() (net.Conn, error) {
	for {
		c, err := fl.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := netshield.ParseAddr(c.RemoteAddr())
		if fl.l.IsBlocked(ip) {
			_ = c.Close()
			continue
		}
		return c, nil
	}
}
