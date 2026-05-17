// Package geoip enrichit chaque requête entrante avec un compteur
// par pays (ISO 3166-1 alpha-2) exposé en métrique Prometheus.
//
// Implémentation pur-Go via github.com/phuslu/iploc : base embarquée
// (~80 KB), aucune dépendance réseau au runtime, compatible
// CGO_ENABLED=0 et cross-platform Windows/Linux.
//
// Politique : on observe l'IP source uniquement pour la
// catégorisation par pays — aucune IP n'est stockée, conformément aux
// règles AGENTS.md (pas de PII brute). Les IP privées / loopback
// retournent le pseudo-code "LO" (local).
package geoip

import (
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/phuslu/iploc"

	"anti-ddos/proxy/internal/metrics"
)

// Counter agrège les requêtes par code pays. Sûr en concurrence.
type Counter struct {
	reg  metrics.Registry
	mu   sync.RWMutex
	cnts map[string]metrics.Counter
}

// New construit un Counter rattaché à la registry du data plane.
func New(reg metrics.Registry) *Counter {
	return &Counter{
		reg:  reg,
		cnts: make(map[string]metrics.Counter),
	}
}

// Middleware enveloppe un handler en incrémentant le compteur du pays
// de l'IP source. Fail-open : toute erreur de lookup compte en "ZZ".
func (c *Counter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.observe(r)
		next.ServeHTTP(w, r)
	})
}

func (c *Counter) observe(r *http.Request) {
	cc := CountryFor(r.RemoteAddr, r.Header.Get("X-Forwarded-For"))
	c.inc(cc)
}

func (c *Counter) inc(cc string) {
	c.mu.RLock()
	cnt, ok := c.cnts[cc]
	c.mu.RUnlock()
	if !ok {
		c.mu.Lock()
		// Re-check après lock pour éviter les duplicates en cas de race.
		if cnt, ok = c.cnts[cc]; !ok {
			cnt = c.reg.Counter("proxy_requests_by_country_" + cc + "_total")
			c.cnts[cc] = cnt
		}
		c.mu.Unlock()
	}
	cnt.Inc()
}

// CountryFor extrait l'IP cliente et retourne un code pays ISO-3166
// alpha-2 majuscule. "LO" pour loopback/privé, "ZZ" pour inconnu.
func CountryFor(remoteAddr, xff string) string {
	ip := clientIP(remoteAddr, xff)
	if ip == nil {
		return "ZZ"
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return "LO"
	}
	raw := iploc.Country(ip)
	if len(raw) != 2 {
		return "ZZ"
	}
	return strings.ToUpper(string(raw))
}

func clientIP(remoteAddr, xff string) net.IP {
	// X-Forwarded-For : premier hop = client réel quand le proxy est
	// derrière un LB de confiance. On reste pragmatique ici : si l'XFF
	// existe on l'utilise, sinon RemoteAddr du peer TCP.
	if xff != "" {
		head := xff
		if i := strings.IndexByte(xff, ','); i >= 0 {
			head = xff[:i]
		}
		if ip := net.ParseIP(strings.TrimSpace(head)); ip != nil {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// RemoteAddr peut être déjà sans port dans certains tests.
		if ip := net.ParseIP(remoteAddr); ip != nil {
			return ip
		}
		return nil
	}
	return net.ParseIP(host)
}
