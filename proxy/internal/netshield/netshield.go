// Package netshield fournit les primitives partagées par les
// mitigations couche réseau (L3/L4) qui s'appliquent au moment de
// l'Accept() TCP, avant tout traitement HTTP/TLS.
//
// Toutes les fonctions sont pures-Go, sans cgo, sans syscall
// spécifique à un OS — la mitigation kernel (eBPF/XDP/iptables) est
// hors scope du projet (cf. AGENTS.md et ADR 0002).
//
// Helpers :
//   - CIDRSet  : sac de préfixes CIDR pour lookups O(n) sur petites
//     listes (allowlist / blocklist statiques).
//   - SubnetKey : agrège une IP en /24 (IPv4) ou /48 (IPv6) pour
//     appliquer des quotas par sous-réseau.
//   - ParseAddr : extrait une net.IP exploitable depuis une net.Addr.
//
// Aucune métrique n'est exposée ici : chaque mitigation a son propre
// jeu de 4 compteurs et appelle ces helpers comme des fonctions pures.
package netshield

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

// ParseAddr extrait l'IP source d'une net.Addr TCP. Retourne nil si
// l'adresse est absente ou non parsable — l'appelant choisit alors
// son comportement (fail-open ou fail-closed selon la mitigation).
func ParseAddr(a net.Addr) net.IP {
	if a == nil {
		return nil
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		// Certains tests passent une adresse sans port.
		host = a.String()
	}
	// Retire le zone-id éventuel des adresses IPv6 link-local.
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	return net.ParseIP(host)
}

// SubnetKey retourne une clé textuelle stable représentant le
// sous-réseau de ip : /24 pour IPv4, /48 pour IPv6. Utilisé pour les
// quotas par sous-réseau (un attaquant qui change d'IP dans son /24
// reste dans le même bucket).
//
// Retourne "" si ip est nil. La clé n'est pas une notation CIDR
// (pas de "/24" en suffixe) pour rester compacte dans les logs et
// les maps de comptage.
func SubnetKey(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return strconv.Itoa(int(v4[0])) + "." + strconv.Itoa(int(v4[1])) + "." + strconv.Itoa(int(v4[2]))
	}
	v6 := ip.To16()
	if v6 == nil {
		return ""
	}
	// /48 = 6 premiers octets.
	mask := net.CIDRMask(48, 128)
	masked := v6.Mask(mask)
	return masked.String()
}

// CIDRSet est un ensemble de préfixes CIDR consultable en O(n).
// Sûr en lecture concurrente après construction. Pour les mutations
// (rechargement), construire un nouvel ensemble et le swap atomiquement
// côté appelant.
type CIDRSet struct {
	nets []*net.IPNet
}

// NewCIDRSet parse une liste de chaînes CIDR ("192.0.2.0/24",
// "2001:db8::/32") ou d'IP unitaires ("203.0.113.5"). Retourne une
// erreur agrégée listant toutes les entrées invalides.
func NewCIDRSet(entries []string) (*CIDRSet, error) {
	s := &CIDRSet{nets: make([]*net.IPNet, 0, len(entries))}
	var bad []string
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "/") {
			ip := net.ParseIP(e)
			if ip == nil {
				bad = append(bad, raw)
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				e = v4.String() + "/32"
			} else {
				e = ip.String() + "/128"
			}
		}
		_, n, err := net.ParseCIDR(e)
		if err != nil {
			bad = append(bad, raw)
			continue
		}
		s.nets = append(s.nets, n)
	}
	if len(bad) > 0 {
		return nil, errors.New("invalid CIDR entries: " + strings.Join(bad, ", "))
	}
	return s, nil
}

// Contains rapporte si ip appartient à l'un des préfixes du set.
// Retourne false si ip est nil ou si le set est vide.
func (s *CIDRSet) Contains(ip net.IP) bool {
	if s == nil || len(s.nets) == 0 || ip == nil {
		return false
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Len retourne le nombre de préfixes du set.
func (s *CIDRSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.nets)
}

// IsPrivateOrLoopback retourne true pour les IP non routables sur
// internet (loopback, link-local, privées RFC1918/ULA, unspecified).
// Les mitigations L3/L4 utilisent ce filtre pour exempter le trafic
// interne des quotas d'attaque (sinon les health checks loopback
// déclenchent les blocs).
func IsPrivateOrLoopback(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsUnspecified() || ip.IsMulticast()
}
