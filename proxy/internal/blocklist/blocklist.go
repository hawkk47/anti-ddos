// Package blocklist fournit un set IP versionné, hot-reloadable et
// allocation-free sur le chemin de lecture, conçu pour être consulté
// au début de la chaîne de mitigation credential-stuffing.
//
// Voir ADR 0004 (docs/adr/0004-credstuff-behavioral.md) pour le
// rationale architectural.
//
// Invariants :
//
//   - Lookup est O(1), sans allocation, sans lock (atomic.Pointer +
//     map en lecture seule).
//   - Replace est atomique : un Lookup voit toujours soit l'ancien
//     soit le nouveau snapshot, jamais un état intermédiaire.
//   - Les versions sont strictement croissantes ; un Replace avec
//     version <= courante est ignoré (idempotence + protection
//     contre les pushs hors ordre).
//   - Les entrées expirées sont ignorées à la lecture (lazy expiry).
//     Pas de goroutine de sweep : la mémoire est bornée par le cap
//     du Replace suivant.
//
// Le package n'a pas d'effet de bord externe : pas de I/O réseau,
// pas de log. Les compteurs Prometheus sont alimentés via
// metrics.Registry passé à New.
package blocklist

import (
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

// MaxEntries est la borne dure acceptée par Replace. Au-delà, le push
// est rejeté avec une erreur. Sanity cap pour éviter qu'un control
// plane buggé ne fasse exploser la mémoire du data plane.
const MaxEntries = 100_000

// MaxReasonLen borne la longueur du champ Reason (audit, runbooks).
const MaxReasonLen = 128

// Entry décrit une IP blocklistée avec son TTL.
//
// Le zero value n'est pas valide : utiliser NewEntry ou construire
// manuellement et faire valider par Replace.
type Entry struct {
	IP        netip.Addr
	ExpiresAt time.Time
	// Reason : libellé court (≤ MaxReasonLen) pour audit/logs.
	// Ex: "per-account-fan-out", "per-ip-failed-rate".
	Reason string
}

// snapshot est le contenu immuable d'un Set à un instant t. Une fois
// publié via atomic.Pointer, il ne doit plus être modifié.
type snapshot struct {
	version int64
	byIP    map[netip.Addr]Entry
}

// Set est un ensemble d'IP blocklistées thread-safe, conçu pour des
// lectures fréquentes (chemin chaud) et des écritures rares (push
// périodique depuis le control plane).
type Set struct {
	cur atomic.Pointer[snapshot]

	metrics struct {
		// Compteurs monotones (les seuls exposés par metrics.Registry).
		// Pour size/version utiliser Size()/Version() directement.
		lookups metrics.Counter
		hits    metrics.Counter
		expired metrics.Counter
		rejects metrics.Counter
	}

	now func() time.Time
}

// New construit un Set vide (version 0, aucune entrée) et enregistre
// les métriques.
//
// reg peut être nil ; dans ce cas les compteurs sont des no-op.
func New(reg metrics.Registry) *Set {
	s := &Set{now: time.Now}
	s.cur.Store(&snapshot{version: 0, byIP: map[netip.Addr]Entry{}})

	if reg != nil {
		s.metrics.lookups = reg.Counter("blocklist_credstuff_lookups_total")
		s.metrics.hits = reg.Counter("blocklist_credstuff_hits_total")
		s.metrics.expired = reg.Counter("blocklist_credstuff_expired_total")
		s.metrics.rejects = reg.Counter("blocklist_credstuff_rejects_total")
	} else {
		s.metrics.lookups = noopCounter{}
		s.metrics.hits = noopCounter{}
		s.metrics.expired = noopCounter{}
		s.metrics.rejects = noopCounter{}
	}
	return s
}

// Lookup retourne l'entrée associée à ip si elle est blocklistée et
// non expirée. Sans allocation, sans lock.
//
// Si ip n'est pas valide (netip.Addr zero), Lookup retourne (Entry{}, false).
func (s *Set) Lookup(ip netip.Addr) (Entry, bool) {
	s.metrics.lookups.Inc()
	if !ip.IsValid() {
		return Entry{}, false
	}
	snap := s.cur.Load()
	entry, ok := snap.byIP[ip]
	if !ok {
		return Entry{}, false
	}
	if !entry.ExpiresAt.IsZero() && !s.now().Before(entry.ExpiresAt) {
		// Lazy expiry : l'entrée existe encore en mémoire mais a
		// dépassé son TTL ; on la traite comme absente.
		s.metrics.expired.Inc()
		return Entry{}, false
	}
	s.metrics.hits.Inc()
	return entry, true
}

// Replace publie atomiquement un nouveau snapshot.
//
// Règles :
//
//   - version DOIT être strictement supérieur à la version courante.
//     Sinon Replace retourne ErrStaleVersion et le snapshot existant
//     est préservé (idempotence + protection contre les pushs hors
//     ordre).
//   - len(entries) DOIT être ≤ MaxEntries.
//   - Chaque entrée DOIT avoir une IP valide et un Reason ≤ MaxReasonLen.
//   - Les entrées déjà expirées au moment du Replace sont silencieusement
//     ignorées (gain mémoire ; le push reste accepté).
//   - Les doublons sur la même IP : la dernière entrée gagne.
//
// L'ancien snapshot reste consultable par les Lookup en cours ; il
// sera collecté quand plus personne ne le référence.
func (s *Set) Replace(version int64, entries []Entry) error {
	cur := s.cur.Load()
	if version <= cur.version {
		s.metrics.rejects.Inc()
		return fmt.Errorf("%w: have=%d got=%d",
			ErrStaleVersion, cur.version, version)
	}
	if len(entries) > MaxEntries {
		s.metrics.rejects.Inc()
		return fmt.Errorf("%w: %d > %d",
			ErrTooManyEntries, len(entries), MaxEntries)
	}

	// Validation passe d'abord : si une entrée est invalide on rejette
	// le push entier (cohérence : pas de snapshot partiellement appliqué).
	now := s.now()
	for i := range entries {
		if !entries[i].IP.IsValid() {
			s.metrics.rejects.Inc()
			return fmt.Errorf("entry[%d]: %w", i, ErrInvalidIP)
		}
		if len(entries[i].Reason) > MaxReasonLen {
			s.metrics.rejects.Inc()
			return fmt.Errorf("entry[%d]: reason length %d > %d",
				i, len(entries[i].Reason), MaxReasonLen)
		}
	}

	byIP := make(map[netip.Addr]Entry, len(entries))
	for i := range entries {
		e := entries[i]
		// Drop silencieusement les entrées déjà expirées au push.
		if !e.ExpiresAt.IsZero() && !now.Before(e.ExpiresAt) {
			continue
		}
		byIP[e.IP] = e
	}

	next := &snapshot{version: version, byIP: byIP}
	s.cur.Store(next)
	return nil
}

// Size retourne le nombre d'entrées dans le snapshot courant. Inclut
// les entrées expirées non encore évincées (l'éviction est faite par
// le prochain Replace).
func (s *Set) Size() int {
	return len(s.cur.Load().byIP)
}

// Version retourne la version du snapshot courant.
func (s *Set) Version() int64 {
	return s.cur.Load().version
}

// Reset vide le set et incrémente la version. Utile en runbook
// (« panique, pousser un PUT vide ») et dans les tests.
//
// La nouvelle version sera Version()+1.
func (s *Set) Reset() {
	cur := s.cur.Load()
	s.cur.Store(&snapshot{version: cur.version + 1, byIP: map[netip.Addr]Entry{}})
}

// Errors sentinelles. Le caller (admin handler) peut errors.Is pour
// renvoyer le bon code HTTP.
var (
	ErrStaleVersion   = errors.New("blocklist: stale version")
	ErrTooManyEntries = errors.New("blocklist: too many entries")
	ErrInvalidIP      = errors.New("blocklist: invalid IP")
)

// noopCounter : implémentation no-op pour les tests sans Registry.
type noopCounter struct{}

func (noopCounter) Inc()          {}
func (noopCounter) Add(_ uint64)  {}
func (noopCounter) Value() uint64 { return 0 }
