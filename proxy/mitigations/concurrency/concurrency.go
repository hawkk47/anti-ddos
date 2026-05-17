// Package concurrency implémente la mitigation `concurrency-cap`
// (a.k.a. load shedding / backpressure).
//
// Vecteur. Une rafale légitime ou hostile (slashdot effect, scrape
// agressif, micro-DDoS L7) sature le pool de goroutines + la mémoire
// résident en handler. Même sans dépasser un quota par-IP (httpflood)
// ni un cap par-conn (slowloris), le simple nombre de requêtes
// *concurrentes* en cours de traitement peut écrouler l'upstream
// (saturation CPU, pool DB épuisé, file d'attente runtime qui gonfle).
//
// Cette mitigation plafonne le nombre de requêtes simultanées dans la
// chaîne handler. Une 12ᵉ requête arrivant alors que le quota est 10
// reçoit immédiatement HTTP 503 + Retry-After plutôt que d'attendre.
// "Fail fast" plutôt que "tomber doucement" : meilleure UX, moins de
// connexions zombies, meilleure observabilité d'une surcharge.
//
// Distinct des autres mitigations :
//   - slowloris : cap *par-IP* sur les connexions TCP simultanées.
//   - httpflood : token-bucket par-IP sur le débit de requêtes.
//   - concurrency : cap *global* sur l'in-flight handler, indépendant
//     de la source. C'est le dernier filet anti-saturation.
//
// Cap global vs per-route : V1 ne supporte qu'un cap global. La portée
// per-route (e.g. /api/expensive séparément) peut être ajoutée plus
// tard sans casser l'API publique.
//
// Hot-reload : la sémaphore est swappée atomiquement. Les requêtes
// déjà en vol sur l'ancien canal terminent normalement (la goroutine
// défère son `<-old`), les nouvelles utilisent le nouveau quota. Pas
// de drop pendant le reload.
//
// Mode `on_error` : non utilisé (la mitigation n'a pas de chemin
// d'erreur autre que "config invalide" qui est rejetée à Update).
// Le champ existe pour symétrie avec les autres mitigations.
//
// Pure-Go, cross-platform, sans allocation sur le hot path
// (`chan struct{}` + atomic pointer).
package concurrency

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

// Config décrit la règle concurrency-cap.
type Config struct {
	Enabled     bool   `json:"enabled"`
	MaxInFlight int    `json:"max_in_flight"`
	OnError     string `json:"on_error"` // "allow" | "deny" (réservé, non lu)
}

// Validate retourne une erreur si la config est inutilisable.
func (c Config) Validate() error {
	if c.Enabled {
		if c.MaxInFlight < 1 {
			return fmt.Errorf("max_in_flight must be >= 1 when enabled, got %d", c.MaxInFlight)
		}
		if c.MaxInFlight > 1_000_000 {
			return fmt.Errorf("max_in_flight %d > 1_000_000 (sanity cap)", c.MaxInFlight)
		}
	}
	switch c.OnError {
	case "", "allow", "deny":
	default:
		return fmt.Errorf("on_error must be allow|deny, got %q", c.OnError)
	}
	return nil
}

// Decision encode la sortie d'Evaluate.
type Decision int

const (
	// Allow : la requête a obtenu un slot.
	Allow Decision = iota
	// Deny : le quota est plein, la requête doit recevoir 503.
	Deny
)

// Limiter applique le cap global d'in-flight. Sûr en concurrence,
// hot-reload via atomic.Pointer.
//
// La sémaphore est implémentée par un canal bufferisé : insérer = prendre
// un slot, recevoir = libérer. La taille du canal est la capacité.
type Limiter struct {
	cfg atomic.Pointer[Config]
	// sem est un *chan struct{} (pointeur vers canal). Le pointeur lui
	// même est swappable atomiquement, le canal sous-jacent n'est jamais
	// muté ; un reload alloue un nouveau canal et publie son adresse.
	sem     atomic.Pointer[chan struct{}]
	metrics struct {
		evaluated metrics.Counter
		blocked   metrics.Counter
		errors    metrics.Counter
		duration  metrics.Histogram
	}
	now func() time.Time
}

// New construit un Limiter et enregistre les métriques.
func New(cfg Config, reg metrics.Registry) (*Limiter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("concurrency: invalid initial config: %w", err)
	}
	l := &Limiter{now: time.Now}
	c := cfg
	l.cfg.Store(&c)
	l.installSemaphore(cfg)
	l.metrics.evaluated = reg.Counter("mitigation_concurrency_cap_evaluated_total")
	l.metrics.blocked = reg.Counter("mitigation_concurrency_cap_blocked_total")
	l.metrics.errors = reg.Counter("mitigation_concurrency_cap_errors_total")
	l.metrics.duration = reg.Histogram("mitigation_concurrency_cap_duration_seconds")
	return l, nil
}

// installSemaphore alloue (ou retire) le canal selon la config.
func (l *Limiter) installSemaphore(cfg Config) {
	if !cfg.Enabled || cfg.MaxInFlight <= 0 {
		l.sem.Store(nil)
		return
	}
	ch := make(chan struct{}, cfg.MaxInFlight)
	l.sem.Store(&ch)
}

// Update remplace atomiquement la config et la sémaphore. Sur erreur
// de validation, l'ancienne config + l'ancienne sémaphore restent.
// Les requêtes en vol sur l'ancienne sémaphore terminent normalement
// (elles ont capturé le pointeur au moment de l'acquisition).
func (l *Limiter) Update(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		l.metrics.errors.Inc()
		return fmt.Errorf("concurrency: invalid config: %w", err)
	}
	c := cfg
	l.cfg.Store(&c)
	l.installSemaphore(cfg)
	return nil
}

// Config retourne une copie de la config courante.
func (l *Limiter) Config() Config { return *l.cfg.Load() }

// Metrics expose les compteurs pour debug/admin.
func (l *Limiter) Metrics() (evaluated, blocked, errs uint64) {
	return l.metrics.evaluated.Value(), l.metrics.blocked.Value(), l.metrics.errors.Value()
}

// InFlight retourne le nombre approximatif de requêtes actuellement en
// vol (= len du canal). Best-effort, pas atomique vis-à-vis d'un reload
// concurrent. Utile pour les tests et l'observabilité bas niveau.
func (l *Limiter) InFlight() int {
	sem := l.sem.Load()
	if sem == nil {
		return 0
	}
	return len(*sem)
}

// tryAcquire tente de prendre un slot. Retourne (slot, true) si le
// slot a été pris (à libérer via release), ou (nil, false) si le
// quota est plein. Pass-through si désactivée.
//
// Le pointeur de canal capturé est retourné pour que release() utilise
// le MÊME canal — même si un Update concurrent a swappé entre-temps.
// C'est ce qui garantit qu'un reload ne drop pas de requête en vol.
func (l *Limiter) tryAcquire() (slot *chan struct{}, acquired bool) {
	cfg := l.cfg.Load()
	if !cfg.Enabled {
		return nil, true // pass-through
	}
	l.metrics.evaluated.Inc()
	sem := l.sem.Load()
	if sem == nil {
		return nil, true // pass-through (no quota)
	}
	select {
	case *sem <- struct{}{}:
		return sem, true
	default:
		l.metrics.blocked.Inc()
		return nil, false
	}
}

// release rend un slot. No-op si slot est nil.
func (l *Limiter) release(slot *chan struct{}) {
	if slot == nil {
		return
	}
	<-*slot
}

// Middleware retourne un http.Handler qui filtre les requêtes via la
// sémaphore. Sur Deny, répond 503 + Retry-After=1.
//
// La latence ajoutée par la mitigation (acquisition + release) est
// observée dans `mitigation_concurrency_cap_duration_seconds`. Sur
// pass-through (disabled), 0 observation.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := l.now()
		slot, ok := l.tryAcquire()
		l.metrics.duration.Observe(l.now().Sub(start).Seconds())
		if !ok {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "service overloaded", http.StatusServiceUnavailable)
			return
		}
		defer l.release(slot)
		next.ServeHTTP(w, r)
	})
}
