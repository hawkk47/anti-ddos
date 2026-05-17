// Package metrics fournit une interface minimale d'observabilité pour
// le data plane. Implémentation in-memory thread-safe par défaut.
//
// L'export Prometheus arrivera via un adapter dans un module séparé.
// Garder cette interface stable est crucial : tous les middlewares de
// mitigation l'utilisent.
package metrics

import (
	"sync"
	"sync/atomic"
)

// Counter : compteur monotone.
type Counter interface {
	Inc()
	Add(delta uint64)
	Value() uint64
}

// Histogram : observations de durée (en secondes).
type Histogram interface {
	Observe(seconds float64)
	Count() uint64
	Sum() float64
}

// Registry : factory de métriques. Les noms doivent être stables
// (ils deviennent des noms Prometheus). Récupérer une métrique 2x avec
// le même nom retourne la même instance.
type Registry interface {
	Counter(name string) Counter
	Histogram(name string) Histogram
}

// CounterSnapshot : vue immuable d'un compteur à l'instant t.
type CounterSnapshot struct {
	Name  string
	Value uint64
}

// HistogramSnapshot : vue immuable d'un histogramme à l'instant t.
type HistogramSnapshot struct {
	Name  string
	Count uint64
	Sum   float64
}

// Snapshotter : Registry capable de produire un snapshot atomique de
// l'ensemble de ses métriques. Utilisé par l'exporter Prometheus.
//
// L'in-memory Registry l'implémente ; d'autres backends peuvent
// l'omettre (l'exporter se débrouillera).
type Snapshotter interface {
	Snapshot() ([]CounterSnapshot, []HistogramSnapshot)
}

// ----------------------------------------------------------------------
// Implémentation in-memory.
// ----------------------------------------------------------------------

// NewInMemory retourne une Registry thread-safe pour les tests et le
// dev. Aucune persistence, aucune surface réseau.
func NewInMemory() Registry {
	return &memReg{
		counters:   make(map[string]*memCounter),
		histograms: make(map[string]*memHistogram),
	}
}

type memReg struct {
	mu         sync.Mutex
	counters   map[string]*memCounter
	histograms map[string]*memHistogram
}

func (r *memReg) Counter(name string) Counter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.counters[name]; ok {
		return c
	}
	c := &memCounter{}
	r.counters[name] = c
	return c
}

func (r *memReg) Histogram(name string) Histogram {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.histograms[name]; ok {
		return h
	}
	h := &memHistogram{}
	r.histograms[name] = h
	return h
}

type memCounter struct{ v atomic.Uint64 }

func (c *memCounter) Inc()             { c.v.Add(1) }
func (c *memCounter) Add(delta uint64) { c.v.Add(delta) }
func (c *memCounter) Value() uint64    { return c.v.Load() }

type memHistogram struct {
	mu    sync.Mutex
	count uint64
	sum   float64
}

func (h *memHistogram) Observe(seconds float64) {
	h.mu.Lock()
	h.count++
	h.sum += seconds
	h.mu.Unlock()
}

func (h *memHistogram) Count() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.count
}

func (h *memHistogram) Sum() float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sum
}

// Snapshot retourne une vue cohérente de toutes les métriques. Les
// listes sont triées par nom pour un export déterministe (utile en
// test et pour le scrape Prometheus).
func (r *memReg) Snapshot() ([]CounterSnapshot, []HistogramSnapshot) {
	r.mu.Lock()
	cs := make([]CounterSnapshot, 0, len(r.counters))
	for name, c := range r.counters {
		cs = append(cs, CounterSnapshot{Name: name, Value: c.Value()})
	}
	hs := make([]HistogramSnapshot, 0, len(r.histograms))
	for name, h := range r.histograms {
		hs = append(hs, HistogramSnapshot{Name: name, Count: h.Count(), Sum: h.Sum()})
	}
	r.mu.Unlock()
	sortCounters(cs)
	sortHistograms(hs)
	return cs, hs
}

func sortCounters(s []CounterSnapshot) {
	// Tri par insertion (n petit, alloc-free).
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1].Name > s[j].Name; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func sortHistograms(s []HistogramSnapshot) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1].Name > s[j].Name; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
