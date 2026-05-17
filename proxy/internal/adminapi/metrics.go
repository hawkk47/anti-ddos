package adminapi

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"anti-ddos/proxy/internal/metrics"
)

// metricsHandler expose les métriques au format Prometheus text
// exposition (0.0.4). Format minimal :
//
//	# TYPE <name> counter|histogram_sum|histogram_count
//	<name> <value>
//
// On reste volontairement simple (pas de buckets, pas de labels) pour
// le MVP. Une future ADR décidera du backend cible (Prom natif, OTLP,
// VictoriaMetrics, etc.).
//
// Les noms Prometheus doivent respecter [a-zA-Z_:][a-zA-Z0-9_:]*. Les
// noms internes utilisent "." comme séparateur (ex:
// "slowloris.evaluated.total") ; on les translittère en "_" ici.
func metricsHandler(reg metrics.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		snap, ok := reg.(metrics.Snapshotter)
		if !ok {
			http.Error(w, "metrics backend does not support snapshot", http.StatusNotImplemented)
			return
		}
		counters, histograms := snap.Snapshot()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		writePromText(w, counters, histograms)
	}
}

func writePromText(w io.Writer, counters []metrics.CounterSnapshot, histograms []metrics.HistogramSnapshot) {
	for _, c := range counters {
		name := promName(c.Name)
		fmt.Fprintf(w, "# TYPE %s counter\n%s %d\n", name, name, c.Value)
	}
	for _, h := range histograms {
		// On expose count + sum (équivalent summary minimal sans
		// quantiles). Prom autorise _count/_sum sans buckets pour
		// un summary, mais pas pour un histogram. On déclare donc
		// type "summary".
		base := promName(h.Name)
		fmt.Fprintf(w, "# TYPE %s summary\n", base)
		fmt.Fprintf(w, "%s_count %d\n", base, h.Count)
		fmt.Fprintf(w, "%s_sum %g\n", base, h.Sum)
	}
}

// promName remplace tout caractère non conforme par "_".
func promName(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i, r := range s {
		valid := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || r == ':'
		if i > 0 {
			valid = valid || (r >= '0' && r <= '9')
		}
		if valid {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
