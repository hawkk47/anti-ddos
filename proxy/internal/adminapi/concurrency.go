package adminapi

import (
	"encoding/json"
	"net/http"

	"anti-ddos/proxy/mitigations/concurrency"
)

// concurrencyRule : format JSON aligné avec
// control/src/mitigations/concurrency.ts et
// configs/schemas/concurrency.schema.json.
type concurrencyRule struct {
	ID      string                `json:"id"`
	Enabled bool                  `json:"enabled"`
	OnError string                `json:"on_error"`
	Params  concurrencyRuleParams `json:"params"`
	Reason  string                `json:"reason,omitempty"`
	Notes   string                `json:"notes,omitempty"`
}

type concurrencyRuleParams struct {
	MaxInFlight int `json:"max_in_flight"`
}

type concurrencyPayload struct {
	Rev   int               `json:"rev"`
	Rules []concurrencyRule `json:"rules"`
}

func concurrencyHandler(lim *concurrency.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg := lim.Config()
			rule := concurrencyRule{
				ID:      "concurrency-cap",
				Enabled: cfg.Enabled,
				OnError: cfg.OnError,
				Params:  concurrencyRuleParams{MaxInFlight: cfg.MaxInFlight},
			}
			writeJSON(w, http.StatusOK, concurrencyPayload{Rev: 0, Rules: []concurrencyRule{rule}})
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
			var payload concurrencyPayload
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error":   "invalid_body",
					"details": err.Error(),
				})
				return
			}
			var target *concurrencyRule
			for i := range payload.Rules {
				if payload.Rules[i].ID == "concurrency-cap" {
					target = &payload.Rules[i]
					break
				}
			}
			if target == nil {
				writeJSON(w, http.StatusOK, map[string]string{"status": "noop"})
				return
			}
			newCfg := concurrency.Config{
				Enabled:     target.Enabled,
				MaxInFlight: target.Params.MaxInFlight,
				OnError:     target.OnError,
			}
			if err := lim.Update(newCfg); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error":   "invalid_config",
					"details": err.Error(),
				})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"status": "applied",
				"rev":    payload.Rev,
			})
		default:
			w.Header().Set("Allow", "GET, PUT")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}
