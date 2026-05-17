package adminapi

import (
	"encoding/json"
	"net/http"

	"anti-ddos/proxy/mitigations/hashflood"
)

// hashFloodRule : format JSON aligné avec control/src/mitigations/hashflood.ts
// et configs/schemas/hashflood.schema.json.
type hashFloodRule struct {
	ID      string              `json:"id"`
	Enabled bool                `json:"enabled"`
	OnError string              `json:"on_error"`
	Params  hashFloodRuleParams `json:"params"`
	Reason  string              `json:"reason,omitempty"`
	Notes   string              `json:"notes,omitempty"`
}

type hashFloodRuleParams struct {
	MaxQueryParams int `json:"max_query_params"`
}

type hashFloodPayload struct {
	Rev   int             `json:"rev"`
	Rules []hashFloodRule `json:"rules"`
}

func hashFloodHandler(lim *hashflood.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg := lim.Config()
			rule := hashFloodRule{
				ID:      "hash-flood",
				Enabled: cfg.Enabled,
				OnError: cfg.OnError,
				Params: hashFloodRuleParams{
					MaxQueryParams: cfg.MaxQueryParams,
				},
			}
			writeJSON(w, http.StatusOK, hashFloodPayload{Rev: 0, Rules: []hashFloodRule{rule}})
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
			var payload hashFloodPayload
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error":   "invalid_body",
					"details": err.Error(),
				})
				return
			}
			var target *hashFloodRule
			for i := range payload.Rules {
				if payload.Rules[i].ID == "hash-flood" {
					target = &payload.Rules[i]
					break
				}
			}
			if target == nil {
				writeJSON(w, http.StatusOK, map[string]string{"status": "noop"})
				return
			}
			newCfg := hashflood.Config{
				Enabled:        target.Enabled,
				MaxQueryParams: target.Params.MaxQueryParams,
				OnError:        target.OnError,
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
