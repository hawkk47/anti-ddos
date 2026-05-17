package adminapi

import (
	"encoding/json"
	"net/http"

	"anti-ddos/proxy/mitigations/rangeamp"
)

// rangeAmpRule : format JSON aligné avec control/src/mitigations/rangeamp.ts
// et configs/schemas/rangeamp.schema.json.
type rangeAmpRule struct {
	ID      string             `json:"id"`
	Enabled bool               `json:"enabled"`
	OnError string             `json:"on_error"`
	Params  rangeAmpRuleParams `json:"params"`
	Reason  string             `json:"reason,omitempty"`
	Notes   string             `json:"notes,omitempty"`
}

type rangeAmpRuleParams struct {
	MaxRanges int `json:"max_ranges"`
}

type rangeAmpPayload struct {
	Rev   int            `json:"rev"`
	Rules []rangeAmpRule `json:"rules"`
}

func rangeAmpHandler(lim *rangeamp.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg := lim.Config()
			rule := rangeAmpRule{
				ID:      "range-amp",
				Enabled: cfg.Enabled,
				OnError: cfg.OnError,
				Params: rangeAmpRuleParams{
					MaxRanges: cfg.MaxRanges,
				},
			}
			writeJSON(w, http.StatusOK, rangeAmpPayload{Rev: 0, Rules: []rangeAmpRule{rule}})
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
			var payload rangeAmpPayload
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error":   "invalid_body",
					"details": err.Error(),
				})
				return
			}
			var target *rangeAmpRule
			for i := range payload.Rules {
				if payload.Rules[i].ID == "range-amp" {
					target = &payload.Rules[i]
					break
				}
			}
			if target == nil {
				writeJSON(w, http.StatusOK, map[string]string{"status": "noop"})
				return
			}
			newCfg := rangeamp.Config{
				Enabled:   target.Enabled,
				MaxRanges: target.Params.MaxRanges,
				OnError:   target.OnError,
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
