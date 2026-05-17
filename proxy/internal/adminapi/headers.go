package adminapi

import (
	"encoding/json"
	"net/http"

	"anti-ddos/proxy/mitigations/largeheader"
)

// headersRule : format JSON aligné avec
// control/src/mitigations/headers.ts et
// configs/schemas/headers.schema.json.
type headersRule struct {
	ID      string            `json:"id"`
	Enabled bool              `json:"enabled"`
	OnError string            `json:"on_error"`
	Params  headersRuleParams `json:"params"`
	Reason  string            `json:"reason,omitempty"`
	Notes   string            `json:"notes,omitempty"`
}

type headersRuleParams struct {
	MaxHeaderCount int `json:"max_header_count"`
	MaxValueBytes  int `json:"max_value_bytes"`
}

type headersPayload struct {
	Rev   int           `json:"rev"`
	Rules []headersRule `json:"rules"`
}

func headersHandler(lim *largeheader.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg := lim.Config()
			rule := headersRule{
				ID:      "large-header",
				Enabled: cfg.Enabled,
				OnError: cfg.OnError,
				Params: headersRuleParams{
					MaxHeaderCount: cfg.MaxHeaderCount,
					MaxValueBytes:  cfg.MaxValueBytes,
				},
			}
			writeJSON(w, http.StatusOK, headersPayload{Rev: 0, Rules: []headersRule{rule}})
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
			var payload headersPayload
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error":   "invalid_body",
					"details": err.Error(),
				})
				return
			}
			var target *headersRule
			for i := range payload.Rules {
				if payload.Rules[i].ID == "large-header" {
					target = &payload.Rules[i]
					break
				}
			}
			if target == nil {
				writeJSON(w, http.StatusOK, map[string]string{"status": "noop"})
				return
			}
			newCfg := largeheader.Config{
				Enabled:        target.Enabled,
				MaxHeaderCount: target.Params.MaxHeaderCount,
				MaxValueBytes:  target.Params.MaxValueBytes,
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
