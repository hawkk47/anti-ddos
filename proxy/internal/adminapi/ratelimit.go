package adminapi

import (
	"encoding/json"
	"net/http"

	"anti-ddos/proxy/mitigations/httpflood"
)

// ratelimitRule : format JSON aligné avec
// control/src/mitigations/ratelimit.ts et
// configs/schemas/ratelimit.schema.json.
type ratelimitRule struct {
	ID      string              `json:"id"`
	Enabled bool                `json:"enabled"`
	OnError string              `json:"on_error"`
	Params  ratelimitRuleParams `json:"params"`
	Reason  string              `json:"reason,omitempty"`
	Notes   string              `json:"notes,omitempty"`
}

type ratelimitRuleParams struct {
	RequestsPerSecond float64 `json:"requests_per_second"`
	Burst             int     `json:"burst"`
}

type ratelimitPayload struct {
	Rev   int             `json:"rev"`
	Rules []ratelimitRule `json:"rules"`
}

func ratelimitHandler(lim *httpflood.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg := lim.Config()
			rule := ratelimitRule{
				ID:      "http-flood-l7",
				Enabled: cfg.Enabled,
				OnError: cfg.OnError,
				Params: ratelimitRuleParams{
					RequestsPerSecond: cfg.RequestsPerSecond,
					Burst:             cfg.Burst,
				},
			}
			writeJSON(w, http.StatusOK, ratelimitPayload{Rev: 0, Rules: []ratelimitRule{rule}})
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
			var payload ratelimitPayload
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error":   "invalid_body",
					"details": err.Error(),
				})
				return
			}
			var target *ratelimitRule
			for i := range payload.Rules {
				if payload.Rules[i].ID == "http-flood-l7" {
					target = &payload.Rules[i]
					break
				}
			}
			if target == nil {
				writeJSON(w, http.StatusOK, map[string]string{"status": "noop"})
				return
			}
			newCfg := httpflood.Config{
				Enabled:           target.Enabled,
				RequestsPerSecond: target.Params.RequestsPerSecond,
				Burst:             target.Params.Burst,
				OnError:           target.OnError,
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
