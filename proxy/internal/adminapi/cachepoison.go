package adminapi

import (
	"encoding/json"
	"net/http"

	"anti-ddos/proxy/mitigations/cachepoison"
)

// cachePoisonRule : format JSON aligné avec control/src/mitigations/cachepoison.ts
// et configs/schemas/cachepoison.schema.json.
type cachePoisonRule struct {
	ID      string                `json:"id"`
	Enabled bool                  `json:"enabled"`
	Action  string                `json:"action"`
	Params  cachePoisonRuleParams `json:"params"`
	Reason  string                `json:"reason,omitempty"`
	Notes   string                `json:"notes,omitempty"`
}

type cachePoisonRuleParams struct {
	Headers []string `json:"headers"`
}

type cachePoisonPayload struct {
	Rev   int               `json:"rev"`
	Rules []cachePoisonRule `json:"rules"`
}

func cachePoisonHandler(lim *cachepoison.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg := lim.Config()
			rule := cachePoisonRule{
				ID:      "cache-poison",
				Enabled: cfg.Enabled,
				Action:  cfg.Action,
				Params: cachePoisonRuleParams{
					Headers: cfg.Headers,
				},
			}
			writeJSON(w, http.StatusOK, cachePoisonPayload{Rev: 0, Rules: []cachePoisonRule{rule}})
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
			var payload cachePoisonPayload
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error":   "invalid_body",
					"details": err.Error(),
				})
				return
			}
			var target *cachePoisonRule
			for i := range payload.Rules {
				if payload.Rules[i].ID == "cache-poison" {
					target = &payload.Rules[i]
					break
				}
			}
			if target == nil {
				writeJSON(w, http.StatusOK, map[string]string{"status": "noop"})
				return
			}
			newCfg := cachepoison.Config{
				Enabled: target.Enabled,
				Headers: target.Params.Headers,
				Action:  target.Action,
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
