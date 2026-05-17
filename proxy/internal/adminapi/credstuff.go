package adminapi

import (
	"encoding/json"
	"net/http"

	"anti-ddos/proxy/mitigations/credstuff"
)

// credStuffRule : format JSON aligné avec control/src/mitigations/credstuff.ts
// et configs/schemas/credstuff.schema.json.
type credStuffRule struct {
	ID      string              `json:"id"`
	Enabled bool                `json:"enabled"`
	Action  string              `json:"action"`
	Params  credStuffRuleParams `json:"params"`
	Reason  string              `json:"reason,omitempty"`
	Notes   string              `json:"notes,omitempty"`
}

type credStuffRuleParams struct {
	LoginPaths           []string `json:"login_paths"`
	Methods              []string `json:"methods,omitempty"`
	MaxAttemptsPerMinute int      `json:"max_attempts_per_minute"`
	BlocklistEnabled     bool     `json:"blocklist_enabled,omitempty"`
}

type credStuffPayload struct {
	Rev   int             `json:"rev"`
	Rules []credStuffRule `json:"rules"`
}

func credStuffHandler(lim *credstuff.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg := lim.Config()
			rule := credStuffRule{
				ID:      "credential-stuffing",
				Enabled: cfg.Enabled,
				Action:  cfg.Action,
				Params: credStuffRuleParams{
					LoginPaths:           cfg.LoginPaths,
					Methods:              cfg.Methods,
					MaxAttemptsPerMinute: cfg.MaxAttemptsPerMinute,
					BlocklistEnabled:     cfg.BlocklistEnabled,
				},
			}
			writeJSON(w, http.StatusOK, credStuffPayload{Rev: 0, Rules: []credStuffRule{rule}})
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
			var payload credStuffPayload
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error":   "invalid_body",
					"details": err.Error(),
				})
				return
			}
			var target *credStuffRule
			for i := range payload.Rules {
				if payload.Rules[i].ID == "credential-stuffing" {
					target = &payload.Rules[i]
					break
				}
			}
			if target == nil {
				writeJSON(w, http.StatusOK, map[string]string{"status": "noop"})
				return
			}
			newCfg := credstuff.Config{
				Enabled:              target.Enabled,
				LoginPaths:           target.Params.LoginPaths,
				Methods:              target.Params.Methods,
				MaxAttemptsPerMinute: target.Params.MaxAttemptsPerMinute,
				Action:               target.Action,
				BlocklistEnabled:     target.Params.BlocklistEnabled,
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
