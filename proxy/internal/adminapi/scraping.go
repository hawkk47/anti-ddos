package adminapi

import (
	"encoding/json"
	"net/http"

	"anti-ddos/proxy/mitigations/scraping"
)

// scrapingRule : format JSON aligné avec control/src/mitigations/scraping.ts
// et configs/schemas/scraping.schema.json.
type scrapingRule struct {
	ID      string             `json:"id"`
	Enabled bool               `json:"enabled"`
	Action  string             `json:"action"`
	Params  scrapingRuleParams `json:"params"`
	Reason  string             `json:"reason,omitempty"`
	Notes   string             `json:"notes,omitempty"`
}

type scrapingRuleParams struct {
	UserAgentDeny         []string `json:"user_agent_deny"`
	RequireAcceptLanguage bool     `json:"require_accept_language"`
	RequireAcceptEncoding bool     `json:"require_accept_encoding"`
}

type scrapingPayload struct {
	Rev   int            `json:"rev"`
	Rules []scrapingRule `json:"rules"`
}

func scrapingHandler(lim *scraping.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg := lim.Config()
			rule := scrapingRule{
				ID:      "scraping",
				Enabled: cfg.Enabled,
				Action:  cfg.Action,
				Params: scrapingRuleParams{
					UserAgentDeny:         cfg.UserAgentDeny,
					RequireAcceptLanguage: cfg.RequireAcceptLanguage,
					RequireAcceptEncoding: cfg.RequireAcceptEncoding,
				},
			}
			writeJSON(w, http.StatusOK, scrapingPayload{Rev: 0, Rules: []scrapingRule{rule}})
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
			var payload scrapingPayload
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error":   "invalid_body",
					"details": err.Error(),
				})
				return
			}
			var target *scrapingRule
			for i := range payload.Rules {
				if payload.Rules[i].ID == "scraping" {
					target = &payload.Rules[i]
					break
				}
			}
			if target == nil {
				writeJSON(w, http.StatusOK, map[string]string{"status": "noop"})
				return
			}
			newCfg := scraping.Config{
				Enabled:               target.Enabled,
				UserAgentDeny:         target.Params.UserAgentDeny,
				RequireAcceptLanguage: target.Params.RequireAcceptLanguage,
				RequireAcceptEncoding: target.Params.RequireAcceptEncoding,
				Action:                target.Action,
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
