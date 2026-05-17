package adminapi

import (
	"encoding/json"
	"net/http"

	"anti-ddos/proxy/mitigations/requesthygiene"
)

// requestHygieneRule : format JSON aligné avec
// control/src/mitigations/requesthygiene.ts et
// configs/schemas/request-hygiene.schema.json.
type requestHygieneRule struct {
	ID      string                   `json:"id"`
	Enabled bool                     `json:"enabled"`
	OnError string                   `json:"on_error"`
	Params  requestHygieneRuleParams `json:"params"`
	Reason  string                   `json:"reason,omitempty"`
	Notes   string                   `json:"notes,omitempty"`
}

type requestHygieneRuleParams struct {
	AllowedMethods  []string `json:"allowed_methods"`
	MaxURILength    int      `json:"max_uri_length"`
	RejectTECL      bool     `json:"reject_te_cl_conflict"`
	RejectDupCL     bool     `json:"reject_duplicate_content_length"`
	RejectBadTE     bool     `json:"reject_invalid_transfer_encoding"`
	RejectEmptyHost bool     `json:"reject_empty_host"`
}

type requestHygienePayload struct {
	Rev   int                  `json:"rev"`
	Rules []requestHygieneRule `json:"rules"`
}

func requestHygieneHandler(lim *requesthygiene.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg := lim.Config()
			methods := append([]string(nil), cfg.AllowedMethods...)
			rule := requestHygieneRule{
				ID:      "request-hygiene",
				Enabled: cfg.Enabled,
				OnError: cfg.OnError,
				Params: requestHygieneRuleParams{
					AllowedMethods:  methods,
					MaxURILength:    cfg.MaxURILength,
					RejectTECL:      cfg.RejectTECL,
					RejectDupCL:     cfg.RejectDupCL,
					RejectBadTE:     cfg.RejectBadTE,
					RejectEmptyHost: cfg.RejectEmptyHost,
				},
			}
			writeJSON(w, http.StatusOK, requestHygienePayload{Rev: 0, Rules: []requestHygieneRule{rule}})
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
			var payload requestHygienePayload
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error":   "invalid_body",
					"details": err.Error(),
				})
				return
			}
			var target *requestHygieneRule
			for i := range payload.Rules {
				if payload.Rules[i].ID == "request-hygiene" {
					target = &payload.Rules[i]
					break
				}
			}
			if target == nil {
				writeJSON(w, http.StatusOK, map[string]string{"status": "noop"})
				return
			}
			newCfg := requesthygiene.Config{
				Enabled:         target.Enabled,
				AllowedMethods:  target.Params.AllowedMethods,
				MaxURILength:    target.Params.MaxURILength,
				RejectTECL:      target.Params.RejectTECL,
				RejectDupCL:     target.Params.RejectDupCL,
				RejectBadTE:     target.Params.RejectBadTE,
				RejectEmptyHost: target.Params.RejectEmptyHost,
				OnError:         target.OnError,
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
