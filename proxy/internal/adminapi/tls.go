package adminapi

import (
	"encoding/json"
	"net/http"

	"anti-ddos/proxy/mitigations/tlsreneg"
)

// tlsRule : format JSON aligné avec control/src/mitigations/tls.ts
// et configs/schemas/tls.schema.json.
type tlsRule struct {
	ID      string        `json:"id"`
	Enabled bool          `json:"enabled"`
	OnError string        `json:"on_error"`
	Params  tlsRuleParams `json:"params"`
	Reason  string        `json:"reason,omitempty"`
	Notes   string        `json:"notes,omitempty"`
}

type tlsRuleParams struct {
	MinTLSVersion            string  `json:"min_tls_version"`
	HandshakesPerSecondPerIP float64 `json:"handshakes_per_second_per_ip"`
	Burst                    int     `json:"burst"`
}

type tlsPayload struct {
	Rev   int       `json:"rev"`
	Rules []tlsRule `json:"rules"`
}

func tlsHandler(lim *tlsreneg.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg := lim.Config()
			rule := tlsRule{
				ID:      "tls-renegotiation-flood",
				Enabled: cfg.Enabled,
				OnError: cfg.OnError,
				Params: tlsRuleParams{
					MinTLSVersion:            cfg.MinTLSVersion,
					HandshakesPerSecondPerIP: cfg.HandshakesPerSecondPerIP,
					Burst:                    cfg.Burst,
				},
			}
			writeJSON(w, http.StatusOK, tlsPayload{Rev: 0, Rules: []tlsRule{rule}})
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
			var payload tlsPayload
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error":   "invalid_body",
					"details": err.Error(),
				})
				return
			}
			var target *tlsRule
			for i := range payload.Rules {
				if payload.Rules[i].ID == "tls-renegotiation-flood" {
					target = &payload.Rules[i]
					break
				}
			}
			if target == nil {
				writeJSON(w, http.StatusOK, map[string]string{"status": "noop"})
				return
			}
			newCfg := tlsreneg.Config{
				Enabled:                  target.Enabled,
				MinTLSVersion:            target.Params.MinTLSVersion,
				HandshakesPerSecondPerIP: target.Params.HandshakesPerSecondPerIP,
				Burst:                    target.Params.Burst,
				OnError:                  target.OnError,
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
