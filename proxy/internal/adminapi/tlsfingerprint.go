package adminapi

import (
	"encoding/json"
	"net/http"

	"anti-ddos/proxy/mitigations/tlsfingerprint"
)

// tlsFingerprintRule : format JSON aligné avec
// control/src/mitigations/tlsfingerprint.ts et
// configs/schemas/tls-fingerprint.schema.json.
type tlsFingerprintRule struct {
	ID      string                   `json:"id"`
	Enabled bool                     `json:"enabled"`
	OnError string                   `json:"on_error"`
	Params  tlsFingerprintRuleParams `json:"params"`
	Reason  string                   `json:"reason,omitempty"`
	Notes   string                   `json:"notes,omitempty"`
}

type tlsFingerprintRuleParams struct {
	BlockedJA3 []string `json:"blocked_ja3"`
	BlockedJA4 []string `json:"blocked_ja4"`
}

type tlsFingerprintPayload struct {
	Rev   int                  `json:"rev"`
	Rules []tlsFingerprintRule `json:"rules"`
}

func tlsFingerprintHandler(lim *tlsfingerprint.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg := lim.Config()
			ja3 := append([]string(nil), cfg.BlockedJA3...)
			ja4 := append([]string(nil), cfg.BlockedJA4...)
			rule := tlsFingerprintRule{
				ID:      "tls-fingerprint",
				Enabled: cfg.Enabled,
				OnError: cfg.OnError,
				Params: tlsFingerprintRuleParams{
					BlockedJA3: ja3,
					BlockedJA4: ja4,
				},
			}
			writeJSON(w, http.StatusOK, tlsFingerprintPayload{Rev: 0, Rules: []tlsFingerprintRule{rule}})
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
			var payload tlsFingerprintPayload
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error":   "invalid_body",
					"details": err.Error(),
				})
				return
			}
			var target *tlsFingerprintRule
			for i := range payload.Rules {
				if payload.Rules[i].ID == "tls-fingerprint" {
					target = &payload.Rules[i]
					break
				}
			}
			if target == nil {
				writeJSON(w, http.StatusOK, map[string]string{"status": "noop"})
				return
			}
			newCfg := tlsfingerprint.Config{
				Enabled:    target.Enabled,
				BlockedJA3: target.Params.BlockedJA3,
				BlockedJA4: target.Params.BlockedJA4,
				OnError:    target.OnError,
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
