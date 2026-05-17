package adminapi

import (
	"encoding/json"
	"net/http"
	"time"

	"anti-ddos/proxy/mitigations/slowpost"
)

// bodiesRule : format JSON aligné avec
// control/src/mitigations/bodies.ts et
// configs/schemas/bodies.schema.json.
type bodiesRule struct {
	ID      string           `json:"id"`
	Enabled bool             `json:"enabled"`
	OnError string           `json:"on_error"`
	Params  bodiesRuleParams `json:"params"`
	Reason  string           `json:"reason,omitempty"`
	Notes   string           `json:"notes,omitempty"`
}

type bodiesRuleParams struct {
	MaxBodyBytes      int64 `json:"max_body_bytes"`
	MinBytesPerSecond int   `json:"min_bytes_per_second"`
	// Grace en millisecondes — JSON ne porte pas de durée native.
	GracePeriodMs int `json:"grace_period_ms"`
}

type bodiesPayload struct {
	Rev   int          `json:"rev"`
	Rules []bodiesRule `json:"rules"`
}

func bodiesHandler(lim *slowpost.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg := lim.Config()
			rule := bodiesRule{
				ID:      "slow-post",
				Enabled: cfg.Enabled,
				OnError: cfg.OnError,
				Params: bodiesRuleParams{
					MaxBodyBytes:      cfg.MaxBodyBytes,
					MinBytesPerSecond: cfg.MinBytesPerSecond,
					GracePeriodMs:     int(cfg.GracePeriod / time.Millisecond),
				},
			}
			writeJSON(w, http.StatusOK, bodiesPayload{Rev: 0, Rules: []bodiesRule{rule}})
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
			var payload bodiesPayload
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error":   "invalid_body",
					"details": err.Error(),
				})
				return
			}
			var target *bodiesRule
			for i := range payload.Rules {
				if payload.Rules[i].ID == "slow-post" {
					target = &payload.Rules[i]
					break
				}
			}
			if target == nil {
				writeJSON(w, http.StatusOK, map[string]string{"status": "noop"})
				return
			}
			newCfg := slowpost.Config{
				Enabled:           target.Enabled,
				MaxBodyBytes:      target.Params.MaxBodyBytes,
				MinBytesPerSecond: target.Params.MinBytesPerSecond,
				GracePeriod:       time.Duration(target.Params.GracePeriodMs) * time.Millisecond,
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
