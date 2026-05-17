package adminapi

import (
	"encoding/json"
	"net/http"
	"time"

	"anti-ddos/proxy/mitigations/http2reset"
)

// http2Rule : format JSON aligné avec control/src/mitigations/http2.ts
// et configs/schemas/http2.schema.json.
type http2Rule struct {
	ID      string          `json:"id"`
	Enabled bool            `json:"enabled"`
	OnError string          `json:"on_error"`
	Params  http2RuleParams `json:"params"`
	Reason  string          `json:"reason,omitempty"`
	Notes   string          `json:"notes,omitempty"`
}

type http2RuleParams struct {
	MaxResetsPerConn     int    `json:"max_resets_per_conn"`
	WindowMs             int    `json:"window_ms"`
	MaxConcurrentStreams uint32 `json:"max_concurrent_streams"`
}

type http2Payload struct {
	Rev   int         `json:"rev"`
	Rules []http2Rule `json:"rules"`
}

func http2Handler(lim *http2reset.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg := lim.Config()
			rule := http2Rule{
				ID:      "http2-rapid-reset",
				Enabled: cfg.Enabled,
				OnError: cfg.OnError,
				Params: http2RuleParams{
					MaxResetsPerConn:     cfg.MaxResetsPerConn,
					WindowMs:             int(cfg.Window / time.Millisecond),
					MaxConcurrentStreams: cfg.MaxConcurrentStreams,
				},
			}
			writeJSON(w, http.StatusOK, http2Payload{Rev: 0, Rules: []http2Rule{rule}})
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
			var payload http2Payload
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error":   "invalid_body",
					"details": err.Error(),
				})
				return
			}
			var target *http2Rule
			for i := range payload.Rules {
				if payload.Rules[i].ID == "http2-rapid-reset" {
					target = &payload.Rules[i]
					break
				}
			}
			if target == nil {
				writeJSON(w, http.StatusOK, map[string]string{"status": "noop"})
				return
			}
			newCfg := http2reset.Config{
				Enabled:              target.Enabled,
				MaxResetsPerConn:     target.Params.MaxResetsPerConn,
				Window:               time.Duration(target.Params.WindowMs) * time.Millisecond,
				MaxConcurrentStreams: target.Params.MaxConcurrentStreams,
				OnError:              target.OnError,
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
