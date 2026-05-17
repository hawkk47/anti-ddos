// Handlers admin pour les mitigations L3/L4.
//
// Aligne le sch\u00e9ma JSON sur celui d\u00e9j\u00e0 utilis\u00e9 par le control plane
// (id/enabled/on_error/params/reason/notes) pour rester homog\u00e8ne avec
// les autres familles. Une famille = un seul `id`.
package adminapi

import (
	"encoding/json"
	"net/http"
	"time"

	"anti-ddos/proxy/mitigations/connflood"
	"anti-ddos/proxy/mitigations/geoblockl4"
	"anti-ddos/proxy/mitigations/handshakeguard"
	"anti-ddos/proxy/mitigations/ipreputation"
	"anti-ddos/proxy/mitigations/synflood"
)

// ---------- ip-reputation ----------

type ipReputationParams struct {
	Allowlist         []string `json:"allowlist"`
	AllowlistStrict   bool     `json:"allowlist_strict"`
	Blocklist         []string `json:"blocklist"`
	MaxDynamicEntries int      `json:"max_dynamic_entries"`
	DefaultBlockTTLMs int      `json:"default_block_ttl_ms"`
}

type ipReputationRule struct {
	ID      string             `json:"id"`
	Enabled bool               `json:"enabled"`
	OnError string             `json:"on_error"`
	Params  ipReputationParams `json:"params"`
	Reason  string             `json:"reason,omitempty"`
	Notes   string             `json:"notes,omitempty"`
}

type ipReputationPayload struct {
	Rev   int                `json:"rev"`
	Rules []ipReputationRule `json:"rules"`
}

func ipReputationHandler(lim *ipreputation.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg := lim.Config()
			writeJSON(w, http.StatusOK, ipReputationPayload{Rules: []ipReputationRule{{
				ID:      "ip-reputation",
				Enabled: cfg.Enabled,
				OnError: cfg.OnError,
				Params: ipReputationParams{
					Allowlist:         cfg.Allowlist,
					AllowlistStrict:   cfg.AllowlistStrict,
					Blocklist:         cfg.Blocklist,
					MaxDynamicEntries: cfg.MaxDynamicEntries,
					DefaultBlockTTLMs: int(cfg.DefaultBlockTTL / time.Millisecond),
				},
			}}})
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
			var p ipReputationPayload
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&p); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body", "details": err.Error()})
				return
			}
			target := findRule(p.Rules, "ip-reputation", func(r ipReputationRule) string { return r.ID })
			if target == nil {
				writeJSON(w, http.StatusOK, map[string]string{"status": "noop"})
				return
			}
			newCfg := ipreputation.Config{
				Enabled:           target.Enabled,
				Allowlist:         target.Params.Allowlist,
				AllowlistStrict:   target.Params.AllowlistStrict,
				Blocklist:         target.Params.Blocklist,
				MaxDynamicEntries: target.Params.MaxDynamicEntries,
				DefaultBlockTTL:   time.Duration(target.Params.DefaultBlockTTLMs) * time.Millisecond,
				OnError:           target.OnError,
			}
			if err := lim.Update(newCfg); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_config", "details": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"status": "applied", "rev": p.Rev})
		default:
			w.Header().Set("Allow", "GET, PUT")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

// ---------- conn-flood ----------

type connFloodParams struct {
	MaxConnsPerIP     int `json:"max_conns_per_ip"`
	MaxConnsPerSubnet int `json:"max_conns_per_subnet"`
}

type connFloodRule struct {
	ID      string          `json:"id"`
	Enabled bool            `json:"enabled"`
	OnError string          `json:"on_error"`
	Params  connFloodParams `json:"params"`
	Reason  string          `json:"reason,omitempty"`
	Notes   string          `json:"notes,omitempty"`
}
type connFloodPayload struct {
	Rev   int             `json:"rev"`
	Rules []connFloodRule `json:"rules"`
}

func connFloodHandler(lim *connflood.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg := lim.Config()
			writeJSON(w, http.StatusOK, connFloodPayload{Rules: []connFloodRule{{
				ID: "conn-flood", Enabled: cfg.Enabled, OnError: cfg.OnError,
				Params: connFloodParams{MaxConnsPerIP: cfg.MaxConnsPerIP, MaxConnsPerSubnet: cfg.MaxConnsPerSubnet},
			}}})
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
			var p connFloodPayload
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&p); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body", "details": err.Error()})
				return
			}
			target := findRule(p.Rules, "conn-flood", func(r connFloodRule) string { return r.ID })
			if target == nil {
				writeJSON(w, http.StatusOK, map[string]string{"status": "noop"})
				return
			}
			if err := lim.Update(connflood.Config{
				Enabled: target.Enabled, OnError: target.OnError,
				MaxConnsPerIP: target.Params.MaxConnsPerIP, MaxConnsPerSubnet: target.Params.MaxConnsPerSubnet,
			}); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_config", "details": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"status": "applied", "rev": p.Rev})
		default:
			w.Header().Set("Allow", "GET, PUT")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

// ---------- syn-flood ----------

type synFloodParams struct {
	AcceptsPerSecondPerIP     float64 `json:"accepts_per_second_per_ip"`
	BurstPerIP                int     `json:"burst_per_ip"`
	AcceptsPerSecondPerSubnet float64 `json:"accepts_per_second_per_subnet"`
	BurstPerSubnet            int     `json:"burst_per_subnet"`
	ReportTTLMs               int     `json:"report_ttl_ms"`
}
type synFloodRule struct {
	ID      string         `json:"id"`
	Enabled bool           `json:"enabled"`
	OnError string         `json:"on_error"`
	Params  synFloodParams `json:"params"`
	Reason  string         `json:"reason,omitempty"`
	Notes   string         `json:"notes,omitempty"`
}
type synFloodPayload struct {
	Rev   int            `json:"rev"`
	Rules []synFloodRule `json:"rules"`
}

func synFloodHandler(lim *synflood.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg := lim.Config()
			writeJSON(w, http.StatusOK, synFloodPayload{Rules: []synFloodRule{{
				ID: "syn-flood", Enabled: cfg.Enabled, OnError: cfg.OnError,
				Params: synFloodParams{
					AcceptsPerSecondPerIP:     cfg.AcceptsPerSecondPerIP,
					BurstPerIP:                cfg.BurstPerIP,
					AcceptsPerSecondPerSubnet: cfg.AcceptsPerSecondPerSubnet,
					BurstPerSubnet:            cfg.BurstPerSubnet,
					ReportTTLMs:               int(cfg.ReportTTL / time.Millisecond),
				},
			}}})
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
			var p synFloodPayload
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&p); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body", "details": err.Error()})
				return
			}
			target := findRule(p.Rules, "syn-flood", func(r synFloodRule) string { return r.ID })
			if target == nil {
				writeJSON(w, http.StatusOK, map[string]string{"status": "noop"})
				return
			}
			if err := lim.Update(synflood.Config{
				Enabled: target.Enabled, OnError: target.OnError,
				AcceptsPerSecondPerIP:     target.Params.AcceptsPerSecondPerIP,
				BurstPerIP:                target.Params.BurstPerIP,
				AcceptsPerSecondPerSubnet: target.Params.AcceptsPerSecondPerSubnet,
				BurstPerSubnet:            target.Params.BurstPerSubnet,
				ReportTTL:                 time.Duration(target.Params.ReportTTLMs) * time.Millisecond,
			}); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_config", "details": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"status": "applied", "rev": p.Rev})
		default:
			w.Header().Set("Allow", "GET, PUT")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

// ---------- handshake-guard ----------

type handshakeGuardParams struct {
	HandshakeWindowMs int `json:"handshake_window_ms"`
	AbandonThreshold  int `json:"abandon_threshold"`
	ObserveWindowMs   int `json:"observe_window_ms"`
	ReportTTLMs       int `json:"report_ttl_ms"`
}
type handshakeGuardRule struct {
	ID      string               `json:"id"`
	Enabled bool                 `json:"enabled"`
	OnError string               `json:"on_error"`
	Params  handshakeGuardParams `json:"params"`
	Reason  string               `json:"reason,omitempty"`
	Notes   string               `json:"notes,omitempty"`
}
type handshakeGuardPayload struct {
	Rev   int                  `json:"rev"`
	Rules []handshakeGuardRule `json:"rules"`
}

func handshakeGuardHandler(lim *handshakeguard.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg := lim.Config()
			writeJSON(w, http.StatusOK, handshakeGuardPayload{Rules: []handshakeGuardRule{{
				ID: "handshake-guard", Enabled: cfg.Enabled, OnError: cfg.OnError,
				Params: handshakeGuardParams{
					HandshakeWindowMs: int(cfg.HandshakeWindow / time.Millisecond),
					AbandonThreshold:  cfg.AbandonThreshold,
					ObserveWindowMs:   int(cfg.ObserveWindow / time.Millisecond),
					ReportTTLMs:       int(cfg.ReportTTL / time.Millisecond),
				},
			}}})
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
			var p handshakeGuardPayload
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&p); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body", "details": err.Error()})
				return
			}
			target := findRule(p.Rules, "handshake-guard", func(r handshakeGuardRule) string { return r.ID })
			if target == nil {
				writeJSON(w, http.StatusOK, map[string]string{"status": "noop"})
				return
			}
			if err := lim.Update(handshakeguard.Config{
				Enabled: target.Enabled, OnError: target.OnError,
				HandshakeWindow:  time.Duration(target.Params.HandshakeWindowMs) * time.Millisecond,
				AbandonThreshold: target.Params.AbandonThreshold,
				ObserveWindow:    time.Duration(target.Params.ObserveWindowMs) * time.Millisecond,
				ReportTTL:        time.Duration(target.Params.ReportTTLMs) * time.Millisecond,
			}); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_config", "details": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"status": "applied", "rev": p.Rev})
		default:
			w.Header().Set("Allow", "GET, PUT")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

// ---------- geoblock-l4 ----------

type geoBlockL4Params struct {
	Allow []string `json:"allow"`
	Block []string `json:"block"`
}
type geoBlockL4Rule struct {
	ID      string           `json:"id"`
	Enabled bool             `json:"enabled"`
	OnError string           `json:"on_error"`
	Params  geoBlockL4Params `json:"params"`
	Reason  string           `json:"reason,omitempty"`
	Notes   string           `json:"notes,omitempty"`
}
type geoBlockL4Payload struct {
	Rev   int              `json:"rev"`
	Rules []geoBlockL4Rule `json:"rules"`
}

func geoBlockL4Handler(lim *geoblockl4.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg := lim.Config()
			writeJSON(w, http.StatusOK, geoBlockL4Payload{Rules: []geoBlockL4Rule{{
				ID: "geoblock-l4", Enabled: cfg.Enabled, OnError: cfg.OnError,
				Params: geoBlockL4Params{Allow: cfg.Allow, Block: cfg.Block},
			}}})
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
			var p geoBlockL4Payload
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&p); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body", "details": err.Error()})
				return
			}
			target := findRule(p.Rules, "geoblock-l4", func(r geoBlockL4Rule) string { return r.ID })
			if target == nil {
				writeJSON(w, http.StatusOK, map[string]string{"status": "noop"})
				return
			}
			if err := lim.Update(geoblockl4.Config{
				Enabled: target.Enabled, OnError: target.OnError,
				Allow: target.Params.Allow, Block: target.Params.Block,
			}); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_config", "details": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"status": "applied", "rev": p.Rev})
		default:
			w.Header().Set("Allow", "GET, PUT")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

// findRule cherche la premi\u00e8re r\u00e8gle dont l'ID extrait par `id`
// correspond \u00e0 `want`.
func findRule[T any](rules []T, want string, id func(T) string) *T {
	for i := range rules {
		if id(rules[i]) == want {
			return &rules[i]
		}
	}
	return nil
}
