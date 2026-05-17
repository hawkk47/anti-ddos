// Package adminapi expose l'API admin du data plane (reload, snapshot
// config). Loopback-only par défaut : le listener doit binder
// 127.0.0.1 (cf. server.Config.AdminListenAddr).
//
// Aucune authentification dans le MVP : la confiance vient du bind
// loopback. Quand mTLS sera ajouté entre control et proxy (cf.
// AGENTS.md), il viendra ici via un middleware.
package adminapi

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"anti-ddos/proxy/internal/blocklist"
	"anti-ddos/proxy/internal/metrics"
	"anti-ddos/proxy/mitigations/cachepoison"
	"anti-ddos/proxy/mitigations/concurrency"
	"anti-ddos/proxy/mitigations/credstuff"
	"anti-ddos/proxy/mitigations/hashflood"
	"anti-ddos/proxy/mitigations/http2reset"
	"anti-ddos/proxy/mitigations/httpflood"
	"anti-ddos/proxy/mitigations/largeheader"
	"anti-ddos/proxy/mitigations/rangeamp"
	"anti-ddos/proxy/mitigations/requesthygiene"
	"anti-ddos/proxy/mitigations/scraping"
	"anti-ddos/proxy/mitigations/slowloris"
	"anti-ddos/proxy/mitigations/slowpost"
	"anti-ddos/proxy/mitigations/tlsfingerprint"
	"anti-ddos/proxy/mitigations/tlsreneg"
)

// Handler construit le mux admin.
func Handler(slow *slowloris.Limiter, flood *httpflood.Limiter, hdr *largeheader.Limiter, body *slowpost.Limiter, tls *tlsreneg.Limiter, h2 *http2reset.Limiter, hash *hashflood.Limiter, rng *rangeamp.Limiter, cache *cachepoison.Limiter, scrap *scraping.Limiter, cred *credstuff.Limiter, conc *concurrency.Limiter, hyg *requesthygiene.Limiter, tlsfp *tlsfingerprint.Limiter, credBlocklist *blocklist.Set, reg metrics.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/_admin/v1/mitigations/connections", connectionsHandler(slow))
	mux.Handle("/_admin/v1/mitigations/ratelimit", ratelimitHandler(flood))
	mux.Handle("/_admin/v1/mitigations/headers", headersHandler(hdr))
	mux.Handle("/_admin/v1/mitigations/bodies", bodiesHandler(body))
	mux.Handle("/_admin/v1/mitigations/tls", tlsHandler(tls))
	mux.Handle("/_admin/v1/mitigations/http2", http2Handler(h2))
	mux.Handle("/_admin/v1/mitigations/hash-flood", hashFloodHandler(hash))
	mux.Handle("/_admin/v1/mitigations/range-amp", rangeAmpHandler(rng))
	mux.Handle("/_admin/v1/mitigations/cache-poison", cachePoisonHandler(cache))
	mux.Handle("/_admin/v1/mitigations/scraping", scrapingHandler(scrap))
	mux.Handle("/_admin/v1/mitigations/credential-stuffing", credStuffHandler(cred))
	mux.Handle("/_admin/v1/mitigations/concurrency", concurrencyHandler(conc))
	mux.Handle("/_admin/v1/mitigations/request-hygiene", requestHygieneHandler(hyg))
	mux.Handle("/_admin/v1/mitigations/tls-fingerprint", tlsFingerprintHandler(tlsfp))
	mux.Handle("/_admin/v1/blocklist/credstuff", blocklistHandler(credBlocklist))
	mux.Handle("/_admin/v1/metrics", metricsHandler(reg))
	mux.HandleFunc("/_admin/v1/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return loopbackOnly(mux)
}

// connectionsRule est le format JSON accepté par le control plane.
// Doit rester aligné avec control/src/mitigations/connections.ts.
type connectionsRule struct {
	ID      string                `json:"id"`
	Enabled bool                  `json:"enabled"`
	OnError string                `json:"on_error"`
	Params  connectionsRuleParams `json:"params"`
	Reason  string                `json:"reason,omitempty"`
	Notes   string                `json:"notes,omitempty"`
}

type connectionsRuleParams struct {
	MaxConnsPerIP int `json:"max_conns_per_ip"`
}

// connectionsPayload : snapshot complet de la famille "connections".
type connectionsPayload struct {
	Rev   int               `json:"rev"`
	Rules []connectionsRule `json:"rules"`
}

func connectionsHandler(lim *slowloris.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg := lim.Config()
			rule := connectionsRule{
				ID:      "slowloris",
				Enabled: cfg.Enabled,
				OnError: cfg.OnError,
				Params:  connectionsRuleParams{MaxConnsPerIP: cfg.MaxConnsPerIP},
			}
			writeJSON(w, http.StatusOK, connectionsPayload{Rev: 0, Rules: []connectionsRule{rule}})
		case http.MethodPut:
			// Body limité à 64 KiB (anti-large-body sur l'admin API).
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
			var payload connectionsPayload
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error":   "invalid_body",
					"details": err.Error(),
				})
				return
			}
			// On accepte 0 ou 1 règle slowloris. Plusieurs ⇒ refus
			// (le proxy ne gère qu'une instance pour le MVP).
			var target *connectionsRule
			for i := range payload.Rules {
				if payload.Rules[i].ID == "slowloris" {
					target = &payload.Rules[i]
					break
				}
			}
			if target == nil {
				// Aucune règle slowloris ⇒ pas de changement.
				writeJSON(w, http.StatusOK, map[string]string{"status": "noop"})
				return
			}
			newCfg := slowloris.Config{
				Enabled:       target.Enabled,
				MaxConnsPerIP: target.Params.MaxConnsPerIP,
				OnError:       target.OnError,
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

// loopbackOnly rejette toute requête dont l'IP source n'est pas
// loopback. Défense en profondeur : même si quelqu'un bind 0.0.0.0
// par erreur, l'admin reste injoignable depuis l'extérieur.
func loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil || !ip.IsLoopback() {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
