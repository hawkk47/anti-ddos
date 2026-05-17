// Package adminapi — middleware d'auth Bearer pour l'API admin.
//
// Politique :
//
//   - Routes publiques (toujours accessibles, jamais authentifiées) :
//     `/_admin/v1/health`, `/_admin/v1/metrics`.
//   - Tout le reste : header `Authorization: Bearer <token>` requis
//     si un token est configuré (non vide).
//   - Token vide ⇒ bypass. Le caller (server.New) est responsable de
//     refuser de booter sur un bind non-loopback sans token.
//   - Comparaison en temps constant (crypto/subtle).
//   - Pas d'écho du token dans les logs ni les réponses ; le 401 est
//     identique que le header soit absent, mal formé ou erroné.
package adminapi

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// publicAdminRoutes : routes (méthode + chemin exact) toujours ouvertes.
// Ne PAS inclure ici des chemins qui mutent (PUT/POST/DELETE).
//
// /_admin/v1/metrics est ouvert pour le scrape Prometheus : c'est
// acceptable parce que l'admin API bind LOOPBACK uniquement (cf.
// server.requireAdminLoopback). Si cette contrainte est jamais
// relâchée, retirer metrics de cette liste.
var publicAdminRoutes = map[string]struct{}{
	"GET /_admin/v1/health":  {},
	"GET /_admin/v1/metrics": {},
}

func isPublicAdminRoute(r *http.Request) bool {
	// On compare sur le path nu (sans query) — aucune de nos routes
	// publiques ne dépend du query string.
	key := r.Method + " " + r.URL.Path
	_, ok := publicAdminRoutes[key]
	return ok
}

// BearerAuth retourne un middleware qui exige `Authorization: Bearer
// <token>` sur toutes les routes non publiques. Token vide ⇒ bypass
// total (utile en dev loopback ; server.New refusera ce cas en bind
// non-loopback).
func BearerAuth(token string) func(http.Handler) http.Handler {
	if token == "" {
		return func(next http.Handler) http.Handler { return next }
	}
	expected := []byte(token)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isPublicAdminRoute(r) {
				next.ServeHTTP(w, r)
				return
			}
			h := r.Header.Get("Authorization")
			const prefix = "Bearer "
			if !strings.HasPrefix(h, prefix) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
			presented := []byte(strings.TrimSpace(h[len(prefix):]))
			// subtle.ConstantTimeCompare retourne 0 si les longueurs
			// diffèrent, donc on n'expose pas la longueur attendue.
			if subtle.ConstantTimeCompare(presented, expected) != 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
