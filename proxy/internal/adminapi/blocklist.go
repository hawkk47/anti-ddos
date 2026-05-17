package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"anti-ddos/proxy/internal/blocklist"
)

// blocklistEntryPayload : format JSON poussé par le control plane.
// Aligné avec le futur control/src/behavioral/credstuff/.
type blocklistEntryPayload struct {
	IP        string `json:"ip"`
	ExpiresAt string `json:"expires_at"` // RFC 3339
	Reason    string `json:"reason"`
}

type blocklistPayload struct {
	Version int64                   `json:"version"`
	Entries []blocklistEntryPayload `json:"entries"`
}

type blocklistStateResponse struct {
	Version int64 `json:"version"`
	Size    int   `json:"size"`
}

// blocklistHandler : GET pour lire l'état (version + size, pas les
// entrées : potentiellement 100k IPs, hors scope d'un GET), PUT pour
// remplacer le snapshot complet.
//
// Si set est nil, toutes les routes retournent 404 (mitigation
// pas câblée dans cette instance).
func blocklistHandler(set *blocklist.Set) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if set == nil {
			http.Error(w, "blocklist not enabled", http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, blocklistStateResponse{
				Version: set.Version(),
				Size:    set.Size(),
			})
		case http.MethodPut:
			// Body limité à 16 MiB : 100k entrées * ~140 octets JSON
			// = ~14 MiB, plus marge.
			r.Body = http.MaxBytesReader(w, r.Body, 16*1024*1024)
			var payload blocklistPayload
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error":   "invalid_body",
					"details": err.Error(),
				})
				return
			}
			entries := make([]blocklist.Entry, 0, len(payload.Entries))
			for i, e := range payload.Entries {
				ip, err := netip.ParseAddr(e.IP)
				if err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]string{
						"error":   "invalid_entry",
						"details": "entry[" + strconv.Itoa(i) + "].ip: " + err.Error(),
					})
					return
				}
				var exp time.Time
				if e.ExpiresAt != "" {
					exp, err = time.Parse(time.RFC3339, e.ExpiresAt)
					if err != nil {
						writeJSON(w, http.StatusBadRequest, map[string]string{
							"error":   "invalid_entry",
							"details": "entry[" + strconv.Itoa(i) + "].expires_at: " + err.Error(),
						})
						return
					}
				}
				entries = append(entries, blocklist.Entry{
					IP:        ip,
					ExpiresAt: exp,
					Reason:    e.Reason,
				})
			}
			if err := set.Replace(payload.Version, entries); err != nil {
				status := http.StatusBadRequest
				if errors.Is(err, blocklist.ErrStaleVersion) {
					status = http.StatusConflict
				}
				writeJSON(w, status, map[string]string{
					"error":   "replace_failed",
					"details": err.Error(),
				})
				return
			}
			writeJSON(w, http.StatusOK, blocklistStateResponse{
				Version: set.Version(),
				Size:    set.Size(),
			})
		default:
			w.Header().Set("Allow", "GET, PUT")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}