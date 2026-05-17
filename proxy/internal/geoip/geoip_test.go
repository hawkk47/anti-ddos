package geoip

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"anti-ddos/proxy/internal/metrics"
)

func TestCountryFor_LoopbackAndPrivateMapToLO(t *testing.T) {
	cases := []string{
		"127.0.0.1:12345",
		"[::1]:80",
		"10.0.0.5:443",
		"192.168.1.1:80",
		"172.16.0.1:80",
		"0.0.0.0:80",
	}
	for _, addr := range cases {
		if got := CountryFor(addr, ""); got != "LO" {
			t.Errorf("CountryFor(%q) = %q, want LO", addr, got)
		}
	}
}

func TestCountryFor_InvalidReturnsZZ(t *testing.T) {
	if got := CountryFor("not-an-ip", ""); got != "ZZ" {
		t.Errorf("invalid addr = %q, want ZZ", got)
	}
	if got := CountryFor("", ""); got != "ZZ" {
		t.Errorf("empty addr = %q, want ZZ", got)
	}
}

func TestCountryFor_XFFTakesPrecedence(t *testing.T) {
	// XFF avec IP publique (Cloudflare) — doit retourner un code à 2
	// lettres (sans présumer du pays exact, juste qu'on a lookup).
	got := CountryFor("127.0.0.1:80", "1.1.1.1")
	if len(got) != 2 {
		t.Fatalf("expected 2-letter code, got %q", got)
	}
	if got == "LO" {
		t.Errorf("XFF public IP should not map to LO, got %q", got)
	}
}

func TestMiddleware_IncrementsCounter(t *testing.T) {
	reg := metrics.NewInMemory()
	c := New(reg)

	h := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "127.0.0.1:5555"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
	}

	snap, _ := reg.(metrics.Snapshotter).Snapshot()
	var found bool
	for _, s := range snap {
		if strings.HasSuffix(s.Name, "_country_LO_total") {
			found = true
			if s.Value != 3 {
				t.Errorf("LO counter = %d, want 3", s.Value)
			}
		}
	}
	if !found {
		t.Fatalf("LO counter not found in snapshot: %+v", snap)
	}
}
