package adminapi

import (
	"testing"

	"anti-ddos/proxy/internal/metrics"
	"anti-ddos/proxy/mitigations/connflood"
	"anti-ddos/proxy/mitigations/geoblockl4"
	"anti-ddos/proxy/mitigations/handshakeguard"
	"anti-ddos/proxy/mitigations/ipreputation"
	"anti-ddos/proxy/mitigations/synflood"
)

// mustL3L4 instancie les 5 limiters L3/L4 en config par défaut (disabled).
// Helper de test partagé entre admin_test.go et metrics_test.go.
func mustL3L4(t *testing.T, reg metrics.Registry) (*ipreputation.Limiter, *connflood.Limiter, *synflood.Limiter, *handshakeguard.Limiter, *geoblockl4.Limiter) {
	t.Helper()
	ipr, err := ipreputation.New(ipreputation.Config{}, reg)
	if err != nil {
		t.Fatalf("ipreputation: %v", err)
	}
	cf, err := connflood.New(connflood.Config{}, reg)
	if err != nil {
		t.Fatalf("connflood: %v", err)
	}
	sf, err := synflood.New(synflood.Config{}, reg)
	if err != nil {
		t.Fatalf("synflood: %v", err)
	}
	hg, err := handshakeguard.New(handshakeguard.Config{}, reg)
	if err != nil {
		t.Fatalf("handshakeguard: %v", err)
	}
	gl, err := geoblockl4.New(geoblockl4.Config{}, reg)
	if err != nil {
		t.Fatalf("geoblockl4: %v", err)
	}
	return ipr, cf, sf, hg, gl
}
