package geoblockl4

import (
	"net"
	"testing"
)

func TestDisabledPasses(t *testing.T) {
	l, _ := New(Config{Enabled: false, Block: []string{"CN"}}, nil)
	if l.IsBlocked(net.ParseIP("1.1.1.1")) {
		t.Fatal("disabled must not block")
	}
}

func TestLoopbackNeverBlocked(t *testing.T) {
	l, _ := New(Config{Enabled: true, Allow: []string{"FR"}}, nil)
	for _, ip := range []string{"127.0.0.1", "::1", "10.0.0.1"} {
		if l.IsBlocked(net.ParseIP(ip)) {
			t.Errorf("%s must not be blocked", ip)
		}
	}
}

func TestBlocklistKnownCountry(t *testing.T) {
	// 8.8.8.8 → US (Google DNS), publiquement connu.
	l, _ := New(Config{Enabled: true, Block: []string{"US"}}, nil)
	if !l.IsBlocked(net.ParseIP("8.8.8.8")) {
		t.Errorf("8.8.8.8 (US) should be blocked")
	}
}

func TestAllowlistRestricts(t *testing.T) {
	l, _ := New(Config{Enabled: true, Allow: []string{"FR"}}, nil)
	// 8.8.8.8 = US, hors allow → bloqué.
	if !l.IsBlocked(net.ParseIP("8.8.8.8")) {
		t.Errorf("8.8.8.8 (US) outside FR allow → block expected")
	}
}

func TestHotReload(t *testing.T) {
	l, _ := New(Config{Enabled: true, Block: []string{"US"}}, nil)
	if !l.IsBlocked(net.ParseIP("8.8.8.8")) {
		t.Fatal("initially blocked")
	}
	if err := l.Update(Config{Enabled: true}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if l.IsBlocked(net.ParseIP("8.8.8.8")) {
		t.Error("should pass after disabling block")
	}
}

func TestInvalidConfig(t *testing.T) {
	if _, err := New(Config{Block: []string{"FRA"}}, nil); err == nil {
		t.Error("expected error on 3-letter code")
	}
}

func TestLookupCountry(t *testing.T) {
	if cc := LookupCountry(net.ParseIP("127.0.0.1")); cc != "LO" {
		t.Errorf("loopback=%q, want LO", cc)
	}
	if cc := LookupCountry(nil); cc != "ZZ" {
		t.Errorf("nil=%q, want ZZ", cc)
	}
}
