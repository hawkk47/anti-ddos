package ipreputation

import (
	"net"
	"testing"
	"time"
)

func mustLim(t *testing.T, cfg Config) *Limiter {
	t.Helper()
	l, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l
}

func TestDisabledPassesEverything(t *testing.T) {
	l := mustLim(t, Config{Enabled: false, Blocklist: []string{"1.2.3.0/24"}})
	if l.IsBlocked(net.ParseIP("1.2.3.4")) {
		t.Fatal("disabled config must not block")
	}
}

func TestStaticBlocklist(t *testing.T) {
	l := mustLim(t, Config{Enabled: true, Blocklist: []string{"203.0.113.0/24", "198.51.100.7"}})
	if !l.IsBlocked(net.ParseIP("203.0.113.42")) {
		t.Error("203.0.113.42 must be blocked")
	}
	if !l.IsBlocked(net.ParseIP("198.51.100.7")) {
		t.Error("198.51.100.7 must be blocked")
	}
	if l.IsBlocked(net.ParseIP("198.51.100.8")) {
		t.Error("198.51.100.8 must not be blocked")
	}
}

func TestAllowlistExempts(t *testing.T) {
	l := mustLim(t, Config{
		Enabled:   true,
		Allowlist: []string{"203.0.113.10"},
		Blocklist: []string{"203.0.113.0/24"},
	})
	if l.IsBlocked(net.ParseIP("203.0.113.10")) {
		t.Error("allowlisted IP must bypass blocklist")
	}
	if !l.IsBlocked(net.ParseIP("203.0.113.11")) {
		t.Error("non-allowlisted IP in blocklist must be blocked")
	}
}

func TestAllowlistStrict(t *testing.T) {
	l := mustLim(t, Config{
		Enabled:         true,
		Allowlist:       []string{"203.0.113.0/24"},
		AllowlistStrict: true,
	})
	if l.IsBlocked(net.ParseIP("203.0.113.5")) {
		t.Error("IP in strict allowlist must pass")
	}
	if !l.IsBlocked(net.ParseIP("8.8.8.8")) {
		t.Error("IP outside strict allowlist must be blocked")
	}
}

func TestLoopbackExempted(t *testing.T) {
	l := mustLim(t, Config{Enabled: true, AllowlistStrict: true, Allowlist: []string{"203.0.113.0/24"}})
	if l.IsBlocked(net.ParseIP("127.0.0.1")) {
		t.Error("loopback must never be blocked")
	}
	if l.IsBlocked(net.ParseIP("10.0.0.1")) {
		t.Error("private must never be blocked")
	}
}

func TestDynamicBlock(t *testing.T) {
	l := mustLim(t, Config{Enabled: true, DefaultBlockTTL: time.Hour})
	ip := net.ParseIP("8.8.8.8")
	if l.IsBlocked(ip) {
		t.Fatal("ip should not be blocked initially")
	}
	l.BlockIP(ip, 0)
	if !l.IsBlocked(ip) {
		t.Fatal("ip should be blocked after BlockIP")
	}
	if l.DynamicSize() != 1 {
		t.Errorf("DynamicSize=%d, want 1", l.DynamicSize())
	}
}

func TestDynamicExpiry(t *testing.T) {
	l := mustLim(t, Config{Enabled: true})
	base := time.Now()
	now := base
	l.now = func() time.Time { return now }
	ip := net.ParseIP("8.8.8.8")
	l.BlockIP(ip, 10*time.Millisecond)
	if !l.IsBlocked(ip) {
		t.Fatal("should be blocked at t0")
	}
	now = base.Add(11 * time.Millisecond)
	if l.IsBlocked(ip) {
		t.Fatal("should be unblocked after TTL")
	}
}

func TestDynamicCap(t *testing.T) {
	l := mustLim(t, Config{Enabled: true, MaxDynamicEntries: 3, DefaultBlockTTL: time.Hour})
	for i := 0; i < 5; i++ {
		ip := net.IPv4(192, 0, 2, byte(i+1))
		l.BlockIP(ip, 0)
	}
	if l.DynamicSize() != 3 {
		t.Errorf("DynamicSize=%d, want 3 (cap)", l.DynamicSize())
	}
}

func TestUpdateHotReload(t *testing.T) {
	l := mustLim(t, Config{Enabled: true, Blocklist: []string{"1.0.0.0/24"}})
	if !l.IsBlocked(net.ParseIP("1.0.0.5")) {
		t.Fatal("initially blocked")
	}
	if err := l.Update(Config{Enabled: true, Blocklist: []string{"2.0.0.0/24"}}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if l.IsBlocked(net.ParseIP("1.0.0.5")) {
		t.Error("should not be blocked after reload")
	}
	if !l.IsBlocked(net.ParseIP("2.0.0.5")) {
		t.Error("new blocklist should apply")
	}
}

func TestInvalidConfigRejected(t *testing.T) {
	if _, err := New(Config{Enabled: true, Blocklist: []string{"not-cidr"}}, nil); err == nil {
		t.Error("expected error for bad CIDR")
	}
	if _, err := New(Config{OnError: "weird"}, nil); err == nil {
		t.Error("expected error for bad OnError")
	}
}
