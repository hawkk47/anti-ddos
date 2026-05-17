package synflood

import (
	"net"
	"testing"
	"time"
)

func TestDisabledPasses(t *testing.T) {
	l, _ := New(Config{Enabled: false}, nil)
	for i := 0; i < 100; i++ {
		if !l.allow(net.ParseIP("8.8.8.8")) {
			t.Fatal("disabled must pass")
		}
	}
}

func TestPerIPBucketBlocksBurst(t *testing.T) {
	l, _ := New(Config{Enabled: true, AcceptsPerSecondPerIP: 1, BurstPerIP: 3}, nil)
	base := time.Unix(1700000000, 0)
	l.now = func() time.Time { return base }
	ip := net.ParseIP("8.8.8.8")
	for i := 0; i < 3; i++ {
		if !l.allow(ip) {
			t.Fatalf("burst %d should pass", i)
		}
	}
	if l.allow(ip) {
		t.Fatal("4th in same instant should be blocked")
	}
}

func TestRefillOverTime(t *testing.T) {
	l, _ := New(Config{Enabled: true, AcceptsPerSecondPerIP: 10, BurstPerIP: 1}, nil)
	base := time.Unix(1700000000, 0)
	now := base
	l.now = func() time.Time { return now }
	ip := net.ParseIP("8.8.8.8")
	if !l.allow(ip) {
		t.Fatal("first should pass")
	}
	if l.allow(ip) {
		t.Fatal("second immediate should fail")
	}
	now = base.Add(200 * time.Millisecond) // +2 tokens à 10/s
	if !l.allow(ip) {
		t.Fatal("after refill should pass")
	}
}

func TestPerSubnetBucket(t *testing.T) {
	l, _ := New(Config{
		Enabled:                   true,
		AcceptsPerSecondPerIP:     100,
		BurstPerIP:                100,
		AcceptsPerSecondPerSubnet: 1,
		BurstPerSubnet:            2,
	}, nil)
	base := time.Unix(1700000000, 0)
	l.now = func() time.Time { return base }
	// 3 IP différentes dans le même /24 → 2 passent, 3e bloquée
	// par le bucket subnet.
	ips := []string{"8.8.8.1", "8.8.8.2", "8.8.8.3"}
	got := 0
	for _, s := range ips {
		if l.allow(net.ParseIP(s)) {
			got++
		}
	}
	if got != 2 {
		t.Errorf("got %d passes, want 2 (subnet cap)", got)
	}
}

func TestLoopbackBypass(t *testing.T) {
	l, _ := New(Config{Enabled: true, AcceptsPerSecondPerIP: 1, BurstPerIP: 1}, nil)
	for i := 0; i < 10; i++ {
		if !l.allow(net.ParseIP("127.0.0.1")) {
			t.Fatal("loopback must always pass")
		}
	}
}

type fakeReporter struct {
	calls []net.IP
	ttl   time.Duration
}

func (f *fakeReporter) BlockIP(ip net.IP, ttl time.Duration) {
	f.calls = append(f.calls, ip)
	f.ttl = ttl
}

func TestReportOnBlock(t *testing.T) {
	l, _ := New(Config{
		Enabled:               true,
		AcceptsPerSecondPerIP: 1,
		BurstPerIP:            1,
		ReportTTL:             time.Minute,
	}, nil)
	base := time.Unix(1700000000, 0)
	l.now = func() time.Time { return base }
	rp := &fakeReporter{}
	l.SetReporter(rp)
	ip := net.ParseIP("8.8.8.8")
	l.allow(ip) // pass
	l.allow(ip) // block + report
	if len(rp.calls) != 1 {
		t.Fatalf("got %d reports, want 1", len(rp.calls))
	}
	if rp.ttl != time.Minute {
		t.Errorf("ttl=%v, want 1m", rp.ttl)
	}
}

func TestInvalidConfig(t *testing.T) {
	if _, err := New(Config{Enabled: true, AcceptsPerSecondPerIP: 0, BurstPerIP: 1}, nil); err == nil {
		t.Error("expected error for zero rate")
	}
}
