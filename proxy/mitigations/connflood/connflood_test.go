package connflood

import (
	"net"
	"testing"
)

func TestDisabledPasses(t *testing.T) {
	l, _ := New(Config{Enabled: false, MaxConnsPerIP: 1}, nil)
	for i := 0; i < 10; i++ {
		ok, _, _ := l.reserve(net.ParseIP("8.8.8.8"))
		if !ok {
			t.Fatal("disabled must pass")
		}
	}
}

func TestPerIPCap(t *testing.T) {
	l, _ := New(Config{Enabled: true, MaxConnsPerIP: 2}, nil)
	ip := net.ParseIP("8.8.8.8")
	for i := 0; i < 2; i++ {
		ok, _, _ := l.reserve(ip)
		if !ok {
			t.Fatalf("reservation %d should succeed", i)
		}
	}
	ok, _, _ := l.reserve(ip)
	if ok {
		t.Fatal("3rd reservation should be rejected")
	}
}

func TestPerSubnetCap(t *testing.T) {
	l, _ := New(Config{Enabled: true, MaxConnsPerSubnet: 3}, nil)
	for i := 1; i <= 3; i++ {
		ok, _, _ := l.reserve(net.IPv4(8, 8, 8, byte(i)))
		if !ok {
			t.Fatalf("IP %d in same /24 should fit", i)
		}
	}
	ok, _, _ := l.reserve(net.IPv4(8, 8, 8, 4))
	if ok {
		t.Fatal("4th IP in same /24 should be rejected (subnet cap)")
	}
	// Autre subnet : OK.
	ok2, _, _ := l.reserve(net.IPv4(9, 9, 9, 1))
	if !ok2 {
		t.Fatal("different /24 should fit")
	}
}

func TestReleaseFreesSlot(t *testing.T) {
	l, _ := New(Config{Enabled: true, MaxConnsPerIP: 1}, nil)
	ip := net.ParseIP("8.8.8.8")
	ok, ipKey, subKey := l.reserve(ip)
	if !ok {
		t.Fatal("first reserve")
	}
	ok2, _, _ := l.reserve(ip)
	if ok2 {
		t.Fatal("second should fail before release")
	}
	l.release(ipKey, subKey)
	ok3, _, _ := l.reserve(ip)
	if !ok3 {
		t.Fatal("should succeed after release")
	}
}

func TestLoopbackBypass(t *testing.T) {
	l, _ := New(Config{Enabled: true, MaxConnsPerIP: 1}, nil)
	for i := 0; i < 5; i++ {
		ok, _, _ := l.reserve(net.ParseIP("127.0.0.1"))
		if !ok {
			t.Fatal("loopback must always pass")
		}
	}
}

func TestHotReload(t *testing.T) {
	l, _ := New(Config{Enabled: true, MaxConnsPerIP: 1}, nil)
	ip := net.ParseIP("8.8.8.8")
	if ok, _, _ := l.reserve(ip); !ok {
		t.Fatal("initial reserve")
	}
	if err := l.Update(Config{Enabled: true, MaxConnsPerIP: 5}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	// La connexion existante reste comptée (1) ; on doit pouvoir
	// ajouter 4 de plus.
	for i := 0; i < 4; i++ {
		if ok, _, _ := l.reserve(ip); !ok {
			t.Fatalf("post-reload reserve %d should succeed", i)
		}
	}
}

func TestInvalidConfig(t *testing.T) {
	if _, err := New(Config{MaxConnsPerIP: -1}, nil); err == nil {
		t.Error("expected error for negative cap")
	}
}
