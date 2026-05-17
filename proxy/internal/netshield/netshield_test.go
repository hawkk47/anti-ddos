package netshield

import (
	"net"
	"testing"
)

func TestParseAddr(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"127.0.0.1:1234", "127.0.0.1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"[fe80::1%eth0]:80", "fe80::1"},
	}
	for _, c := range cases {
		addr, err := net.ResolveTCPAddr("tcp", c.in)
		if err != nil {
			t.Fatalf("resolve %s: %v", c.in, err)
		}
		ip := ParseAddr(addr)
		if ip == nil || ip.String() != c.want {
			t.Errorf("ParseAddr(%s)=%v, want %s", c.in, ip, c.want)
		}
	}
	if ParseAddr(nil) != nil {
		t.Error("ParseAddr(nil) should be nil")
	}
}

func TestSubnetKey(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"192.0.2.123", "192.0.2"},
		{"10.20.30.40", "10.20.30"},
		{"2001:db8:1234::1", "2001:db8:1234::"},
		{"2001:db8:abcd:efff::ff", "2001:db8:abcd::"},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.in)
		if got := SubnetKey(ip); got != c.want {
			t.Errorf("SubnetKey(%s)=%q, want %q", c.in, got, c.want)
		}
	}
	if SubnetKey(nil) != "" {
		t.Error("SubnetKey(nil) should be empty")
	}
}

func TestCIDRSet(t *testing.T) {
	s, err := NewCIDRSet([]string{"192.0.2.0/24", "203.0.113.5", "2001:db8::/32"})
	if err != nil {
		t.Fatalf("NewCIDRSet: %v", err)
	}
	if s.Len() != 3 {
		t.Errorf("Len=%d, want 3", s.Len())
	}
	cases := []struct {
		ip   string
		want bool
	}{
		{"192.0.2.42", true},
		{"192.0.3.1", false},
		{"203.0.113.5", true},
		{"203.0.113.6", false},
		{"2001:db8::cafe", true},
		{"2001:db9::1", false},
	}
	for _, c := range cases {
		if got := s.Contains(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("Contains(%s)=%v, want %v", c.ip, got, c.want)
		}
	}
	var nilSet *CIDRSet
	if nilSet.Contains(net.ParseIP("1.1.1.1")) {
		t.Error("nil set should not contain anything")
	}
}

func TestCIDRSetInvalid(t *testing.T) {
	if _, err := NewCIDRSet([]string{"not-an-ip", "10.0.0.0/99"}); err == nil {
		t.Error("expected error for invalid entries")
	}
}

func TestIsPrivateOrLoopback(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.0.0.5", true},
		{"192.168.1.1", true},
		{"169.254.1.1", true},
		{"1.1.1.1", false},
		{"2001:db8::1", false},
	}
	for _, c := range cases {
		if got := IsPrivateOrLoopback(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("IsPrivateOrLoopback(%s)=%v, want %v", c.ip, got, c.want)
		}
	}
}
