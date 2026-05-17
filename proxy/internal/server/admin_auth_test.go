package server

import (
	"strings"
	"testing"
)

func TestRequireAdminLoopback_AcceptsLoopback(t *testing.T) {
	t.Parallel()
	cases := []string{"127.0.0.1:8081", "127.0.0.42:0", "[::1]:8081", "localhost:8081"}
	for _, addr := range cases {
		if err := requireAdminLoopback(addr); err != nil {
			t.Errorf("addr=%q loopback: unexpected error %v", addr, err)
		}
	}
}

func TestRequireAdminLoopback_RejectsNonLoopback(t *testing.T) {
	t.Parallel()
	cases := []string{
		"0.0.0.0:8081",
		"[::]:8081",
		"192.0.2.1:8081",
		":8081",
		"example.com:8081",
	}
	for _, addr := range cases {
		err := requireAdminLoopback(addr)
		if err == nil {
			t.Errorf("addr=%q: expected refusal, got nil", addr)
			continue
		}
		if !strings.Contains(err.Error(), "loopback") && !strings.Contains(err.Error(), "invalid") {
			t.Errorf("addr=%q: error %q should mention loopback", addr, err.Error())
		}
	}
}

func TestRequireAdminLoopback_BearerIsDefenseInDepth(t *testing.T) {
	// Le Bearer s'ajoute à loopback-only ; il ne le remplace pas.
	// Donc un bind non-loopback DOIT être refusé même avec token —
	// requireAdminLoopback ne prend pas le token en compte.
	t.Parallel()
	if err := requireAdminLoopback("0.0.0.0:8081"); err == nil {
		t.Fatalf("non-loopback bind must be refused")
	}
	if err := requireAdminLoopback("127.0.0.1:8081"); err != nil {
		t.Fatalf("loopback bind must be accepted: %v", err)
	}
}

func TestRequireAdminLoopback_MalformedAddr(t *testing.T) {
	t.Parallel()
	if err := requireAdminLoopback("not-a-valid-addr"); err == nil {
		t.Fatalf("expected error for malformed address")
	}
}
