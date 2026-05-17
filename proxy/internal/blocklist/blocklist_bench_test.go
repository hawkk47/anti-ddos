package blocklist

import (
	"net/netip"
	"testing"
	"time"
)

// BenchmarkLookup_Hit : lookup d'une IP présente dans une blocklist
// de 10k entrées. Objectif : O(1), 0 alloc/op.
func BenchmarkLookup_Hit(b *testing.B) {
	s := New(nil)
	entries := make([]Entry, 10_000)
	for i := range entries {
		entries[i] = Entry{
			IP:        netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}),
			ExpiresAt: time.Now().Add(time.Hour),
		}
	}
	if err := s.Replace(1, entries); err != nil {
		b.Fatalf("Replace: %v", err)
	}
	target := entries[5_000].IP

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := s.Lookup(target); !ok {
			b.Fatalf("miss")
		}
	}
}

// BenchmarkLookup_Miss : lookup d'une IP absente. Doit aussi être
// allocation-free.
func BenchmarkLookup_Miss(b *testing.B) {
	s := New(nil)
	entries := make([]Entry, 10_000)
	for i := range entries {
		entries[i] = Entry{
			IP:        netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}),
			ExpiresAt: time.Now().Add(time.Hour),
		}
	}
	_ = s.Replace(1, entries)
	missing := netip.AddrFrom4([4]byte{192, 0, 2, 1})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := s.Lookup(missing); ok {
			b.Fatalf("unexpected hit")
		}
	}
}
