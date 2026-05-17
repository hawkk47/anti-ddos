package blocklist

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

func mustIP(t *testing.T, s string) netip.Addr {
	t.Helper()
	ip, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ip
}

func TestNew_EmptyAndVersionZero(t *testing.T) {
	s := New(nil)
	if got := s.Size(); got != 0 {
		t.Fatalf("Size=%d want 0", got)
	}
	if got := s.Version(); got != 0 {
		t.Fatalf("Version=%d want 0", got)
	}
	if _, ok := s.Lookup(mustIP(t, "10.0.0.1")); ok {
		t.Fatalf("Lookup on empty set should miss")
	}
}

func TestLookup_HitsAndMisses(t *testing.T) {
	reg := metrics.NewInMemory()
	s := New(reg)

	ip1 := mustIP(t, "203.0.113.1")
	ip2 := mustIP(t, "203.0.113.2")
	if err := s.Replace(1, []Entry{
		{IP: ip1, ExpiresAt: time.Now().Add(time.Hour), Reason: "test"},
	}); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	if _, ok := s.Lookup(ip1); !ok {
		t.Fatalf("Lookup(ip1) miss, want hit")
	}
	if _, ok := s.Lookup(ip2); ok {
		t.Fatalf("Lookup(ip2) hit, want miss")
	}

	// Métriques : 2 lookups, 1 hit.
	if got := reg.Counter("blocklist_credstuff_lookups_total").Value(); got != 2 {
		t.Errorf("lookups=%d want 2", got)
	}
	if got := reg.Counter("blocklist_credstuff_hits_total").Value(); got != 1 {
		t.Errorf("hits=%d want 1", got)
	}
}

func TestLookup_InvalidIPMisses(t *testing.T) {
	s := New(nil)
	if _, ok := s.Lookup(netip.Addr{}); ok {
		t.Fatalf("Lookup(zero addr) hit, want miss")
	}
}

func TestLookup_ExpiredEntryMissesAndCounts(t *testing.T) {
	reg := metrics.NewInMemory()
	s := New(reg)

	// Horloge contrôlée : t0 publish, t0+5min lookup.
	t0 := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return t0 }

	ip := mustIP(t, "203.0.113.42")
	if err := s.Replace(1, []Entry{
		{IP: ip, ExpiresAt: t0.Add(1 * time.Minute), Reason: "test"},
	}); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	// Avant expiration.
	if _, ok := s.Lookup(ip); !ok {
		t.Fatalf("Lookup before expiry should hit")
	}

	// Après expiration.
	s.now = func() time.Time { return t0.Add(5 * time.Minute) }
	if _, ok := s.Lookup(ip); ok {
		t.Fatalf("Lookup after expiry should miss")
	}
	if got := reg.Counter("blocklist_credstuff_expired_total").Value(); got != 1 {
		t.Errorf("expired=%d want 1", got)
	}
}

func TestReplace_StaleVersionRejected(t *testing.T) {
	reg := metrics.NewInMemory()
	s := New(reg)

	if err := s.Replace(5, nil); err != nil {
		t.Fatalf("Replace v5: %v", err)
	}
	// Même version : refusé.
	if err := s.Replace(5, nil); !errors.Is(err, ErrStaleVersion) {
		t.Fatalf("Replace v5 again: got %v want ErrStaleVersion", err)
	}
	// Version inférieure : refusé.
	if err := s.Replace(3, nil); !errors.Is(err, ErrStaleVersion) {
		t.Fatalf("Replace v3 after v5: got %v want ErrStaleVersion", err)
	}
	if s.Version() != 5 {
		t.Fatalf("Version=%d want 5 (snapshot preserved)", s.Version())
	}
	if got := reg.Counter("blocklist_credstuff_rejects_total").Value(); got != 2 {
		t.Errorf("rejects=%d want 2", got)
	}
}

func TestReplace_TooManyEntriesRejected(t *testing.T) {
	s := New(nil)
	entries := make([]Entry, MaxEntries+1)
	for i := range entries {
		entries[i] = Entry{
			IP:        netip.AddrFrom4([4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}),
			ExpiresAt: time.Now().Add(time.Hour),
		}
	}
	if err := s.Replace(1, entries); !errors.Is(err, ErrTooManyEntries) {
		t.Fatalf("Replace oversize: got %v want ErrTooManyEntries", err)
	}
}

func TestReplace_InvalidIPRejected(t *testing.T) {
	s := New(nil)
	err := s.Replace(1, []Entry{
		{IP: netip.Addr{}, ExpiresAt: time.Now().Add(time.Hour), Reason: "x"},
	})
	if !errors.Is(err, ErrInvalidIP) {
		t.Fatalf("Replace invalid IP: got %v want ErrInvalidIP", err)
	}
}

func TestReplace_ReasonTooLongRejected(t *testing.T) {
	s := New(nil)
	big := make([]byte, MaxReasonLen+1)
	for i := range big {
		big[i] = 'x'
	}
	err := s.Replace(1, []Entry{
		{IP: mustIP(t, "10.0.0.1"), ExpiresAt: time.Now().Add(time.Hour), Reason: string(big)},
	})
	if err == nil {
		t.Fatalf("Replace oversize reason: want error")
	}
}

func TestReplace_DropsAlreadyExpired(t *testing.T) {
	s := New(nil)
	t0 := time.Now()
	s.now = func() time.Time { return t0 }

	if err := s.Replace(1, []Entry{
		{IP: mustIP(t, "10.0.0.1"), ExpiresAt: t0.Add(-time.Second), Reason: "stale"},
		{IP: mustIP(t, "10.0.0.2"), ExpiresAt: t0.Add(time.Hour), Reason: "ok"},
	}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if got := s.Size(); got != 1 {
		t.Fatalf("Size=%d want 1 (expired entry dropped)", got)
	}
	if _, ok := s.Lookup(mustIP(t, "10.0.0.1")); ok {
		t.Fatalf("expired entry should not be looked up")
	}
}

func TestReplace_DuplicateIPLastWins(t *testing.T) {
	s := New(nil)
	ip := mustIP(t, "10.0.0.1")
	if err := s.Replace(1, []Entry{
		{IP: ip, ExpiresAt: time.Now().Add(time.Hour), Reason: "first"},
		{IP: ip, ExpiresAt: time.Now().Add(time.Hour), Reason: "second"},
	}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	got, ok := s.Lookup(ip)
	if !ok {
		t.Fatalf("Lookup miss")
	}
	if got.Reason != "second" {
		t.Fatalf("Reason=%q want %q", got.Reason, "second")
	}
}

func TestReset_BumpsVersionAndClears(t *testing.T) {
	s := New(nil)
	_ = s.Replace(7, []Entry{
		{IP: mustIP(t, "10.0.0.1"), ExpiresAt: time.Now().Add(time.Hour), Reason: "x"},
	})
	s.Reset()
	if s.Version() != 8 {
		t.Fatalf("Version=%d want 8", s.Version())
	}
	if s.Size() != 0 {
		t.Fatalf("Size=%d want 0", s.Size())
	}
}

// TestConcurrent_LookupDuringReplace : pendant qu'un Lookup tourne en
// boucle, des Replace successifs ne doivent provoquer ni race
// (-race), ni faux miss, ni crash.
func TestConcurrent_LookupDuringReplace(t *testing.T) {
	s := New(nil)
	ip := mustIP(t, "203.0.113.99")

	if err := s.Replace(1, []Entry{
		{IP: ip, ExpiresAt: time.Now().Add(time.Hour), Reason: "v1"},
	}); err != nil {
		t.Fatalf("Replace v1: %v", err)
	}

	var (
		stop atomic.Bool
		wg   sync.WaitGroup
	)

	const readers = 8
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				// L'IP doit toujours être présente : tous les snapshots
				// successifs la contiennent.
				if _, ok := s.Lookup(ip); !ok {
					t.Errorf("Lookup miss during concurrent Replace")
					return
				}
			}
		}()
	}

	deadline := time.Now().Add(200 * time.Millisecond)
	version := int64(1)
	for time.Now().Before(deadline) {
		version++
		if err := s.Replace(version, []Entry{
			{IP: ip, ExpiresAt: time.Now().Add(time.Hour), Reason: "vN"},
		}); err != nil {
			t.Errorf("Replace v%d: %v", version, err)
			break
		}
	}
	stop.Store(true)
	wg.Wait()
}
