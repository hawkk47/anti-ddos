package credstuff

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"anti-ddos/proxy/internal/blocklist"
	"anti-ddos/proxy/internal/metrics"
)

// helper : middleware qui injecte un RemoteAddr explicite, peu importe
// l'IP r\u00e9elle du client httptest.
func withRemote(remote string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = remote
		next.ServeHTTP(w, r)
	})
}

func newCredLimWithBlocklist(t *testing.T, cfg Config) (*Limiter, *blocklist.Set) {
	t.Helper()
	lim, err := New(cfg, metrics.NewInMemory())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	bl := blocklist.New(nil)
	lim.SetBlocklist(bl)
	return lim, bl
}

func TestBlocklist_HitDeniesBeforeBucket(t *testing.T) {
	lim, bl := newCredLimWithBlocklist(t, Config{
		Enabled:              true,
		LoginPaths:           []string{"/login"},
		Methods:              []string{"POST"},
		MaxAttemptsPerMinute: 100, // bucket large : si lookup loup\u00e9, tout passerait
		Action:               ActionDeny,
		BlocklistEnabled:     true,
	})

	addr := netip.MustParseAddr("203.0.113.42")
	if err := bl.Replace(1, []blocklist.Entry{{
		IP:        addr,
		ExpiresAt: time.Now().Add(time.Hour),
		Reason:    "credstuff:cluster",
	}}); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(withRemote(net.JoinHostPort(addr.String(), "12345"), lim.Middleware(backend)))
	defer srv.Close()

	codes := stuffer(t, srv.URL, "/login", 3)
	for i, c := range codes {
		if c != http.StatusTooManyRequests {
			t.Fatalf("code[%d]=%d, want 429 (blocklist)", i, c)
		}
	}
	if got := lim.BlocklistHits(); got != 3 {
		t.Fatalf("blocklist_hits=%d, want 3", got)
	}
	_, _, _, blocked, _ := lim.Metrics()
	if blocked != 3 {
		t.Fatalf("blocked=%d, want 3", blocked)
	}
}

func TestBlocklist_HitLogsWhenActionLog(t *testing.T) {
	lim, bl := newCredLimWithBlocklist(t, Config{
		Enabled:              true,
		LoginPaths:           []string{"/login"},
		Methods:              []string{"POST"},
		MaxAttemptsPerMinute: 100,
		Action:               ActionLog,
		BlocklistEnabled:     true,
	})
	addr := netip.MustParseAddr("198.51.100.7")
	_ = bl.Replace(1, []blocklist.Entry{{IP: addr, ExpiresAt: time.Now().Add(time.Hour), Reason: "x"}})

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(withRemote(net.JoinHostPort(addr.String(), "1234"), lim.Middleware(backend)))
	defer srv.Close()

	codes := stuffer(t, srv.URL, "/login", 2)
	for i, c := range codes {
		if c != http.StatusOK {
			t.Fatalf("code[%d]=%d, want 200 (log-only)", i, c)
		}
	}
	if got := lim.BlocklistHits(); got != 2 {
		t.Fatalf("blocklist_hits=%d, want 2", got)
	}
	_, _, logged, blocked, _ := lim.Metrics()
	if blocked != 0 {
		t.Fatalf("blocked=%d, want 0 (action=log)", blocked)
	}
	if logged != 2 {
		t.Fatalf("logged=%d, want 2", logged)
	}
}

func TestBlocklist_MissFallsThroughToBucket(t *testing.T) {
	lim, bl := newCredLimWithBlocklist(t, Config{
		Enabled:              true,
		LoginPaths:           []string{"/login"},
		Methods:              []string{"POST"},
		MaxAttemptsPerMinute: 3,
		Action:               ActionDeny,
		BlocklistEnabled:     true,
	})
	// blocklist contient une AUTRE IP : la requ\u00eate doit retomber sur
	// le bucket per-IP v1.1.
	_ = bl.Replace(1, []blocklist.Entry{{
		IP: netip.MustParseAddr("203.0.113.99"), ExpiresAt: time.Now().Add(time.Hour), Reason: "x",
	}})

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(withRemote("198.51.100.1:5555", lim.Middleware(backend)))
	defer srv.Close()

	codes := stuffer(t, srv.URL, "/login", 10)
	var allow, denied int
	for _, c := range codes {
		switch c {
		case http.StatusUnauthorized:
			allow++
		case http.StatusTooManyRequests:
			denied++
		}
	}
	if allow != 3 || denied != 7 {
		t.Fatalf("bucket behaviour broken: allow=%d denied=%d, want 3/7", allow, denied)
	}
	if got := lim.BlocklistHits(); got != 0 {
		t.Fatalf("blocklist_hits=%d, want 0", got)
	}
}

func TestBlocklist_DisabledFlagSkipsLookup(t *testing.T) {
	lim, bl := newCredLimWithBlocklist(t, Config{
		Enabled:              true,
		LoginPaths:           []string{"/login"},
		Methods:              []string{"POST"},
		MaxAttemptsPerMinute: 100,
		Action:               ActionDeny,
		BlocklistEnabled:     false, // flag OFF
	})
	addr := netip.MustParseAddr("203.0.113.42")
	_ = bl.Replace(1, []blocklist.Entry{{IP: addr, ExpiresAt: time.Now().Add(time.Hour), Reason: "x"}})

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(withRemote(net.JoinHostPort(addr.String(), "1234"), lim.Middleware(backend)))
	defer srv.Close()

	codes := stuffer(t, srv.URL, "/login", 3)
	for i, c := range codes {
		if c != http.StatusUnauthorized {
			t.Fatalf("code[%d]=%d, want 401 (blocklist disabled)", i, c)
		}
	}
	if got := lim.BlocklistHits(); got != 0 {
		t.Fatalf("blocklist_hits=%d, want 0 (flag off)", got)
	}
}

func TestBlocklist_NilBlocklistNoCrash(t *testing.T) {
	// On construit le limiter mais on n'appelle PAS SetBlocklist.
	lim, err := New(Config{
		Enabled:              true,
		LoginPaths:           []string{"/login"},
		Methods:              []string{"POST"},
		MaxAttemptsPerMinute: 100,
		Action:               ActionDeny,
		BlocklistEnabled:     true, // m\u00eame avec flag on, blocklist nil = skip
	}, metrics.NewInMemory())
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(withRemote("203.0.113.42:1234", lim.Middleware(backend)))
	defer srv.Close()

	codes := stuffer(t, srv.URL, "/login", 2)
	for i, c := range codes {
		if c != http.StatusUnauthorized {
			t.Fatalf("code[%d]=%d, want 401 (blocklist nil = skip)", i, c)
		}
	}
}

func TestBlocklist_ExpiredEntryIgnored(t *testing.T) {
	lim, bl := newCredLimWithBlocklist(t, Config{
		Enabled:              true,
		LoginPaths:           []string{"/login"},
		Methods:              []string{"POST"},
		MaxAttemptsPerMinute: 100,
		Action:               ActionDeny,
		BlocklistEnabled:     true,
	})
	// Entr\u00e9e expir\u00e9e : Replace la drop. Le Lookup doit \u00eatre un miss.
	addr := netip.MustParseAddr("203.0.113.42")
	_ = bl.Replace(1, []blocklist.Entry{{
		IP: addr, ExpiresAt: time.Now().Add(-time.Hour), Reason: "stale",
	}})
	if bl.Size() != 0 {
		t.Fatalf("expected blocklist to drop expired entry, size=%d", bl.Size())
	}

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(withRemote(net.JoinHostPort(addr.String(), "1234"), lim.Middleware(backend)))
	defer srv.Close()

	codes := stuffer(t, srv.URL, "/login", 2)
	for i, c := range codes {
		if c != http.StatusUnauthorized {
			t.Fatalf("code[%d]=%d, want 401 (expired = miss)", i, c)
		}
	}
}

func TestBlocklist_OutOfScopePathSkipsLookup(t *testing.T) {
	// Path hors scope ne doit JAMAIS consulter la blocklist : on garde
	// le chemin chaud non-login propre (z\u00e9ro consultation).
	lim, bl := newCredLimWithBlocklist(t, Config{
		Enabled:              true,
		LoginPaths:           []string{"/login"},
		Methods:              []string{"POST"},
		MaxAttemptsPerMinute: 100,
		Action:               ActionDeny,
		BlocklistEnabled:     true,
	})
	addr := netip.MustParseAddr("203.0.113.42")
	_ = bl.Replace(1, []blocklist.Entry{{IP: addr, ExpiresAt: time.Now().Add(time.Hour), Reason: "x"}})

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(withRemote(net.JoinHostPort(addr.String(), "1234"), lim.Middleware(backend)))
	defer srv.Close()

	// On tape /public (pas /login) \u2192 hors scope.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/public",
		strings.NewReader("x=1"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	if got := lim.BlocklistHits(); got != 0 {
		t.Fatalf("blocklist_hits=%d, want 0 (out of scope)", got)
	}
}
