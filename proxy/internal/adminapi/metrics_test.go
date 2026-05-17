package adminapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"anti-ddos/proxy/internal/metrics"
	"anti-ddos/proxy/mitigations/cachepoison"
	"anti-ddos/proxy/mitigations/concurrency"
	"anti-ddos/proxy/mitigations/credstuff"
	"anti-ddos/proxy/mitigations/hashflood"
	"anti-ddos/proxy/mitigations/http2reset"
	"anti-ddos/proxy/mitigations/httpflood"
	"anti-ddos/proxy/mitigations/largeheader"
	"anti-ddos/proxy/mitigations/rangeamp"
	"anti-ddos/proxy/mitigations/requesthygiene"
	"anti-ddos/proxy/mitigations/scraping"
	"anti-ddos/proxy/mitigations/slowloris"
	"anti-ddos/proxy/mitigations/slowpost"
	"anti-ddos/proxy/mitigations/tlsfingerprint"
	"anti-ddos/proxy/mitigations/tlsreneg"
)

// mustFlood : helper construisant un httpflood.Limiter pass-through.
func mustFlood(t *testing.T, reg metrics.Registry) *httpflood.Limiter {
	t.Helper()
	f, err := httpflood.New(httpflood.Config{}, reg)
	if err != nil {
		t.Fatalf("flood: %v", err)
	}
	return f
}

// mustHdr : helper construisant un largeheader.Limiter pass-through.
func mustHdr(t *testing.T, reg metrics.Registry) *largeheader.Limiter {
	t.Helper()
	h, err := largeheader.New(largeheader.Config{}, reg)
	if err != nil {
		t.Fatalf("hdr: %v", err)
	}
	return h
}

// mustBody : helper construisant un slowpost.Limiter pass-through.
func mustBody(t *testing.T, reg metrics.Registry) *slowpost.Limiter {
	t.Helper()
	b, err := slowpost.New(slowpost.Config{}, reg)
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	return b
}

// mustTLS : helper construisant un tlsreneg.Limiter pass-through.
func mustTLS(t *testing.T, reg metrics.Registry) *tlsreneg.Limiter {
	t.Helper()
	l, err := tlsreneg.New(tlsreneg.Config{}, reg)
	if err != nil {
		t.Fatalf("tls: %v", err)
	}
	return l
}

// mustH2 : helper construisant un http2reset.Limiter pass-through.
func mustH2(t *testing.T, reg metrics.Registry) *http2reset.Limiter {
	t.Helper()
	l, err := http2reset.New(http2reset.Config{}, reg)
	if err != nil {
		t.Fatalf("h2: %v", err)
	}
	return l
}

// mustHash : helper construisant un hashflood.Limiter pass-through.
func mustHash(t *testing.T, reg metrics.Registry) *hashflood.Limiter {
	t.Helper()
	l, err := hashflood.New(hashflood.Config{}, reg)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return l
}

// mustRange : helper construisant un rangeamp.Limiter pass-through.
func mustRange(t *testing.T, reg metrics.Registry) *rangeamp.Limiter {
	t.Helper()
	l, err := rangeamp.New(rangeamp.Config{}, reg)
	if err != nil {
		t.Fatalf("rangeamp: %v", err)
	}
	return l
}

// mustCache : helper construisant un cachepoison.Limiter pass-through.
func mustCache(t *testing.T, reg metrics.Registry) *cachepoison.Limiter {
	t.Helper()
	l, err := cachepoison.New(cachepoison.Config{}, reg)
	if err != nil {
		t.Fatalf("cachepoison: %v", err)
	}
	return l
}

// mustScrap : helper construisant un scraping.Limiter pass-through.
func mustScrap(t *testing.T, reg metrics.Registry) *scraping.Limiter {
	t.Helper()
	l, err := scraping.New(scraping.Config{}, reg)
	if err != nil {
		t.Fatalf("scraping: %v", err)
	}
	return l
}

// mustCred : helper construisant un credstuff.Limiter pass-through.
func mustCred(t *testing.T, reg metrics.Registry) *credstuff.Limiter {
	t.Helper()
	l, err := credstuff.New(credstuff.Config{}, reg)
	if err != nil {
		t.Fatalf("credstuff: %v", err)
	}
	return l
}

func mustConc(t *testing.T, reg metrics.Registry) *concurrency.Limiter {
	t.Helper()
	l, err := concurrency.New(concurrency.Config{}, reg)
	if err != nil {
		t.Fatalf("concurrency: %v", err)
	}
	return l
}

func mustHyg(t *testing.T, reg metrics.Registry) *requesthygiene.Limiter {
	t.Helper()
	l, err := requesthygiene.New(requesthygiene.Config{}, reg)
	if err != nil {
		t.Fatalf("requesthygiene: %v", err)
	}
	return l
}

func mustTLSFP(t *testing.T, reg metrics.Registry) *tlsfingerprint.Limiter {
	t.Helper()
	l, err := tlsfingerprint.New(tlsfingerprint.Config{}, reg)
	if err != nil {
		t.Fatalf("tlsfingerprint: %v", err)
	}
	return l
}

func TestMetrics_ExposesPrometheusFormat(t *testing.T) {
	reg := metrics.NewInMemory()
	lim, err := slowloris.New(slowloris.Config{Enabled: true, MaxConnsPerIP: 1}, reg)
	if err != nil {
		t.Fatalf("limiter: %v", err)
	}
	srv := httptest.NewServer(Handler(lim, mustFlood(t, reg), mustHdr(t, reg), mustBody(t, reg), mustTLS(t, reg), mustH2(t, reg), mustHash(t, reg), mustRange(t, reg), mustCache(t, reg), mustScrap(t, reg), mustCred(t, reg), mustConc(t, reg), mustHyg(t, reg), mustTLSFP(t, reg), nil, reg))
	defer srv.Close()

	// Génère un peu d'activité pour avoir des compteurs non nuls.
	reg.Counter("slowloris.evaluated.total").Add(3)
	reg.Counter("slowloris.blocked.total").Inc()
	reg.Histogram("slowloris.eval.seconds").Observe(0.0012)

	resp, err := http.Get(srv.URL + "/_admin/v1/metrics")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type: %q", ct)
	}
	raw, _ := io.ReadAll(resp.Body)
	body := string(raw)
	for _, want := range []string{
		"# TYPE slowloris_evaluated_total counter",
		"slowloris_evaluated_total 3",
		"slowloris_blocked_total 1",
		"# TYPE slowloris_eval_seconds summary",
		"slowloris_eval_seconds_count 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in body:\n%s", want, body)
		}
	}
}

func TestMetrics_RejectsNonLoopback(t *testing.T) {
	reg := metrics.NewInMemory()
	lim, _ := slowloris.New(slowloris.Config{}, reg)
	h := Handler(lim, mustFlood(t, reg), mustHdr(t, reg), mustBody(t, reg), mustTLS(t, reg), mustH2(t, reg), mustHash(t, reg), mustRange(t, reg), mustCache(t, reg), mustScrap(t, reg), mustCred(t, reg), mustConc(t, reg), mustHyg(t, reg), mustTLSFP(t, reg), nil, reg)
	req := httptest.NewRequest(http.MethodGet, "/_admin/v1/metrics", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("got %d want 403", rec.Code)
	}
}

func TestPromName_Sanitizes(t *testing.T) {
	cases := map[string]string{
		"slowloris.evaluated.total": "slowloris_evaluated_total",
		"foo:bar":                   "foo:bar",
		"1leading":                  "_leading",
		"http.500.errors":           "http_500_errors",
	}
	for in, want := range cases {
		if got := promName(in); got != want {
			t.Errorf("promName(%q) = %q, want %q", in, got, want)
		}
	}
}
