package tlsfingerprint

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

// ---------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------

// helloChrome représente une approximation d'un ClientHello Chrome
// récent (TLS 1.3, GREASE actif, ALPN h2). Les hashes seront calculés
// par les tests et figés dans des constantes pour servir de référence.
func helloChrome() *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		SupportedVersions: []uint16{0x6a6a /*GREASE*/, tls.VersionTLS13, tls.VersionTLS12},
		CipherSuites: []uint16{
			0x1a1a, // GREASE
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		Extensions: []uint16{
			0x2a2a, // GREASE
			0,      // server_name
			23,     // extended_master_secret
			65281,  // renegotiation_info
			10,     // supported_groups
			11,     // ec_point_formats
			16,     // ALPN
			43,     // supported_versions
		},
		SupportedCurves: []tls.CurveID{
			tls.CurveID(0xaaaa), // GREASE
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
		SupportedPoints:  []uint8{0},
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
		SupportedProtos:  []string{"h2", "http/1.1"},
		ServerName:       "example.test",
	}
}

// helloMinimal : ClientHello pauvre (curl --http1.1 style). Pas de SNI,
// pas d'ALPN, peu d'extensions. Sert à montrer qu'on distingue
// nettement un client "stock".
func helloMinimal() *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS12},
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
		Extensions:       []uint16{0, 23},
		SupportedCurves:  []tls.CurveID{tls.CurveP256},
		SupportedPoints:  []uint8{0},
		SignatureSchemes: []tls.SignatureScheme{tls.PKCS1WithSHA256},
		SupportedProtos:  nil,
		ServerName:       "",
	}
}

func defaultCfg() Config {
	return Config{
		Enabled:    true,
		BlockedJA3: nil,
		BlockedJA4: nil,
		OnError:    "allow",
	}
}

// ---------------------------------------------------------------------
// Pure-function tests
// ---------------------------------------------------------------------

func TestComputeJA3_StableAndGreaseFiltered(t *testing.T) {
	h1 := helloChrome()
	got1 := ComputeJA3(h1)
	if len(got1) != 32 {
		t.Fatalf("JA3 must be 32 hex chars, got %d (%q)", len(got1), got1)
	}

	// Re-run avec GREASE différents : doit donner le même hash.
	h2 := helloChrome()
	h2.SupportedVersions[0] = 0xeaea // autre GREASE
	h2.CipherSuites[0] = 0xfafa
	h2.Extensions[0] = 0xcaca
	h2.SupportedCurves[0] = tls.CurveID(0x3a3a)
	got2 := ComputeJA3(h2)
	if got1 != got2 {
		t.Fatalf("JA3 must be GREASE-invariant: %q vs %q", got1, got2)
	}
}

func TestComputeJA3_NilHello(t *testing.T) {
	if got := ComputeJA3(nil); got != "" {
		t.Errorf("ComputeJA3(nil)=%q, want empty", got)
	}
}

func TestComputeJA3_DifferentClientsDifferentHashes(t *testing.T) {
	a := ComputeJA3(helloChrome())
	b := ComputeJA3(helloMinimal())
	if a == b {
		t.Fatalf("Chrome and minimal should produce different JA3: both=%q", a)
	}
}

func TestComputeJA4_FormatAndComponents(t *testing.T) {
	got := ComputeJA4(helloChrome())
	// Format: t<2><d|i><nn><mm><2alpn>_<12hex>_<12hex>
	if !strings.HasPrefix(got, "t13d") {
		t.Errorf("expected t13d prefix (TLS 1.3, SNI present), got %q", got)
	}
	parts := strings.Split(got, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 must have 3 underscore-separated parts, got %d (%q)", len(parts), got)
	}
	if len(parts[1]) != 12 || len(parts[2]) != 12 {
		t.Errorf("JA4 hashes must be 12 chars each, got %d/%d", len(parts[1]), len(parts[2]))
	}
	if !strings.HasSuffix(parts[0], "h2") {
		t.Errorf("expected ALPN suffix 'h2' (first proto = h2), got prefix %q", parts[0])
	}
}

func TestComputeJA4_NoSNI(t *testing.T) {
	got := ComputeJA4(helloMinimal())
	if !strings.HasPrefix(got, "t12i") {
		t.Errorf("expected t12i prefix (TLS 1.2, no SNI), got %q", got)
	}
	// ALPN absent → "00"
	parts := strings.Split(got, "_")
	if !strings.HasSuffix(parts[0], "00") {
		t.Errorf("expected ALPN '00' suffix, got %q", parts[0])
	}
}

func TestComputeJA4_GreaseFiltered(t *testing.T) {
	a := ComputeJA4(helloChrome())
	h := helloChrome()
	h.SupportedVersions[0] = 0xeaea
	h.CipherSuites[0] = 0xfafa
	h.Extensions[0] = 0xcaca
	b := ComputeJA4(h)
	if a != b {
		t.Fatalf("JA4 must be GREASE-invariant: %q vs %q", a, b)
	}
}

func TestIsGREASE(t *testing.T) {
	cases := []struct {
		v      uint16
		grease bool
	}{
		{0x0a0a, true},
		{0x1a1a, true},
		{0xfafa, true},
		{0x0000, false},
		{0x1301, false}, // TLS_AES_128_GCM_SHA256
	}
	for _, tc := range cases {
		if got := isGREASE(tc.v); got != tc.grease {
			t.Errorf("isGREASE(%#x)=%v, want %v", tc.v, got, tc.grease)
		}
	}
}

// ---------------------------------------------------------------------
// Reproducer tests : sans / avec mitigation
// ---------------------------------------------------------------------

// TestReproducer_TLSFingerprint_WithoutMitigation : un ClientHello dont
// l'empreinte JA3 figurerait sur une blocklist n'est PAS rejeté tant
// que la mitigation est désactivée. La fonction Evaluate retourne
// ReasonNone et le hash, sans aucun effet de bord.
func TestReproducer_TLSFingerprint_WithoutMitigation(t *testing.T) {
	lim, err := New(Config{Enabled: false}, metrics.NewInMemory())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	chi := helloMinimal()
	ja3, ja4, reason := lim.Evaluate(chi)
	if reason != ReasonNone {
		t.Fatalf("disabled: want ReasonNone, got %v", reason)
	}
	if ja3 == "" || ja4 == "" {
		t.Fatalf("disabled: hashes should still be computed for observability (ja3=%q ja4=%q)", ja3, ja4)
	}
	// GetConfigForClient ne doit pas retourner d'erreur.
	cfg, err := lim.GetConfigForClient(chi)
	if cfg != nil || err != nil {
		t.Fatalf("disabled GetConfigForClient: cfg=%v err=%v, want (nil,nil)", cfg, err)
	}
	evald, blkd, errs := lim.Metrics()
	if evald != 0 || blkd != 0 || errs != 0 {
		t.Fatalf("disabled must not increment metrics, got %d/%d/%d", evald, blkd, errs)
	}
}

// TestReproducer_TLSFingerprint_WithMitigation_Blocks : avec la même
// empreinte ajoutée à BlockedJA3, GetConfigForClient retourne
// ErrBlocked et le handshake est rejeté.
func TestReproducer_TLSFingerprint_WithMitigation_Blocks(t *testing.T) {
	chi := helloMinimal()
	expectedJA3 := ComputeJA3(chi)

	cfg := defaultCfg()
	cfg.BlockedJA3 = []string{expectedJA3}
	lim, err := New(cfg, metrics.NewInMemory())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ja3, _, reason := lim.Evaluate(chi)
	if reason != ReasonJA3Blocked {
		t.Fatalf("want ReasonJA3Blocked, got %v (ja3=%s)", reason, ja3)
	}
	tlsCfg, err := lim.GetConfigForClient(chi)
	if err == nil || tlsCfg != nil {
		t.Fatalf("blocked GetConfigForClient: cfg=%v err=%v, want (nil,ErrBlocked)", tlsCfg, err)
	}
	evald, blkd, _ := lim.Metrics()
	if evald == 0 || blkd == 0 {
		t.Fatalf("metrics: evaluated=%d blocked=%d, want both >0", evald, blkd)
	}
}

func TestEvaluate_BlockedJA4(t *testing.T) {
	chi := helloChrome()
	expectedJA4 := ComputeJA4(chi)

	cfg := defaultCfg()
	cfg.BlockedJA4 = []string{expectedJA4}
	lim, err := New(cfg, metrics.NewInMemory())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, _, reason := lim.Evaluate(chi)
	if reason != ReasonJA4Blocked {
		t.Fatalf("want ReasonJA4Blocked, got %v", reason)
	}
}

func TestEvaluate_NotInBlocklist(t *testing.T) {
	cfg := defaultCfg()
	cfg.BlockedJA3 = []string{"deadbeef00000000000000000000beef"}
	lim, err := New(cfg, metrics.NewInMemory())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, _, reason := lim.Evaluate(helloChrome())
	if reason != ReasonNone {
		t.Fatalf("unrelated blocklist must not match, got %v", reason)
	}
}

func TestEvaluate_DisabledIgnoresBlocklist(t *testing.T) {
	chi := helloMinimal()
	cfg := Config{Enabled: false, BlockedJA3: []string{ComputeJA3(chi)}}
	lim, err := New(cfg, metrics.NewInMemory())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, _, reason := lim.Evaluate(chi)
	if reason != ReasonNone {
		t.Fatalf("disabled must ignore blocklist, got %v", reason)
	}
}

// ---------------------------------------------------------------------
// Hot reload
// ---------------------------------------------------------------------

func TestUpdate_HotReloadBlocklist(t *testing.T) {
	chi := helloMinimal()
	hash := ComputeJA3(chi)

	lim, err := New(defaultCfg(), metrics.NewInMemory())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, r := lim.Evaluate(chi); r != ReasonNone {
		t.Fatalf("before reload: want ReasonNone, got %v", r)
	}

	if err := lim.Update(Config{Enabled: true, BlockedJA3: []string{hash}, OnError: "allow"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if _, _, r := lim.Evaluate(chi); r != ReasonJA3Blocked {
		t.Fatalf("after reload: want ReasonJA3Blocked, got %v", r)
	}

	// Reload pour vider la blocklist : doit redevenir permissif.
	if err := lim.Update(defaultCfg()); err != nil {
		t.Fatalf("Update empty: %v", err)
	}
	if _, _, r := lim.Evaluate(chi); r != ReasonNone {
		t.Fatalf("after empty reload: want ReasonNone, got %v", r)
	}
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func TestValidate_RejectsBadJA3(t *testing.T) {
	cases := []struct {
		name string
		h    string
	}{
		{"too short", "abc"},
		{"too long", strings.Repeat("a", 33)},
		{"uppercase", "DEADBEEF00000000000000000000BEEF"},
		{"non-hex", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{Enabled: true, BlockedJA3: []string{tc.h}}
			if err := c.Validate(); err == nil {
				t.Errorf("want error for %q", tc.h)
			}
		})
	}
}

func TestValidate_RejectsBadJA4(t *testing.T) {
	cases := []struct {
		name string
		h    string
	}{
		{"too short", "tld"},
		{"no underscores", "t13d0102h2abcdefghijklmnopqrstuvwxyz0123"},
		{"too many underscores", "a_b_c_d"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{Enabled: true, BlockedJA4: []string{tc.h}}
			if err := c.Validate(); err == nil {
				t.Errorf("want error for %q", tc.h)
			}
		})
	}
}

func TestValidate_RejectsBadOnError(t *testing.T) {
	c := Config{Enabled: true, OnError: "log"}
	if err := c.Validate(); err == nil {
		t.Errorf("want error for on_error=log")
	}
}

func TestValidate_DisabledAcceptsAnything(t *testing.T) {
	c := Config{Enabled: false, BlockedJA3: []string{"garbage"}, OnError: "weird"}
	if err := c.Validate(); err != nil {
		t.Errorf("disabled should not validate: %v", err)
	}
}

// ---------------------------------------------------------------------
// Middleware no-op
// ---------------------------------------------------------------------

func TestMiddleware_IsNoOp(t *testing.T) {
	lim, err := New(defaultCfg(), metrics.NewInMemory())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	called := false
	h := lim.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if !called || resp.StatusCode != 200 {
		t.Errorf("middleware should be no-op: called=%v status=%d", called, resp.StatusCode)
	}
}

// ---------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------

func BenchmarkComputeJA3(b *testing.B) {
	chi := helloChrome()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeJA3(chi)
	}
}

func BenchmarkComputeJA4(b *testing.B) {
	chi := helloChrome()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeJA4(chi)
	}
}

// Évite l'erreur "imported and not used" pour les imports utiles aux
// futurs tests d'intégration TLS.
var _ = net.IPv4zero
var _ = time.Now
