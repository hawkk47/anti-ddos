// Package tlsfingerprint implémente la mitigation #14 (ja3-ja4-fingerprint).
//
// Le but : identifier les clients TLS hostiles ou non-conformes (bots,
// scanners, outils offensifs connus) par l'empreinte de leur ClientHello,
// indépendamment de l'IP source ou du User-Agent. Le ClientHello est le
// premier message du handshake TLS et révèle le profil cryptographique
// du client (versions supportées, suites de chiffrement, extensions,
// courbes, etc.). Les bibliothèques d'attaque (curl --tls-max=…, go-http,
// Python `requests`, outils de bruteforce) ont un ClientHello distinct
// des navigateurs réels, et changent rarement.
//
// Deux empreintes sont calculées :
//
//   - JA3 (Salesforce, 2017) : MD5 d'une concaténation
//     "SSLVersion,Cipher,Extension,EllipticCurve,ECPointFormat"
//     avec filtrage des valeurs GREASE (RFC 8701). Très répandu mais
//     vulnérable à des collisions et à l'altération volontaire.
//
//   - JA4 (FoxIO, 2023) : format lisible "tXXdNNMM<alpn>_<chash>_<ehash>"
//     plus stable (composantes triées, sigalgs séparés). Détaille
//     transport (t/q), version TLS, SNI présent (d/i), nb ciphers/ext,
//     ALPN, et deux hashes SHA-256 tronqués.
//
// Réaction : sur match blocklist, on retourne une erreur depuis
// GetConfigForClient → le handshake TLS est avorté, la connexion fermée
// avant qu'aucune requête HTTP ne soit acheminée. Aucun mapping
// conn↔request à maintenir, aucune fenêtre d'opportunité après decrypt.
//
// Références :
//   - Althouse, Atkinson, Atkins. "TLS Fingerprinting with JA3 and JA3S",
//     Salesforce Engineering, 2017. https://github.com/salesforce/ja3
//   - FoxIO. "JA4+ Network Fingerprinting", 2023.
//     https://github.com/FoxIO-LLC/ja4
//   - RFC 8701 — GREASE (Generate Random Extensions And Sustain
//     Extensibility), Benjamin, 2020.
//
// Limites : un attaquant peut spoofer une empreinte de navigateur (curl-
// impersonate, utls). Cette mitigation reste donc un filet utile contre
// le tout-venant (scanners auto, outils stock) mais pas une défense
// suffisante isolément.
package tlsfingerprint

import (
	"crypto/md5" //nolint:gosec // JA3 spec mandates MD5; pas de propriété cryptographique requise.
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"anti-ddos/proxy/internal/metrics"
)

// Reason décrit le verdict de l'évaluation d'un ClientHello.
type Reason int

const (
	ReasonNone       Reason = iota // pas de blocage
	ReasonJA3Blocked               // hash JA3 figure dans la blocklist
	ReasonJA4Blocked               // hash JA4 figure dans la blocklist
)

func (r Reason) String() string {
	switch r {
	case ReasonNone:
		return "none"
	case ReasonJA3Blocked:
		return "ja3_blocked"
	case ReasonJA4Blocked:
		return "ja4_blocked"
	default:
		return "unknown"
	}
}

// Config décrit les paramètres statiques de la mitigation.
//
// On_error : "allow" (défaut, fail-open) ou "deny" (fail-closed).
// Sur erreur interne du computer (ClientHelloInfo malformé, état
// inattendu) : "allow" laisse passer le handshake, "deny" le rejette.
type Config struct {
	Enabled    bool     `json:"enabled"`
	BlockedJA3 []string `json:"blocked_ja3"` // hashes MD5 32-hex lowercase
	BlockedJA4 []string `json:"blocked_ja4"` // format FoxIO complet
	OnError    string   `json:"on_error"`    // "allow" | "deny"
}

// Validate vérifie les invariants de la config.
func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	switch c.OnError {
	case "", "allow", "deny":
	default:
		return fmt.Errorf("on_error must be allow|deny, got %q", c.OnError)
	}
	for i, h := range c.BlockedJA3 {
		if len(h) != 32 {
			return fmt.Errorf("blocked_ja3[%d]: must be 32 hex chars, got %d", i, len(h))
		}
		if _, err := hex.DecodeString(h); err != nil {
			return fmt.Errorf("blocked_ja3[%d]: not hex: %w", i, err)
		}
		if strings.ToLower(h) != h {
			return fmt.Errorf("blocked_ja3[%d]: must be lowercase", i)
		}
	}
	for i, h := range c.BlockedJA4 {
		// Format FoxIO : "t13d1516h2_8daaf6152771_b186095e22b6"
		// (transport + version + sni + cipher_n + ext_n + alpn + _ + cipher_hash + _ + ext_hash)
		if len(h) < 10 || len(h) > 64 {
			return fmt.Errorf("blocked_ja4[%d]: invalid length %d", i, len(h))
		}
		if strings.Count(h, "_") != 2 {
			return fmt.Errorf("blocked_ja4[%d]: must contain exactly two underscores", i)
		}
	}
	return nil
}

// Limiter applique la mitigation. Hot-reload via Update.
type Limiter struct {
	cfg     atomic.Pointer[Config]
	ja3Set  atomic.Pointer[map[string]struct{}]
	ja4Set  atomic.Pointer[map[string]struct{}]
	metrics struct {
		evaluated metrics.Counter
		blocked   metrics.Counter
		errors    metrics.Counter
		duration  metrics.Histogram
	}
	now func() time.Time
}

// New construit un Limiter et enregistre les métriques.
func New(cfg Config, reg metrics.Registry) (*Limiter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	l := &Limiter{now: time.Now}
	c := cfg
	l.cfg.Store(&c)
	l.rebuildSets(&c)
	if reg != nil {
		l.metrics.evaluated = reg.Counter("mitigation_tls_fingerprint_evaluated_total")
		l.metrics.blocked = reg.Counter("mitigation_tls_fingerprint_blocked_total")
		l.metrics.errors = reg.Counter("mitigation_tls_fingerprint_errors_total")
		l.metrics.duration = reg.Histogram("mitigation_tls_fingerprint_duration_seconds")
	}
	return l, nil
}

// Update applique une nouvelle config à chaud (atomic swap).
func (l *Limiter) Update(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	c := cfg
	l.cfg.Store(&c)
	l.rebuildSets(&c)
	return nil
}

// Config retourne la copie courante.
func (l *Limiter) Config() Config { return *l.cfg.Load() }

func (l *Limiter) rebuildSets(c *Config) {
	ja3 := make(map[string]struct{}, len(c.BlockedJA3))
	for _, h := range c.BlockedJA3 {
		ja3[strings.ToLower(h)] = struct{}{}
	}
	ja4 := make(map[string]struct{}, len(c.BlockedJA4))
	for _, h := range c.BlockedJA4 {
		ja4[h] = struct{}{}
	}
	l.ja3Set.Store(&ja3)
	l.ja4Set.Store(&ja4)
}

// Metrics expose les compteurs en lecture seule.
func (l *Limiter) Metrics() (evaluated, blocked, errs uint64) {
	if l.metrics.evaluated == nil {
		return 0, 0, 0
	}
	return l.metrics.evaluated.Value(), l.metrics.blocked.Value(), l.metrics.errors.Value()
}

// ---------------------------------------------------------------------
// GREASE filtering (RFC 8701)
// ---------------------------------------------------------------------

// greaseValues = {0x0a0a, 0x1a1a, ..., 0xfafa} (16 valeurs réservées
// pour signaler "extension inutile" aux serveurs.) On les filtre pour
// que l'empreinte soit stable d'un handshake à l'autre.
var greaseValues = func() map[uint16]struct{} {
	m := make(map[uint16]struct{}, 16)
	for i := 0; i < 16; i++ {
		v := uint16(i)*0x1010 + 0x0a0a
		m[v] = struct{}{}
	}
	return m
}()

func isGREASE(v uint16) bool {
	_, ok := greaseValues[v]
	return ok
}

func filterGREASE16(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

// ---------------------------------------------------------------------
// JA3
// ---------------------------------------------------------------------

// ComputeJA3 retourne le hash MD5 (32 hex lowercase) du ClientHello.
// Format pré-hash : "SSLVersion,Cipher,Extension,EllipticCurve,ECPointFormat".
// GREASE filtré sur ciphers/extensions/curves.
//
// SSLVersion = max(SupportedVersions hors GREASE). Si vide, 0.
func ComputeJA3(chi *tls.ClientHelloInfo) string {
	if chi == nil {
		return ""
	}
	var version uint16
	for _, v := range filterGREASE16(chi.SupportedVersions) {
		if v > version {
			version = v
		}
	}
	ciphers := filterGREASE16(chi.CipherSuites)
	exts := filterGREASE16(chi.Extensions)
	curves := make([]uint16, 0, len(chi.SupportedCurves))
	for _, c := range chi.SupportedCurves {
		curves = append(curves, uint16(c))
	}
	curves = filterGREASE16(curves)

	var b strings.Builder
	b.WriteString(strconv.FormatUint(uint64(version), 10))
	b.WriteByte(',')
	writeJoinedDec(&b, ciphers)
	b.WriteByte(',')
	writeJoinedDec(&b, exts)
	b.WriteByte(',')
	writeJoinedDec(&b, curves)
	b.WriteByte(',')
	writeJoinedU8(&b, chi.SupportedPoints)

	sum := md5.Sum([]byte(b.String())) //nolint:gosec
	return hex.EncodeToString(sum[:])
}

func writeJoinedDec(b *strings.Builder, vs []uint16) {
	for i, v := range vs {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
}

func writeJoinedU8(b *strings.Builder, vs []uint8) {
	for i, v := range vs {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
}

// ---------------------------------------------------------------------
// JA4 (TCP profile only)
// ---------------------------------------------------------------------

// ComputeJA4 retourne l'empreinte FoxIO JA4 du ClientHello.
//
// Format : t<ver><d|i><nn><mm><alpn>_<chash>_<ehash>
//
//	t        — transport (TCP). QUIC ('q') hors scope.
//	ver      — version TLS max ("13","12","11","10") ou "00".
//	d|i      — 'd' si SNI présent, 'i' sinon.
//	nn       — nombre de ciphers (non-GREASE), %02d clampé 99.
//	mm       — nombre d'extensions (non-GREASE, excluant SNI=0 et
//	            ALPN=16 comme spécifié par FoxIO), %02d clampé 99.
//	alpn     — premier ALPN. Premier et dernier caractère ascii ; "00"
//	            si absent.
//	chash    — sha256(hex(ciphers triés asc)).join(",") tronqué à 12.
//	ehash    — sha256(hex(extensions triés asc, sans SNI/ALPN)
//	            ".join(",") + "_" + sigalgs (ordre original)).join(","))
//	            tronqué à 12.
func ComputeJA4(chi *tls.ClientHelloInfo) string {
	if chi == nil {
		return ""
	}
	var maxVer uint16
	for _, v := range filterGREASE16(chi.SupportedVersions) {
		if v > maxVer {
			maxVer = v
		}
	}
	verStr := tlsVersionToJA4(maxVer)

	sni := "i"
	if chi.ServerName != "" {
		sni = "d"
	}

	ciphers := filterGREASE16(chi.CipherSuites)
	allExts := filterGREASE16(chi.Extensions)
	// Pour le compteur et le hash, exclure SNI(0) et ALPN(16).
	extsForCount := make([]uint16, 0, len(allExts))
	for _, e := range allExts {
		if e == 0 || e == 16 {
			continue
		}
		extsForCount = append(extsForCount, e)
	}

	nn := clamp2(len(ciphers))
	mm := clamp2(len(extsForCount))

	alpn := "00"
	if len(chi.SupportedProtos) > 0 {
		p := chi.SupportedProtos[0]
		if len(p) >= 2 {
			alpn = string(p[0]) + string(p[len(p)-1])
		} else if len(p) == 1 {
			alpn = string(p[0]) + string(p[0])
		}
	}

	// Cipher hash : hex 4-char minuscule, trié asc, joint par ','.
	chash := sha12(joinHex16Sorted(ciphers))

	// Extension hash : hex 4-char trié asc + "_" + sigalgs ordre original.
	extHex := joinHex16Sorted(extsForCount)
	sigStr := joinHex16Original(toU16(chi.SignatureSchemes))
	ehashInput := extHex + "_" + sigStr
	ehash := sha12(ehashInput)

	return fmt.Sprintf("t%s%s%s%s%s_%s_%s", verStr, sni, nn, mm, alpn, chash, ehash)
}

func tlsVersionToJA4(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "13"
	case tls.VersionTLS12:
		return "12"
	case tls.VersionTLS11:
		return "11"
	case tls.VersionTLS10:
		return "10"
	default:
		return "00"
	}
}

func clamp2(n int) string {
	if n < 0 {
		n = 0
	}
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

func toU16(s []tls.SignatureScheme) []uint16 {
	out := make([]uint16, len(s))
	for i, v := range s {
		out[i] = uint16(v)
	}
	return out
}

func joinHex16Sorted(vs []uint16) string {
	cp := make([]uint16, len(vs))
	copy(cp, vs)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return joinHex16Original(cp)
}

func joinHex16Original(vs []uint16) string {
	var b strings.Builder
	for i, v := range vs {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%04x", v)
	}
	return b.String()
}

func sha12(in string) string {
	sum := sha256.Sum256([]byte(in))
	return hex.EncodeToString(sum[:6]) // 6 bytes → 12 hex chars
}

// ---------------------------------------------------------------------
// Evaluate / GetConfigForClient
// ---------------------------------------------------------------------

// Evaluate calcule les empreintes du ClientHello, consulte la
// blocklist et retourne le verdict + les hashes. Aucun side-effect.
func (l *Limiter) Evaluate(chi *tls.ClientHelloInfo) (ja3, ja4 string, r Reason) {
	if chi == nil {
		return "", "", ReasonNone
	}
	ja3 = ComputeJA3(chi)
	ja4 = ComputeJA4(chi)
	cfg := l.cfg.Load()
	if cfg == nil || !cfg.Enabled {
		return ja3, ja4, ReasonNone
	}
	if set := l.ja3Set.Load(); set != nil {
		if _, hit := (*set)[ja3]; hit {
			return ja3, ja4, ReasonJA3Blocked
		}
	}
	if set := l.ja4Set.Load(); set != nil {
		if _, hit := (*set)[ja4]; hit {
			return ja3, ja4, ReasonJA4Blocked
		}
	}
	return ja3, ja4, ReasonNone
}

// ErrBlocked est retourné par GetConfigForClient sur match blocklist.
// Le handshake TLS est avorté côté serveur ; le client voit une
// connexion fermée sans alerte explicative.
var ErrBlocked = errors.New("tls fingerprint blocked")

// GetConfigForClient est destiné à être branché sur tls.Config.
//
//	srv.TLSConfig.GetConfigForClient = lim.GetConfigForClient
//
// Sur match : retourne (nil, ErrBlocked) → handshake avorté.
// Sur miss / Enabled=false : retourne (nil, nil) → handshake suit la
// config de base. (Pas de surcharge de TLS settings ici ; on n'a que
// le contrôle d'admission.)
func (l *Limiter) GetConfigForClient(chi *tls.ClientHelloInfo) (*tls.Config, error) {
	cfg := l.cfg.Load()
	enabled := cfg != nil && cfg.Enabled
	t0 := l.now()
	if enabled && l.metrics.evaluated != nil {
		l.metrics.evaluated.Inc()
	}
	_, _, reason := l.Evaluate(chi)
	if enabled && l.metrics.duration != nil {
		l.metrics.duration.Observe(l.now().Sub(t0).Seconds())
	}
	if reason != ReasonNone {
		if l.metrics.blocked != nil {
			l.metrics.blocked.Inc()
		}
		return nil, ErrBlocked
	}
	return nil, nil
}

// Middleware est un no-op pour l'API HTTP. Le blocage se fait au
// handshake TLS via GetConfigForClient. Exposé pour cohérence avec
// les autres mitigations qui chaînent des http.Handler.
//
// Si un opérateur veut récupérer l'empreinte dans le handler HTTP
// (pour log/labelling), il doit injecter le ClientHello via un
// ConnContext custom — non fourni par défaut.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}
