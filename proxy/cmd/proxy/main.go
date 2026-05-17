// Package main bootstraps the anti-ddos data plane.
//
// Pure-Go (CGO_ENABLED=0), portable Windows + Linux. Cf.
// docs/adr/0001-language-data-plane.md and
// .github/instructions/proxy-data-plane.instructions.md.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"anti-ddos/proxy/internal/server"
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

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg, err := loadConfigFromEnv()
	if err != nil {
		logger.Error("invalid configuration", "err", err)
		os.Exit(2)
	}

	srv, err := server.New(cfg, logger)
	if err != nil {
		logger.Error("server init failed", "err", err)
		os.Exit(2)
	}

	// Signaux portables : SIGINT (Ctrl+C) sur Win/Linux, SIGTERM sur Linux
	// (no-op sur Windows mais accepté par signal.Notify).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server stopped with error", "err", err)
		os.Exit(1)
	}
	logger.Info("server stopped cleanly")
}

// loadConfigFromEnv lit la configuration depuis l'environnement. Aucun
// défaut ne pointe vers la prod ; les valeurs sont des défauts de dev
// loopback.
func loadConfigFromEnv() (server.Config, error) {
	cfg := server.Config{
		ListenAddr:        envOr("ANTIDDOS_LISTEN", "127.0.0.1:8080"),
		UpstreamURL:       envOr("ANTIDDOS_UPSTREAM", "http://127.0.0.1:9000"),
		AdminListenAddr:   envOr("ANTIDDOS_ADMIN_LISTEN", "127.0.0.1:8081"),
		AdminAuthToken:    envOr("ANTIDDOS_ADMIN_TOKEN", ""),
		ReadHeaderTimeout: envDuration("ANTIDDOS_READ_HEADER_TIMEOUT", 5*time.Second),
		ReadTimeout:       envDuration("ANTIDDOS_READ_TIMEOUT", 30*time.Second),
		WriteTimeout:      envDuration("ANTIDDOS_WRITE_TIMEOUT", 30*time.Second),
		IdleTimeout:       envDuration("ANTIDDOS_IDLE_TIMEOUT", 60*time.Second),
		MaxHeaderBytes:    envInt("ANTIDDOS_MAX_HEADER_BYTES", 1<<14), // 16 KiB
		// Slowloris : configuration runtime. Les défauts (Enabled=false,
		// MaxConnsPerIP=0) ⇒ pass-through. Les vraies valeurs viennent
		// de configs/base/connections.yaml via le control plane (à
		// brancher dans une étape ultérieure : POST /v1/reload).
		Slowloris: slowloris.Config{
			Enabled:       envBool("ANTIDDOS_SLOWLORIS_ENABLED", false),
			MaxConnsPerIP: envInt("ANTIDDOS_SLOWLORIS_MAX_PER_IP", 0),
			OnError:       envOr("ANTIDDOS_SLOWLORIS_ON_ERROR", "allow"),
		},
		HTTPFlood: httpflood.Config{
			Enabled:           envBool("ANTIDDOS_HTTPFLOOD_ENABLED", false),
			RequestsPerSecond: envFloat("ANTIDDOS_HTTPFLOOD_RPS", 0),
			Burst:             envInt("ANTIDDOS_HTTPFLOOD_BURST", 0),
			OnError:           envOr("ANTIDDOS_HTTPFLOOD_ON_ERROR", "deny"),
		},
		LargeHeader: largeheader.Config{
			Enabled:        envBool("ANTIDDOS_LARGEHEADER_ENABLED", false),
			MaxHeaderCount: envInt("ANTIDDOS_LARGEHEADER_MAX_COUNT", 0),
			MaxValueBytes:  envInt("ANTIDDOS_LARGEHEADER_MAX_VALUE_BYTES", 0),
			OnError:        envOr("ANTIDDOS_LARGEHEADER_ON_ERROR", "allow"),
		},
		SlowPost: slowpost.Config{
			Enabled:           envBool("ANTIDDOS_SLOWPOST_ENABLED", false),
			MaxBodyBytes:      int64(envInt("ANTIDDOS_SLOWPOST_MAX_BODY_BYTES", 0)),
			MinBytesPerSecond: envInt("ANTIDDOS_SLOWPOST_MIN_BYTES_PER_SEC", 0),
			GracePeriod:       envDuration("ANTIDDOS_SLOWPOST_GRACE", 0),
			OnError:           envOr("ANTIDDOS_SLOWPOST_ON_ERROR", "allow"),
		},
		TLSReneg: tlsreneg.Config{
			Enabled:                  envBool("ANTIDDOS_TLS_ENABLED", false),
			MinTLSVersion:            envOr("ANTIDDOS_TLS_MIN_VERSION", "1.2"),
			HandshakesPerSecondPerIP: envFloat("ANTIDDOS_TLS_HANDSHAKES_PER_SEC", 0),
			Burst:                    envInt("ANTIDDOS_TLS_BURST", 0),
			OnError:                  envOr("ANTIDDOS_TLS_ON_ERROR", "allow"),
		},
		HTTP2Reset: http2reset.Config{
			Enabled:              envBool("ANTIDDOS_HTTP2_ENABLED", false),
			MaxResetsPerConn:     envInt("ANTIDDOS_HTTP2_MAX_RESETS_PER_CONN", 0),
			Window:               envDuration("ANTIDDOS_HTTP2_WINDOW", 0),
			MaxConcurrentStreams: uint32(envInt("ANTIDDOS_HTTP2_MAX_CONCURRENT_STREAMS", 0)),
			OnError:              envOr("ANTIDDOS_HTTP2_ON_ERROR", "allow"),
		},
		HashFlood: hashflood.Config{
			Enabled:        envBool("ANTIDDOS_HASHFLOOD_ENABLED", false),
			MaxQueryParams: envInt("ANTIDDOS_HASHFLOOD_MAX_QUERY_PARAMS", 0),
			OnError:        envOr("ANTIDDOS_HASHFLOOD_ON_ERROR", "allow"),
		},
		RangeAmp: rangeamp.Config{
			Enabled:   envBool("ANTIDDOS_RANGEAMP_ENABLED", false),
			MaxRanges: envInt("ANTIDDOS_RANGEAMP_MAX_RANGES", 0),
			OnError:   envOr("ANTIDDOS_RANGEAMP_ON_ERROR", "allow"),
		},
		CachePoison: cachepoison.Config{
			Enabled: envBool("ANTIDDOS_CACHEPOISON_ENABLED", false),
			Headers: envCSV("ANTIDDOS_CACHEPOISON_HEADERS", nil),
			Action:  envOr("ANTIDDOS_CACHEPOISON_ACTION", "strip"),
		},
		Scraping: scraping.Config{
			Enabled:               envBool("ANTIDDOS_SCRAPING_ENABLED", false),
			UserAgentDeny:         envCSV("ANTIDDOS_SCRAPING_USER_AGENT_DENY", nil),
			RequireAcceptLanguage: envBool("ANTIDDOS_SCRAPING_REQUIRE_ACCEPT_LANGUAGE", false),
			RequireAcceptEncoding: envBool("ANTIDDOS_SCRAPING_REQUIRE_ACCEPT_ENCODING", false),
			Action:                envOr("ANTIDDOS_SCRAPING_ACTION", "log"),
		},
		CredStuff: credstuff.Config{
			Enabled:              envBool("ANTIDDOS_CREDSTUFF_ENABLED", false),
			LoginPaths:           envCSV("ANTIDDOS_CREDSTUFF_LOGIN_PATHS", nil),
			Methods:              envCSV("ANTIDDOS_CREDSTUFF_METHODS", nil),
			MaxAttemptsPerMinute: envInt("ANTIDDOS_CREDSTUFF_MAX_ATTEMPTS_PER_MINUTE", 0),
			Action:               envOr("ANTIDDOS_CREDSTUFF_ACTION", "deny"),
		},
		Concurrency: concurrency.Config{
			Enabled:     envBool("ANTIDDOS_CONCURRENCY_ENABLED", false),
			MaxInFlight: envInt("ANTIDDOS_CONCURRENCY_MAX_IN_FLIGHT", 0),
			OnError:     envOr("ANTIDDOS_CONCURRENCY_ON_ERROR", "allow"),
		},
		RequestHygiene: requesthygiene.Config{
			Enabled:         envBool("ANTIDDOS_REQUEST_HYGIENE_ENABLED", false),
			AllowedMethods:  envCSV("ANTIDDOS_REQUEST_HYGIENE_ALLOWED_METHODS", nil),
			MaxURILength:    envInt("ANTIDDOS_REQUEST_HYGIENE_MAX_URI_LENGTH", 0),
			RejectTECL:      envBool("ANTIDDOS_REQUEST_HYGIENE_REJECT_TE_CL", false),
			RejectDupCL:     envBool("ANTIDDOS_REQUEST_HYGIENE_REJECT_DUP_CL", false),
			RejectBadTE:     envBool("ANTIDDOS_REQUEST_HYGIENE_REJECT_BAD_TE", false),
			RejectEmptyHost: envBool("ANTIDDOS_REQUEST_HYGIENE_REJECT_EMPTY_HOST", false),
			OnError:         envOr("ANTIDDOS_REQUEST_HYGIENE_ON_ERROR", "deny"),
		},
		TLSFingerprint: tlsfingerprint.Config{
			Enabled:    envBool("ANTIDDOS_TLS_FINGERPRINT_ENABLED", false),
			BlockedJA3: envCSV("ANTIDDOS_TLS_FINGERPRINT_BLOCKED_JA3", nil),
			BlockedJA4: envCSV("ANTIDDOS_TLS_FINGERPRINT_BLOCKED_JA4", nil),
			OnError:    envOr("ANTIDDOS_TLS_FINGERPRINT_ON_ERROR", "allow"),
		},
	}
	return cfg, cfg.Validate()
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envFloat(key string, def float64) float64 {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func envCSV(key string, def []string) []string {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
