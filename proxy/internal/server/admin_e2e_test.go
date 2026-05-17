package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"
)

// TestE2E_AdminReloadAppliesSlowlorisConfig démarre un Server complet
// avec admin listener, pousse une nouvelle config via l'API admin, et
// vérifie que le limiter en mémoire reflète bien le changement. Ce
// test couvre la boucle complète "control plane → proxy admin →
// slowloris.Limiter.Update" qui est le coeur du hot-reload.
func TestE2E_AdminReloadAppliesSlowlorisConfig(t *testing.T) {
	cfg := Config{
		ListenAddr:        "127.0.0.1:0",
		AdminListenAddr:   "127.0.0.1:0",
		UpstreamURL:       "http://127.0.0.1:9", // jamais joint, inutile pour l'admin
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       time.Second,
		WriteTimeout:      time.Second,
		IdleTimeout:       time.Second,
		MaxHeaderBytes:    1 << 14,
	}
	srv, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- srv.Run(ctx) }()

	// Attendre que les listeners soient prêts.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && srv.AdminAddr() == "" {
		time.Sleep(5 * time.Millisecond)
	}
	if srv.AdminAddr() == "" {
		t.Fatal("admin listener not ready")
	}

	body := map[string]any{
		"rev": 3,
		"rules": []map[string]any{{
			"id":       "slowloris",
			"enabled":  true,
			"on_error": "allow",
			"params":   map[string]any{"max_conns_per_ip": 99},
		}},
	}
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPut, "http://"+srv.AdminAddr()+"/_admin/v1/mitigations/connections", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("admin PUT: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d want 200, body=%s", resp.StatusCode, out)
	}

	got := srv.Slowloris().Config()
	if got.MaxConnsPerIP != 99 || !got.Enabled || got.OnError != "allow" {
		t.Errorf("limiter config not applied: %+v", got)
	}

	cancel()
	if err := <-runDone; err != nil {
		t.Errorf("Run returned: %v", err)
	}
}
