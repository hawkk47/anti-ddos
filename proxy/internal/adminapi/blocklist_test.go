package adminapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"anti-ddos/proxy/internal/blocklist"
)

func newBlocklistServer(t *testing.T, set *blocklist.Set) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/_admin/v1/blocklist/credstuff", blocklistHandler(set))
	srv := httptest.NewServer(loopbackOnly(mux))
	t.Cleanup(srv.Close)
	return srv
}

func TestBlocklistAdmin_GetEmpty(t *testing.T) {
	set := blocklist.New(nil)
	srv := newBlocklistServer(t, set)

	resp, err := http.Get(srv.URL + "/_admin/v1/blocklist/credstuff")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
	var got blocklistStateResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Version != 0 || got.Size != 0 {
		t.Fatalf("want empty state, got %+v", got)
	}
}

func TestBlocklistAdmin_PutAndGet(t *testing.T) {
	set := blocklist.New(nil)
	srv := newBlocklistServer(t, set)

	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	body := blocklistPayload{
		Version: 5,
		Entries: []blocklistEntryPayload{
			{IP: "203.0.113.1", ExpiresAt: exp, Reason: "credstuff:cluster"},
			{IP: "203.0.113.2", ExpiresAt: exp, Reason: "credstuff:cluster"},
		},
	}
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/_admin/v1/blocklist/credstuff", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
	var got blocklistStateResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Version != 5 || got.Size != 2 {
		t.Fatalf("want v=5 size=2, got %+v", got)
	}
}

func TestBlocklistAdmin_StaleVersionReturns409(t *testing.T) {
	set := blocklist.New(nil)
	srv := newBlocklistServer(t, set)

	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	put := func(v int64) int {
		body, _ := json.Marshal(blocklistPayload{
			Version: v,
			Entries: []blocklistEntryPayload{{IP: "203.0.113.10", ExpiresAt: exp, Reason: "x"}},
		})
		req, _ := http.NewRequest(http.MethodPut, srv.URL+"/_admin/v1/blocklist/credstuff", bytes.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT v=%d: %v", v, err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if got := put(10); got != http.StatusOK {
		t.Fatalf("first put: got %d", got)
	}
	if got := put(5); got != http.StatusConflict {
		t.Fatalf("stale put: want 409, got %d", got)
	}
}

func TestBlocklistAdmin_InvalidIPReturns400(t *testing.T) {
	set := blocklist.New(nil)
	srv := newBlocklistServer(t, set)

	body, _ := json.Marshal(blocklistPayload{
		Version: 1,
		Entries: []blocklistEntryPayload{{IP: "not-an-ip", Reason: "x"}},
	})
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/_admin/v1/blocklist/credstuff", bytes.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
	buf, _ := jsonReadAll(resp.Body)
	if !strings.Contains(buf, "invalid_entry") {
		t.Fatalf("error body: %s", buf)
	}
}

func TestBlocklistAdmin_NilSetReturns404(t *testing.T) {
	srv := newBlocklistServer(t, nil)
	resp, err := http.Get(srv.URL + "/_admin/v1/blocklist/credstuff")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestBlocklistAdmin_MethodNotAllowed(t *testing.T) {
	set := blocklist.New(nil)
	srv := newBlocklistServer(t, set)
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/_admin/v1/blocklist/credstuff", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); got != "GET, PUT" {
		t.Fatalf("Allow: got %q", got)
	}
}

func jsonReadAll(r interface{ Read([]byte) (int, error) }) (string, error) {
	var sb strings.Builder
	buf := make([]byte, 1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			if err.Error() == "EOF" {
				return sb.String(), nil
			}
			return sb.String(), err
		}
	}
}
