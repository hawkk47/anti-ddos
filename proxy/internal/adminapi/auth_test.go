package adminapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBearerAuth_BypassWhenEmpty(t *testing.T) {
	t.Parallel()
	mw := BearerAuth("")
	called := false
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/_admin/v1/blocklist/credstuff", strings.NewReader(""))
	h.ServeHTTP(rec, req)

	if !called {
		t.Fatalf("handler should be invoked when token is empty (dev bypass)")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
}

func TestBearerAuth_RejectsMissingHeader(t *testing.T) {
	t.Parallel()
	mw := BearerAuth("super-secret-token-XXXX")
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("handler must NOT be invoked")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/_admin/v1/blocklist/credstuff", strings.NewReader(""))
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestBearerAuth_RejectsWrongScheme(t *testing.T) {
	t.Parallel()
	mw := BearerAuth("super-secret-token-XXXX")
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("handler must NOT be invoked")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_admin/v1/mitigations/connections", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestBearerAuth_RejectsWrongToken(t *testing.T) {
	t.Parallel()
	mw := BearerAuth("super-secret-token-XXXX")
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("handler must NOT be invoked")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_admin/v1/mitigations/connections", nil)
	req.Header.Set("Authorization", "Bearer wrong-token-of-same-length-YY")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestBearerAuth_AcceptsCorrectToken(t *testing.T) {
	t.Parallel()
	const tok = "super-secret-token-XXXX"
	mw := BearerAuth(tok)
	called := false
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_admin/v1/mitigations/connections", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(rec, req)

	if !called {
		t.Fatalf("handler must be invoked with correct token")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestBearerAuth_PublicRoutesAlwaysOpen(t *testing.T) {
	t.Parallel()
	mw := BearerAuth("super-secret-token-XXXX")

	publics := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/_admin/v1/health"},
		{http.MethodGet, "/_admin/v1/metrics"},
	}
	for _, tc := range publics {
		tc := tc
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			t.Parallel()
			called := false
			h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			}))
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, nil)
			h.ServeHTTP(rec, req)
			if !called {
				t.Fatalf("public route %s %s must be reachable without token", tc.method, tc.path)
			}
		})
	}
}

func TestBearerAuth_RejectsTokenOfDifferentLength(t *testing.T) {
	// Garantit que subtle.ConstantTimeCompare gère la différence de
	// longueur sans paniquer ni leaker l'info via timing observable.
	t.Parallel()
	mw := BearerAuth("super-secret-token-XXXX")
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("handler must NOT be invoked")
	}))

	for _, presented := range []string{"x", "Bearer x", "Bearer wrong", strings.Repeat("a", 1024)} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/_admin/v1/mitigations/connections", nil)
		req.Header.Set("Authorization", presented)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("payload %q: expected 401, got %d", presented, rec.Code)
		}
	}
}
