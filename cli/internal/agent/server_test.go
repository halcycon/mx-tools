package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthUnauthenticated(t *testing.T) {
	s := &server{token: "secret-token"}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.cors(s.handleHealth))

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestLookupRequiresToken(t *testing.T) {
	s := &server{token: "secret-token"}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/lookup", s.cors(s.auth(s.handleLookup)))

	req := httptest.NewRequest(http.MethodGet, "/api/lookup?q=soa:example.com", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/lookup?q=soa:example.com", nil)
	req2.Header.Set("Authorization", "Bearer secret-token")
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr2.Code, rr2.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr2.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["tool"] != "soa" {
		t.Fatalf("tool=%v", body["tool"])
	}
}

func TestCORSPreflight(t *testing.T) {
	s := &server{token: "t"}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/lookup", s.cors(s.auth(s.handleLookup)))
	req := httptest.NewRequest(http.MethodOptions, "/api/lookup", nil)
	req.Header.Set("Origin", "https://example.com")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Access-Control-Allow-Headers"), "authorization") {
		t.Fatalf("headers=%v", rr.Header())
	}
}
