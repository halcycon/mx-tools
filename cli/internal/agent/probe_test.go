package agent

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func signedProbe(t *testing.T, secret, body string, ts time.Time) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/probe", strings.NewReader(body))
	unix := strconv.FormatInt(ts.Unix(), 10)
	req.Header.Set("x-mx-timestamp", unix)
	req.Header.Set("x-mx-signature", SignProbe(secret, unix, http.MethodPost, "/api/v1/probe", []byte(body)))
	return req
}

// Same vector as test/report-full.spec.ts (Worker signer).
func TestSignProbeVector(t *testing.T) {
	got := SignProbe("shh", "1700000000", "POST", "/api/v1/probe", []byte(`{"domain":"example.com","mode":"quick"}`))
	if want := "c1eaedb319036c3f6b4a305b8ea560541957a3833b66e07f1cc99b4ad68bef85"; got != want {
		t.Fatalf("got %s", got)
	}
}

func TestProbeHMAC(t *testing.T) {
	s := &server{token: "tok", hmacSecret: "shh"}
	now := time.Now()
	body := []byte(`{"domain":"example.com"}`)

	if !s.verifyProbeAuth(signedProbe(t, "shh", string(body), now), body, now) {
		t.Fatal("valid signature rejected")
	}
	if s.verifyProbeAuth(signedProbe(t, "shh", string(body), now), body, now) {
		t.Fatal("replayed signature accepted")
	}
	if s.verifyProbeAuth(signedProbe(t, "wrong", string(body), now.Add(time.Second)), body, now) {
		t.Fatal("wrong secret accepted")
	}
	if s.verifyProbeAuth(signedProbe(t, "shh", string(body), now.Add(-10*time.Minute)), body, now) {
		t.Fatal("stale timestamp accepted")
	}
	tampered := []byte(`{"domain":"evil.com"}`)
	if s.verifyProbeAuth(signedProbe(t, "shh", string(body), now.Add(2*time.Second)), tampered, now) {
		t.Fatal("tampered body accepted")
	}

	bearer := httptest.NewRequest(http.MethodPost, "/api/v1/probe", nil)
	bearer.Header.Set("Authorization", "Bearer tok")
	if s.verifyProbeAuth(bearer, nil, now) {
		t.Fatal("bearer accepted while HMAC is required")
	}
	if !(&server{token: "tok"}).verifyProbeAuth(bearer, nil, now) {
		t.Fatal("bearer rejected when no HMAC secret is configured")
	}
}

func TestProbeRejectsBadInput(t *testing.T) {
	s := &server{token: "tok"}
	for _, body := range []string{`{"domain":"10.0.0.1"}`, `{"domain":"localhost"}`, `not json`} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/probe", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		rr := httptest.NewRecorder()
		s.handleProbe(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d", body, rr.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/probe", strings.NewReader(`{"domain":"example.com"}`))
	rr := httptest.NewRecorder()
	s.handleProbe(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", rr.Code)
	}
}
