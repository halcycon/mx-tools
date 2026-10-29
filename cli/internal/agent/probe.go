package agent

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"mxtools/internal/checks"
)

const (
	hmacMaxSkew  = 5 * time.Minute
	probeMaxBody = 4096
)

var domainRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// SignProbe returns the hex HMAC-SHA256 the Worker sends in x-mx-signature:
// HMAC(secret, "<unix ts>\n<METHOD>\n<path>\n<sha256 hex of body>").
func SignProbe(secret, ts, method, path string, body []byte) string {
	sum := sha256.Sum256(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "\n" + method + "\n" + path + "\n" + hex.EncodeToString(sum[:])))
	return hex.EncodeToString(mac.Sum(nil))
}

type replayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (c *replayCache) firstUse(sig string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]time.Time{}
	}
	for k, t := range c.seen {
		if now.Sub(t) > 2*hmacMaxSkew {
			delete(c.seen, k)
		}
	}
	if _, dup := c.seen[sig]; dup {
		return false
	}
	c.seen[sig] = now
	return true
}

// verifyProbeAuth accepts a valid HMAC signature when a secret is configured; otherwise the bearer token.
func (s *server) verifyProbeAuth(r *http.Request, body []byte, now time.Time) bool {
	if s.hmacSecret == "" {
		return hmac.Equal([]byte(bearerToken(r)), []byte(s.token))
	}
	ts := r.Header.Get("x-mx-timestamp")
	sig := strings.ToLower(strings.TrimSpace(r.Header.Get("x-mx-signature")))
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || sig == "" {
		return false
	}
	if d := now.Sub(time.Unix(unix, 0)); d > hmacMaxSkew || d < -hmacMaxSkew {
		return false
	}
	want := SignProbe(s.hmacSecret, ts, r.Method, r.URL.Path, body)
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return false
	}
	return s.replays.firstUse(sig, now)
}

func (s *server) handleProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, probeMaxBody+1))
	if err != nil || len(body) > probeMaxBody {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_request"})
		return
	}
	if !s.verifyProbeAuth(r, body, time.Now()) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var req struct {
		Domain string `json:"domain"`
		Mode   string `json:"mode"`
	}
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_request"})
		return
	}
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.Domain)), ".")
	if len(domain) > 253 || !domainRe.MatchString(domain) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_domain"})
		return
	}
	writeJSON(w, http.StatusOK, checks.Probe(domain, req.Mode))
}
