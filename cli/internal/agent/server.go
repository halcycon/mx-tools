package agent

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"mxtools/internal/checks"
)

type Config struct {
	Listen   string
	Token    string
	AllowLAN bool
}

func GenerateToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func Run(cfg Config) error {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8788"
	}
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return fmt.Errorf("invalid --listen %q: %w", cfg.Listen, err)
	}
	if !cfg.AllowLAN && host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return fmt.Errorf("refusing to bind %s without --allow-lan (default is loopback only)", cfg.Listen)
	}
	if strings.TrimSpace(cfg.Token) == "" {
		tok, err := GenerateToken()
		if err != nil {
			return err
		}
		cfg.Token = tok
		fmt.Fprintf(os.Stderr, "mx agent: generated token (save this):\n  %s\n\n", cfg.Token)
	}

	mux := http.NewServeMux()
	s := &server{token: cfg.Token}
	mux.HandleFunc("/api/health", s.cors(s.handleHealth))
	mux.HandleFunc("/api/config", s.cors(s.auth(s.handleConfig)))
	mux.HandleFunc("/api/tools", s.cors(s.auth(s.handleTools)))
	mux.HandleFunc("/api/lookup", s.cors(s.auth(s.handleLookup)))
	mux.HandleFunc("/api/headers", s.cors(s.auth(s.handleHeaders)))

	fmt.Fprintf(os.Stderr, "mx agent listening on http://%s\n", cfg.Listen)
	fmt.Fprintf(os.Stderr, "  Auth: Authorization: Bearer <token>  or  x-agent-token: <token>\n")
	if key := strings.TrimSpace(os.Getenv("SPAMHAUS_DQS_KEY")); key != "" {
		fmt.Fprintf(os.Stderr, "  Spamhaus DQS: configured via SPAMHAUS_DQS_KEY\n")
	} else {
		fmt.Fprintf(os.Stderr, "  Spamhaus DQS: not set (local recursive DNS may still work for public mirrors)\n")
	}
	fmt.Fprintf(os.Stderr, "  Point the web UI Settings → Probe agent at this URL + token.\n")

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

type server struct {
	token string
}

func (s *server) cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "content-type, accept, authorization, x-agent-token, x-spamhaus-dqs-key")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func (s *server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := bearerToken(r)
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized — set Authorization: Bearer <token>"})
			return
		}
		next(w, r)
	}
}

func bearerToken(r *http.Request) string {
	if t := strings.TrimSpace(r.Header.Get("x-agent-token")); t != "" {
		return t
	}
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"service": "mx-tools-agent",
		"mode":    "agent",
	})
}

func (s *server) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"spamhausDqsConfigured": strings.TrimSpace(os.Getenv("SPAMHAUS_DQS_KEY")) != "",
		"agent":                 true,
		"platform":              "cli",
	})
}

func (s *server) handleTools(w http.ResponseWriter, r *http.Request) {
	tools := make([]map[string]string, 0, len(toolCatalog))
	for _, t := range toolCatalog {
		tools = append(tools, map[string]string{
			"id":          t.id,
			"label":       t.label,
			"description": t.description,
			"example":     t.example,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tools": tools})
}

func (s *server) handleLookup(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("q")
	if raw == "" {
		raw = r.URL.Query().Get("query")
	}
	if r.Method == http.MethodPost {
		var body struct {
			Q     string `json:"q"`
			Query string `json:"query"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
		if body.Q != "" {
			raw = body.Q
		} else if body.Query != "" {
			raw = body.Query
		}
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Missing q"})
		return
	}
	if len(raw) > 512 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Query too long"})
		return
	}

	parsed, err := checks.ParseQuery(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	stream := r.URL.Query().Get("stream") == "1" || strings.Contains(r.Header.Get("Accept"), "text/event-stream")
	if stream {
		s.streamLookup(w, raw, parsed)
		return
	}

	results := checks.Run(parsed)
	writeJSON(w, http.StatusOK, map[string]any{
		"query":   raw,
		"tool":    parsed.Tool,
		"target":  parsed.Target,
		"results": results,
	})
}

func (s *server) streamLookup(w http.ResponseWriter, raw string, parsed checks.ParsedQuery) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "streaming unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	planned := checks.Planned(parsed)
	sendSSE(w, flusher, "start", map[string]any{
		"query":    raw,
		"tool":     parsed.Tool,
		"target":   parsed.Target,
		"expected": len(planned),
		"checks":   planned,
		"agent":    true,
	})

	count := 0
	checks.RunEach(parsed, func(res checks.Result) {
		count++
		sendSSE(w, flusher, "result", res)
	})
	sendSSE(w, flusher, "done", map[string]any{"count": count})
}

func (s *server) handleHeaders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": `POST JSON { "raw": "<header block>" }`})
		return
	}
	var body struct {
		Raw string `json:"raw"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10+1024)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": checks.AnalyzeHeaders(body.Raw)})
}

func sendSSE(w http.ResponseWriter, flusher http.Flusher, event string, data any) {
	b, _ := json.Marshal(data)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
	flusher.Flush()
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(data)
}

type toolDef struct {
	id, label, description, example string
}

var toolCatalog = []toolDef{
	{"auto", "Domain health", "Quick live report: MX + SPF + DMARC + blacklist + SOA", "example.com"},
	{"full", "Email health report", "Deep live report including auth, DNS, HTTPS, RDAP", "full:example.com"},
	{"a", "A", "DNS A (IPv4)", "a:example.com"},
	{"aaaa", "AAAA", "DNS AAAA (IPv6)", "aaaa:example.com"},
	{"cname", "CNAME", "DNS CNAME", "cname:www.example.com"},
	{"mx", "MX", "Mail exchanger records", "mx:example.com"},
	{"ns", "NS", "Name server records", "ns:example.com"},
	{"ptr", "PTR", "Reverse DNS", "ptr:1.2.3.4"},
	{"soa", "SOA", "Start of Authority", "soa:example.com"},
	{"txt", "TXT", "TXT records", "txt:example.com"},
	{"spf", "SPF", "Sender Policy Framework", "spf:example.com"},
	{"spf-flat", "SPF flatten", "Expand SPF includes", "spf-flat:example.com"},
	{"dmarc", "DMARC", "DMARC policy", "dmarc:example.com"},
	{"dkim", "DKIM", "DKIM key (selector:domain)", "dkim:default:example.com"},
	{"bimi", "BIMI", "BIMI record", "bimi:example.com"},
	{"mta-sts", "MTA-STS", "MTA-STS policy", "mta-sts:example.com"},
	{"tlsrpt", "TLSRPT", "TLS reporting", "tlsrpt:example.com"},
	{"headers", "Header analyzer", "Parse pasted RFC 5322 headers", "headers"},
	{"blacklist", "Blacklist", "DNSBL reputation (local DNS)", "blacklist:1.2.3.4"},
	{"dns", "DNS health", "Nameserver sanity", "dns:example.com"},
	{"whois", "WHOIS/RDAP", "Domain registration", "whois:example.com"},
	{"arin", "ARIN/RDAP", "IP network registration", "arin:1.2.3.4"},
	{"asn", "ASN", "Autonomous system", "asn:1.2.3.4"},
	{"http", "HTTP", "HTTP connectivity", "http:example.com"},
	{"https", "HTTPS", "HTTPS connectivity", "https:example.com"},
	{"tcp", "TCP", "TCP connect", "tcp:example.com:443"},
	{"smtp", "SMTP", "SMTP banner (25/587/465)", "smtp:smtp.gmail.com"},
	{"ping", "Ping", "ICMP echo", "ping:example.com"},
	{"trace", "Traceroute", "ICMP traceroute", "trace:example.com"},
}
