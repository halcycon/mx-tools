package checks

import (
	"fmt"
	"io"
	"net/mail"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const headerMaxBytes = 256 * 1024

type headerField struct {
	name, value string
}

func unfoldHeaders(raw string) []headerField {
	normalized := strings.ReplaceAll(strings.ReplaceAll(raw, "\r\n", "\n"), "\r", "\n")
	headerBlock := normalized
	if i := strings.Index(normalized, "\n\n"); i >= 0 {
		headerBlock = normalized[:i]
	}
	var fields []headerField
	for _, line := range strings.Split(headerBlock, "\n") {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') && len(fields) > 0 {
			fields[len(fields)-1].value += " " + strings.TrimSpace(line)
			continue
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			continue
		}
		fields = append(fields, headerField{name: strings.TrimSpace(line[:i]), value: strings.TrimSpace(line[i+1:])})
	}
	return fields
}

func headerAll(fields []headerField, name string) []string {
	n := strings.ToLower(name)
	var out []string
	for _, f := range fields {
		if strings.ToLower(f.name) == n {
			out = append(out, f.value)
		}
	}
	return out
}

func headerFirst(fields []headerField, name string) string {
	all := headerAll(fields, name)
	if len(all) == 0 {
		return ""
	}
	return all[0]
}

var emailAngle = regexp.MustCompile(`<([^>]+@[^>]+)>`)
var emailBare = regexp.MustCompile(`(?i)[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}`)

func emailsIn(value string) []string {
	ms := emailAngle.FindAllStringSubmatch(value, -1)
	if len(ms) > 0 {
		var out []string
		for _, m := range ms {
			out = append(out, strings.ToLower(m[1]))
		}
		return out
	}
	if m := emailBare.FindString(value); m != "" {
		return []string{strings.ToLower(m)}
	}
	return nil
}

func domainOfAddr(addr string) string {
	i := strings.LastIndexByte(addr, '@')
	if i < 0 {
		return addr
	}
	return addr[i+1:]
}

func parseHeaderDate(value string) time.Time {
	v := strings.TrimSpace(regexp.MustCompile(`\s+\([^)]+\)\s*$`).ReplaceAllString(value, ""))
	if t, err := mail.ParseDate(v); err == nil {
		return t
	}
	if t, err := mail.ParseDate(strings.TrimSpace(value)); err == nil {
		return t
	}
	return time.Time{}
}

var (
	reFromHop = regexp.MustCompile(`(?i)\bfrom\s+(\S+)`)
	reByHop   = regexp.MustCompile(`(?i)\bby\s+(\S+)`)
	reWith    = regexp.MustCompile(`(?i)\bwith\s+(\S+)`)
	reID      = regexp.MustCompile(`(?i)\bid\s+(\S+)`)
	reFor     = regexp.MustCompile(`(?i)\bfor\s+<?([^\s>;]+)>?`)
	reIPBrack = regexp.MustCompile(`\[([0-9a-fA-F:.]+)\]`)
	reIPv4    = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)
	reAuth    = regexp.MustCompile(`(?i)^(spf|dkim|dmarc|arc|compauth)\s*=\s*(\S+)`)
	reSpamSc  = regexp.MustCompile(`(?i)score\s*=\s*([-\d.]+)`)
	reDKIMD   = regexp.MustCompile(`(?i)(?:^|;)\s*d=([^;]+)`)
	reDKIMS   = regexp.MustCompile(`(?i)(?:^|;)\s*s=([^;]+)`)
	reDKIMA   = regexp.MustCompile(`(?i)(?:^|;)\s*a=([^;]+)`)
)

type hop struct {
	index   int
	from    string
	by      string
	with    string
	id      string
	forAddr string
	when    time.Time
	whenRaw string
	ip      string
	delay   time.Duration
	hasDelay bool
}

func parseReceived(value string) hop {
	datePart := ""
	body := value
	if i := strings.LastIndexByte(value, ';'); i >= 0 {
		datePart = strings.TrimSpace(value[i+1:])
		body = value[:i]
	}
	h := hop{whenRaw: datePart, when: parseHeaderDate(datePart)}
	if m := reFromHop.FindStringSubmatch(body); len(m) > 1 {
		h.from = m[1]
	}
	if m := reByHop.FindStringSubmatch(body); len(m) > 1 {
		h.by = m[1]
	}
	if m := reWith.FindStringSubmatch(body); len(m) > 1 {
		h.with = m[1]
	}
	if m := reID.FindStringSubmatch(body); len(m) > 1 {
		h.id = m[1]
	}
	if m := reFor.FindStringSubmatch(body); len(m) > 1 {
		h.forAddr = m[1]
	}
	if m := reIPBrack.FindStringSubmatch(body); len(m) > 1 {
		h.ip = m[1]
	} else if m := reIPv4.FindStringSubmatch(body); len(m) > 1 {
		h.ip = m[1]
	}
	return h
}

func formatDelay(d time.Duration) string {
	sign := ""
	if d < 0 {
		sign = "-"
		d = -d
	}
	if d < time.Second {
		return fmt.Sprintf("%s%dms", sign, d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%s%.1fs", sign, d.Seconds())
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%s%dm %ds", sign, m, s)
}

func delayStatus(d time.Duration, ok bool) Severity {
	if !ok {
		return StatusInfo
	}
	if d < 0 {
		return StatusWarn
	}
	if d > 10*time.Minute {
		return StatusFail
	}
	if d > time.Minute {
		return StatusWarn
	}
	return StatusOK
}

func authTone(result string) Severity {
	switch strings.ToLower(result) {
	case "pass":
		return StatusOK
	case "none", "neutral":
		return StatusInfo
	case "softfail", "temperror", "policy":
		return StatusWarn
	case "fail", "permerror", "hardfail":
		return StatusFail
	default:
		return StatusInfo
	}
}

func dkimMeta(value string) string {
	var parts []string
	if m := reDKIMD.FindStringSubmatch(value); len(m) > 1 {
		parts = append(parts, "d="+strings.TrimSpace(m[1]))
	}
	if m := reDKIMS.FindStringSubmatch(value); len(m) > 1 {
		parts = append(parts, "s="+strings.TrimSpace(m[1]))
	}
	if m := reDKIMA.FindStringSubmatch(value); len(m) > 1 {
		parts = append(parts, "a="+strings.TrimSpace(m[1]))
	}
	return strings.Join(parts, " ")
}

func parseSpamHeaders(fields []headerField) []Row {
	var rows []Row
	if status := headerFirst(fields, "X-Spam-Status"); status != "" {
		yes := strings.HasPrefix(strings.ToLower(strings.TrimSpace(status)), "yes")
		info := status
		if m := reSpamSc.FindStringSubmatch(status); len(m) > 1 {
			info = "score=" + m[1]
		}
		st := StatusOK
		val := "No"
		if yes {
			st = StatusFail
			val = "YES (flagged)"
		}
		rows = append(rows, Row{Status: st, Name: "X-Spam-Status", Value: val, Info: truncate(info, 180)})
	}
	if score := headerFirst(fields, "X-Spam-Score"); score != "" {
		n, _ := strconv.ParseFloat(score, 64)
		st := StatusOK
		if n >= 5 {
			st = StatusFail
		} else if n >= 2 {
			st = StatusWarn
		}
		rows = append(rows, Row{Status: st, Name: "X-Spam-Score", Value: score})
	}
	fore := headerFirst(fields, "X-Forefront-Antispam-Report")
	if fore == "" {
		fore = headerFirst(fields, "X-MS-Exchange-Organization-SCL")
	}
	if fore != "" {
		rows = append(rows, Row{Status: StatusInfo, Name: "Microsoft SCL", Value: truncate(fore, 80), Info: truncate(fore, 200)})
	}
	if flag := headerFirst(fields, "X-Spam-Flag"); flag != "" {
		st := StatusOK
		if strings.EqualFold(strings.TrimSpace(flag), "YES") {
			st = StatusFail
		}
		rows = append(rows, Row{Status: st, Name: "X-Spam-Flag", Value: flag})
	}
	return rows
}

func AnalyzeHeaders(raw string) []Result {
	start := time.Now()
	if strings.TrimSpace(raw) == "" {
		return []Result{Base("headers", "Email headers", "headers", nil, "Paste a header block first", start, false)}
	}
	if len(raw) > headerMaxBytes {
		return []Result{Base("headers", "Email headers", "headers", nil, fmt.Sprintf("Header too large (%d bytes)", len(raw)), start, false)}
	}
	fields := unfoldHeaders(raw)
	if len(fields) == 0 {
		return []Result{Base("headers", "Email headers", "headers", nil, "No RFC 5322 header fields found", start, false)}
	}

	from := headerFirst(fields, "From")
	to := headerFirst(fields, "To")
	subject := headerFirst(fields, "Subject")
	if subject == "" {
		subject = "(no subject)"
	}
	date := headerFirst(fields, "Date")
	mid := headerFirst(fields, "Message-ID")
	if mid == "" {
		mid = headerFirst(fields, "Message-Id")
	}
	rp := headerFirst(fields, "Return-Path")
	froms := emailsIn(from)
	rps := emailsIn(rp)
	fromAddr, rpAddr := "", ""
	if len(froms) > 0 {
		fromAddr = froms[0]
	}
	if len(rps) > 0 {
		rpAddr = rps[0]
	}

	sumRows := []Row{
		{Status: StatusInfo, Name: "Subject", Value: subject},
		{Status: StatusInfo, Name: "From", Value: orDash(from)},
		{Status: StatusInfo, Name: "To", Value: orDash(to)},
		{Status: dateStatus(date), Name: "Date", Value: orMissing(date)},
		{Status: dateStatus(mid), Name: "Message-ID", Value: orMissing(mid)},
		{Status: StatusInfo, Name: "Return-Path", Value: orDash(rp)},
	}
	if fromAddr != "" && rpAddr != "" && domainOfAddr(fromAddr) != domainOfAddr(rpAddr) {
		sumRows = append(sumRows, Row{
			Status: StatusWarn,
			Name:   "Envelope vs From",
			Value:  rpAddr + " vs " + fromAddr,
			Info:   "Return-Path domain differs from From (can be forwarding, or spoofing)",
		})
	}

	received := headerAll(fields, "Received")
	hops := make([]hop, 0, len(received))
	for i, v := range received {
		h := parseReceived(v)
		h.index = len(received) - i
		hops = append(hops, h)
	}
	for i := len(hops) - 1; i > 0; i-- {
		newer := hops[i-1]
		older := hops[i]
		if !newer.when.IsZero() && !older.when.IsZero() {
			hops[i-1].delay = newer.when.Sub(older.when)
			hops[i-1].hasDelay = true
		}
	}

	var hopRows []Row
	for _, h := range hops {
		parts := []string{}
		if h.from != "" {
			parts = append(parts, "from "+h.from)
		}
		if h.by != "" {
			parts = append(parts, "by "+h.by)
		}
		if h.with != "" {
			parts = append(parts, "with "+h.with)
		}
		val := strings.Join(parts, "  ")
		if val == "" {
			val = h.whenRaw
		}
		infoParts := []string{}
		if h.hasDelay {
			infoParts = append(infoParts, "delay "+formatDelay(h.delay))
		}
		if h.ip != "" {
			infoParts = append(infoParts, "ip "+h.ip)
		}
		if !h.when.IsZero() {
			infoParts = append(infoParts, h.when.UTC().Format(time.RFC3339))
		}
		if h.forAddr != "" {
			infoParts = append(infoParts, "for "+h.forAddr)
		}
		hopRows = append(hopRows, Row{
			Status: delayStatus(h.delay, h.hasDelay),
			Name:   fmt.Sprintf("Hop %d", h.index),
			Value:  val,
			Info:   strings.Join(infoParts, " · "),
		})
	}
	if len(hopRows) == 0 {
		hopRows = []Row{{Status: StatusWarn, Name: "Received", Value: "None"}}
	}

	var authRows []Row
	var authBits []string
	if spf := headerFirst(fields, "Received-SPF"); spf != "" {
		tok := strings.ToLower(strings.Fields(spf)[0])
		authRows = append(authRows, Row{Status: authTone(tok), Name: "Received-SPF", Value: tok, Info: truncate(spf, 200)})
		authBits = append(authBits, "Received-SPF "+tok)
	}
	for _, ar := range headerAll(fields, "Authentication-Results") {
		chunks := strings.Split(ar, ";")
		for _, chunk := range chunks[1:] {
			chunk = strings.TrimSpace(chunk)
			m := reAuth.FindStringSubmatch(chunk)
			if len(m) < 3 {
				continue
			}
			method := strings.ToLower(m[1])
			res := strings.ToLower(strings.TrimSuffix(m[2], ";"))
			authRows = append(authRows, Row{Status: authTone(res), Name: strings.ToUpper(method), Value: res, Info: truncate(chunk, 220)})
			authBits = append(authBits, method+"="+res)
		}
	}
	for _, sig := range headerAll(fields, "DKIM-Signature") {
		meta := dkimMeta(sig)
		if meta == "" {
			meta = "present"
		}
		authRows = append(authRows, Row{Status: StatusInfo, Name: "DKIM-Signature", Value: meta, Info: truncate(sig, 160)})
	}
	if len(authRows) == 0 {
		authRows = []Row{{Status: StatusWarn, Name: "Auth", Value: "No Authentication-Results or Received-SPF"}}
	}

	fromDomain := ""
	if fromAddr != "" {
		fromDomain = domainOfAddr(fromAddr)
	}
	var related []Related
	if fromDomain != "" {
		related = []Related{
			{Tool: "spf", Label: "SPF " + fromDomain, Query: "spf:" + fromDomain},
			{Tool: "dmarc", Label: "DMARC " + fromDomain, Query: "dmarc:" + fromDomain},
			{Tool: "mx", Label: "MX " + fromDomain, Query: "mx:" + fromDomain},
		}
	}
	for _, h := range hops {
		if reIPv4.MatchString(h.ip) && strings.Count(h.ip, ".") == 3 {
			related = append(related, Related{Tool: "blacklist", Label: "Blacklist " + h.ip, Query: "blacklist:" + h.ip})
			break
		}
	}

	failAuth := false
	for _, r := range authRows {
		if r.Status == StatusFail {
			failAuth = true
			break
		}
	}
	elapsed := time.Since(start)
	summary := Base("headers", "Email headers", subject, sumRows, fmt.Sprintf("%d hop(s) · %s", len(received), subject), start, from != "" && len(received) > 0)
	summary.Related = related
	summary.ElapsedMs = elapsed.Milliseconds()

	hopsRes := Base("headers-hops", "Delivery path", fmt.Sprintf("%d Received", len(received)), hopRows, fmt.Sprintf("%d hop(s), newest first", len(received)), start, len(received) > 0)
	hopsRes.ElapsedMs = elapsed.Milliseconds()

	authSum := "No auth headers"
	if len(authBits) > 0 {
		authSum = strings.Join(authBits, " · ")
	}
	q := fromDomain
	if q == "" {
		q = "headers"
	}
	authRes := Base("headers-auth", "Authentication results", q, authRows, authSum, start, !failAuth)
	authRes.Related = related
	authRes.ElapsedMs = elapsed.Milliseconds()

	out := []Result{summary, hopsRes, authRes}
	if spam := parseSpamHeaders(fields); len(spam) > 0 {
		ok := true
		var bits []string
		for _, r := range spam {
			if r.Status == StatusFail {
				ok = false
			}
			bits = append(bits, r.Name+" "+r.Value)
		}
		sp := Base("headers-spam", "Anti-spam headers", "headers", spam, strings.Join(bits, " · "), start, ok)
		sp.ElapsedMs = elapsed.Milliseconds()
		out = append(out, sp)
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func orMissing(s string) string {
	if s == "" {
		return "Missing"
	}
	return s
}

func dateStatus(s string) Severity {
	if s == "" {
		return StatusWarn
	}
	return StatusOK
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func readHeaderSource(target string) (string, error) {
	if target == "" || target == "-" {
		st, err := os.Stdin.Stat()
		if err != nil {
			return "", err
		}
		if st.Mode()&os.ModeCharDevice != 0 {
			return "", fmt.Errorf("pipe a header dump, or use headers:/path/to/file.eml")
		}
		b, err := io.ReadAll(io.LimitReader(os.Stdin, headerMaxBytes+1))
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	b, err := os.ReadFile(target)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func RunHeaders(target string) []Result {
	raw, err := readHeaderSource(target)
	if err != nil {
		return []Result{Base("headers", "Email headers", "headers", []Row{{Status: StatusError, Name: "Error", Value: err.Error()}}, err.Error(), time.Now(), false)}
	}
	return AnalyzeHeaders(raw)
}
