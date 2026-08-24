package checks

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var DNSBLs = []struct {
	Zone string
	Name string
}{
	{"zen.spamhaus.org", "Spamhaus ZEN"},
	{"bl.spamcop.net", "SpamCop"},
	{"b.barracudacentral.org", "Barracuda"},
	{"dnsbl.sorbs.net", "SORBS"},
	{"spam.dnsbl.sorbs.net", "SORBS Spam"},
	{"psbl.surriel.com", "PSBL"},
	{"dnsbl.dronebl.org", "DroneBL"},
	{"rbl.interserver.net", "InterServer"},
	{"dnsbl-1.uceprotect.net", "UCEPROTECT L1"},
	{"cbl.abuseat.org", "CBL Abuseat"},
	{"dyna.spamrats.com", "SpamRats Dyna"},
	{"noptr.spamrats.com", "SpamRats NoPTR"},
	{"spam.spamrats.com", "SpamRats Spam"},
	{"z.mailspike.net", "Mailspike Z"},
	{"bl.mailspike.net", "Mailspike BL"},
	{"db.wpbl.info", "WPBL"},
	{"dnsbl.spfbl.net", "SPFBL"},
	{"all.s5h.net", "S5H"},
	{"bl.blocklist.de", "Blocklist.de"},
	{"list.dnswl.org", "DNSWL (whitelist)"},
	{"combined.abuse.ro", "Abuse.ro"},
}

func RunBlacklist(target string) Result {
	start := time.Now()
	var web []string
	var mx []struct {
		host string
		ips  []string
	}
	if net.ParseIP(target) != nil {
		web = []string{target}
	} else {
		web = resolveIPs(target)
		ans, _ := lookup(target, dns.TypeMX)
		type mxPref struct {
			pref uint16
			host string
		}
		var hosts []mxPref
		for _, rr := range ans {
			if m, ok := rr.(*dns.MX); ok {
				h := strings.TrimSuffix(m.Mx, ".")
				if h != "" && h != "." {
					hosts = append(hosts, mxPref{pref: m.Preference, host: h})
				}
			}
		}
		sort.Slice(hosts, func(i, j int) bool { return hosts[i].pref < hosts[j].pref })
		if len(hosts) > 3 {
			hosts = hosts[:3]
		}
		for _, h := range hosts {
			mx = append(mx, struct {
				host string
				ips  []string
			}{host: h.host, ips: resolveIPs(h.host)})
		}
	}
	check, skipped := selectBlacklistIPs(web, mx)
	if len(check) == 0 && len(skipped) == 0 {
		return Base("blacklist", "Blacklist Check", target, []Row{{Status: StatusError, Name: "Resolve", Value: "No IPs"}}, "Cannot resolve", start, false)
	}

	lists := make([]struct{ Zone, Name string }, len(DNSBLs))
	copy(lists, DNSBLs)
	sz, sn := SpamhausZone()
	for i := range lists {
		if strings.Contains(lists[i].Zone, "spamhaus") {
			lists[i].Zone = sz
			lists[i].Name = sn
		}
	}

	var rows []Row
	if len(check) > 0 {
		parts := make([]string, 0, len(check))
		for _, a := range check {
			parts = append(parts, a.ip+" ("+a.role+")")
		}
		info := ""
		if len(mx) > 0 {
			info = "Mail reputation uses MX host IPs. Website A records that are Cloudflare proxies are skipped."
		}
		if len(skipped) > 0 {
			skipIps := make([]string, 0, len(skipped))
			for _, a := range skipped {
				skipIps = append(skipIps, a.ip)
			}
			info = "Also skipped website CDN edge " + strings.Join(skipIps, ", ") + " — orange-cloud anycast, not mail origin."
		}
		rows = append(rows, Row{Status: StatusInfo, Name: "DNSBL targets", Value: strings.Join(parts, ", "), Info: info})
	}
	for _, a := range skipped {
		rows = append(rows, Row{
			Status: StatusInfo,
			Name:   "Website A (" + a.ip + ")",
			Value:  "Cloudflare CDN — not a DNSBL target",
			Info:   "Orange-cloud / anycast proxy. DNSBL rows below are MX (mail) IPs, not this address.",
		})
	}

	listed := 0
	queryErrors := 0
	for _, addr := range check {
		rev := reverseIPv4(addr.ip)
		if rev == "" {
			continue
		}
		for _, bl := range lists {
			q := rev + "." + bl.Zone
			ans, err := lookup(q, dns.TypeA)
			var answers []string
			if err == nil {
				for _, rr := range ans {
					if a, ok := rr.(*dns.A); ok {
						answers = append(answers, a.A.String())
					}
				}
			}
			isWL := strings.Contains(bl.Zone, "dnswl")
			interp := InterpretDnsbl(bl.Zone, answers, isWL)
			if interp.Kind == DnsblListed {
				listed++
			}
			if interp.Kind == DnsblQueryError {
				queryErrors++
			}
			rows = append(rows, Row{
				Status: interp.Status,
				Name:   fmt.Sprintf("%s (%s)", bl.Name, addr.ip),
				Value:  interp.Label,
				Info:   addr.role + ". " + interp.Detail,
			})
		}
	}
	sum := fmt.Sprintf("Clean on %d lists", len(lists))
	if listed > 0 {
		sum = fmt.Sprintf("Listed on %d list(s)", listed)
	} else if queryErrors > 0 {
		sum = fmt.Sprintf("No listings; %d list(s) returned query errors", queryErrors)
	}
	return Base("blacklist", "Blacklist Check", target, rows, sum, start, listed == 0)
}

func RunDNSHealth(target string) Result {
	start := time.Now()
	ans, _ := lookup(target, dns.TypeNS)
	var ns []string
	for _, rr := range ans {
		if n, ok := rr.(*dns.NS); ok {
			ns = append(ns, strings.TrimSuffix(n.Ns, "."))
		}
	}
	var rows []Row
	if len(ns) < 2 {
		rows = append(rows, Row{Status: StatusWarn, Name: "NS count", Value: strconv.Itoa(len(ns)), Info: "Prefer ≥ 2"})
	} else {
		rows = append(rows, Row{Status: StatusOK, Name: "NS count", Value: strconv.Itoa(len(ns))})
	}
	for _, s := range ns {
		ips := resolveIPs(s)
		st := StatusOK
		val := strings.Join(ips, ", ")
		if len(ips) == 0 {
			st = StatusFail
			val = "unresolved"
		}
		rows = append(rows, Row{Status: st, Name: s, Value: val})
	}
	return Base("dns", "DNS Health", target, rows, fmt.Sprintf("%d NS", len(ns)), start, len(ns) >= 2)
}

func RunMTASTS(target string) Result {
	start := time.Now()
	domain := strings.TrimSuffix(target, ".")
	vals := txtValues("_mta-sts." + domain)
	var rows []Row
	found := false
	for _, v := range vals {
		if strings.Contains(strings.ToUpper(v), "V=STSV1") {
			rows = append(rows, Row{Status: StatusOK, Name: "DNS", Value: v})
			found = true
		}
	}
	if !found {
		rows = append(rows, Row{Status: StatusInfo, Name: "DNS", Value: "No MTA-STS TXT"})
	}
	url := "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
	client := &http.Client{Timeout: 8 * time.Second}
	res, err := client.Get(url)
	if err != nil {
		rows = append(rows, Row{Status: StatusWarn, Name: "Policy fetch", Value: err.Error()})
	} else {
		defer res.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		st := StatusWarn
		if res.StatusCode == 200 {
			st = StatusOK
		}
		rows = append(rows, Row{Status: st, Name: "Policy URL", Value: url, Info: res.Status})
		for i, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || i > 11 {
				continue
			}
			rows = append(rows, Row{Status: StatusInfo, Name: "Policy", Value: line})
		}
	}
	sum := "No MTA-STS"
	if found {
		sum = rows[0].Value
	}
	return Base("mta-sts", "MTA-STS", target, rows, sum, start, found)
}

func RunHTTP(target string, secure bool) Result {
	start := time.Now()
	tool := "http"
	scheme := "http"
	title := "HTTP"
	if secure {
		tool = "https"
		scheme = "https"
		title = "HTTPS"
	}
	url := target
	if !strings.HasPrefix(strings.ToLower(url), "http://") && !strings.HasPrefix(strings.ToLower(url), "https://") {
		url = scheme + "://" + url
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return Base(tool, title, target, []Row{{Status: StatusError, Name: "Error", Value: err.Error()}}, "Failed", start, false)
	}
	req.Header.Set("User-Agent", "mx-tools/1.0")
	t0 := time.Now()
	res, err := client.Do(req)
	ms := time.Since(t0).Milliseconds()
	if err != nil {
		return Base(tool, title, target, []Row{{Status: StatusFail, Name: "Error", Value: err.Error()}}, "Failed", start, false)
	}
	defer res.Body.Close()
	st := StatusWarn
	if res.StatusCode >= 200 && res.StatusCode < 400 {
		st = StatusOK
	}
	rows := []Row{
		{Status: st, Name: "Status", Value: strconv.Itoa(res.StatusCode)},
		{Status: StatusInfo, Name: "URL", Value: url},
		{Status: StatusInfo, Name: "Time", Value: fmt.Sprintf("%d ms", ms)},
	}
	if loc := res.Header.Get("Location"); loc != "" {
		rows = append(rows, Row{Status: StatusInfo, Name: "Location", Value: loc})
	}
	if srv := res.Header.Get("Server"); srv != "" {
		rows = append(rows, Row{Status: StatusInfo, Name: "Server", Value: srv})
	}
	return Base(tool, title, target, rows, fmt.Sprintf("HTTP %d", res.StatusCode), start, true)
}

func RunTCP(host, portStr string) Result {
	start := time.Now()
	if portStr == "" {
		portStr = "443"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return Base("tcp", "TCP Check", host+":"+portStr, []Row{{Status: StatusError, Name: "Port", Value: "Invalid"}}, "Bad port", start, false)
	}
	addr := net.JoinHostPort(host, portStr)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return Base("tcp", "TCP Check", addr, []Row{{Status: StatusFail, Name: "Connect", Value: err.Error()}}, "Closed/failed", start, false)
	}
	_ = conn.Close()
	return Base("tcp", "TCP Check", addr, []Row{{Status: StatusOK, Name: "Connect", Value: "Open " + addr}}, "Open", start, true)
}

func smtpReadReply(r *bufio.Reader) (int, string, error) {
	var lines []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return 0, strings.Join(lines, "\n"), err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 4 {
			continue
		}
		code, err := strconv.Atoi(line[:3])
		if err != nil {
			continue
		}
		lines = append(lines, strings.TrimSpace(line[4:]))
		if line[3] == ' ' {
			return code, strings.Join(lines, "\n"), nil
		}
	}
}

func ehloHas(text, token string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.EqualFold(strings.TrimSpace(line), token) {
			return true
		}
	}
	return false
}

func ehloAuth(text string) string {
	for _, line := range strings.Split(text, "\n") {
		u := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(u), "AUTH ") {
			return u[5:]
		}
	}
	return ""
}

func probeSMTPPort(host string, port int, implicitTLS bool, tryStartTLS bool) Row {
	name := fmt.Sprintf("TCP %d", port)
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: 8 * time.Second}
	var conn net.Conn
	var err error
	if implicitTLS {
		conn, err = tls.DialWithDialer(&dialer, "tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return Row{Status: StatusFail, Name: name, Value: err.Error(), Info: addr}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	br := bufio.NewReader(conn)
	code, greet, err := smtpReadReply(br)
	if err != nil {
		return Row{Status: StatusFail, Name: name, Value: err.Error(), Info: addr}
	}
	if _, err := fmt.Fprintf(conn, "EHLO dart.invalid\r\n"); err != nil {
		return Row{Status: StatusFail, Name: name, Value: err.Error()}
	}
	_, ehlo, err := smtpReadReply(br)
	if err != nil {
		return Row{Status: StatusWarn, Name: name, Value: fmt.Sprintf("%d banner, EHLO failed", code), Info: greet}
	}
	mode := "SMTP"
	if implicitTLS {
		mode = "SMTPS"
	}
	if tryStartTLS && ehloHas(ehlo, "STARTTLS") {
		if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err == nil {
			ready, _, rerr := smtpReadReply(br)
			if rerr == nil && ready == 220 {
				tlsConn := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
				if herr := tlsConn.Handshake(); herr != nil {
					return Row{Status: StatusFail, Name: name, Value: "STARTTLS handshake: " + herr.Error(), Info: addr}
				}
				conn = tlsConn
				_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
				br = bufio.NewReader(conn)
				if _, err := fmt.Fprintf(conn, "EHLO dart.invalid\r\n"); err == nil {
					_, ehlo, _ = smtpReadReply(br)
				}
				mode = "STARTTLS"
			}
		}
	} else if tryStartTLS && !ehloHas(ehlo, "STARTTLS") {
		_, _ = fmt.Fprintf(conn, "QUIT\r\n")
		return Row{Status: StatusWarn, Name: name, Value: fmt.Sprintf("%d open, no STARTTLS", code), Info: greet}
	}
	_, _ = fmt.Fprintf(conn, "QUIT\r\n")
	info := greet
	if auth := ehloAuth(ehlo); auth != "" {
		info += " · AUTH " + auth
	}
	if ehloHas(ehlo, "STARTTLS") {
		info += " · STARTTLS"
	}
	st := StatusOK
	if code >= 400 {
		st = StatusFail
	}
	return Row{Status: st, Name: name, Value: fmt.Sprintf("%d %s", code, mode), Info: info}
}

func bestMX(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}
	ans, err := lookup(host, dns.TypeMX)
	if err != nil {
		return host
	}
	var best string
	var pref uint16 = 65535
	for _, rr := range ans {
		if m, ok := rr.(*dns.MX); ok && m.Preference <= pref {
			pref = m.Preference
			best = strings.TrimSuffix(m.Mx, ".")
		}
	}
	if best == "" {
		return host
	}
	return best
}

func RunSMTP(target, extra string) Result {
	start := time.Now()
	host := strings.TrimSuffix(target, ".")
	rows := []Row{}
	if extra != "" {
		port, err := strconv.Atoi(extra)
		if err != nil || port < 1 || port > 65535 {
			return Base("smtp", "SMTP Test", target, []Row{{Status: StatusError, Name: "Port", Value: "Invalid"}}, "Bad port", start, false)
		}
		h := host
		if port == 25 {
			h = bestMX(host)
			if h != host {
				rows = append(rows, Row{Status: StatusInfo, Name: "MX", Value: h})
			}
		}
		rows = append(rows, probeSMTPPort(h, port, port == 465, port == 587))
	} else {
		mx := bestMX(host)
		if mx != host {
			rows = append(rows, Row{Status: StatusInfo, Name: "MX (port 25)", Value: mx})
		}
		rows = append(rows, probeSMTPPort(mx, 25, false, false))
		rows = append(rows, probeSMTPPort(host, 587, false, true))
		rows = append(rows, probeSMTPPort(host, 465, true, false))
	}
	open := 0
	for _, r := range rows {
		if r.Status == StatusOK && strings.HasPrefix(r.Name, "TCP ") {
			open++
		}
	}
	sum := fmt.Sprintf("%d SMTP port(s) answered", open)
	ok := open > 0
	if !ok {
		sum = "No SMTP banner"
	}
	r := Base("smtp", "SMTP Test", target, rows, sum, start, ok)
	r.Related = []Related{
		{Tool: "mx", Label: "MX " + host, Query: "mx:" + host},
		{Tool: "tcp", Label: "TCP " + host + ":587", Query: "tcp:" + host + ":587"},
		{Tool: "tcp", Label: "TCP " + host + ":465", Query: "tcp:" + host + ":465"},
	}
	return r
}

func RunPing(target string) Result {
	start := time.Now()
	cmd := exec.Command("ping", "-c", "4", "-W", "2", target)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil && text == "" {
		return Base("ping", "Ping", target, []Row{{Status: StatusFail, Name: "ping", Value: err.Error()}}, "Failed", start, false)
	}
	lines := strings.Split(text, "\n")
	var rows []Row
	for _, line := range lines {
		rows = append(rows, Row{Status: StatusInfo, Name: "out", Value: line})
	}
	st := StatusOK
	if err != nil {
		st = StatusWarn
	}
	if len(rows) > 0 {
		rows[0].Status = st
	}
	return Base("ping", "Ping", target, rows, "ping complete", start, err == nil)
}

func RunTrace(target string) Result {
	start := time.Now()
	bin := "traceroute"
	if _, err := exec.LookPath(bin); err != nil {
		bin = "tracepath"
	}
	cmd := exec.Command(bin, "-n", target)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil && text == "" {
		return Base("trace", "Traceroute", target, []Row{{Status: StatusFail, Name: "trace", Value: err.Error()}}, "Failed", start, false)
	}
	var rows []Row
	for _, line := range strings.Split(text, "\n") {
		rows = append(rows, Row{Status: StatusInfo, Name: "hop", Value: line})
	}
	return Base("trace", "Traceroute", target, rows, "trace complete", start, true)
}

func RunWhois(target string) Result {
	start := time.Now()
	url := "https://rdap.org/domain/" + target
	return rdapGet("whois", "Domain RDAP", target, url, start)
}

func RunARIN(target string) Result {
	start := time.Now()
	ip := target
	if net.ParseIP(target) == nil {
		ips := resolveIPs(target)
		if len(ips) == 0 {
			return Base("arin", "IP RDAP", target, []Row{{Status: StatusError, Name: "IP", Value: "Unresolved"}}, "Failed", start, false)
		}
		ip = ips[0]
	}
	return rdapGet("arin", "IP RDAP", target, "https://rdap.org/ip/"+ip, start)
}

func RunASN(target string) Result {
	start := time.Now()
	ip := target
	if net.ParseIP(target) == nil {
		ips := resolveIPs(target)
		if len(ips) == 0 {
			return Base("asn", "ASN Lookup", target, []Row{{Status: StatusError, Name: "IP", Value: "Unresolved"}}, "Failed", start, false)
		}
		ip = ips[0]
	}
	if v4 := net.ParseIP(ip).To4(); v4 != nil {
		rev := reverseIPv4(ip)
		vals := txtValues(rev + ".origin.asn.cymru.com")
		var rows []Row
		for _, v := range vals {
			parts := strings.Split(v, "|")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			if len(parts) >= 3 {
				rows = append(rows, Row{
					Status: StatusOK,
					Name:   "AS" + parts[0],
					Value:  strings.Join(parts[1:], " "),
				})
			}
		}
		if len(rows) > 0 {
			return Base("asn", "ASN Lookup", target, rows, rows[0].Name, start, true)
		}
	}
	return RunARIN(ip)
}

func rdapGet(tool, title, query, url string, start time.Time) Result {
	client := &http.Client{Timeout: 12 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return Base(tool, title, query, []Row{{Status: StatusError, Name: "RDAP", Value: err.Error()}}, "Failed", start, false)
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	res, err := client.Do(req)
	if err != nil {
		return Base(tool, title, query, []Row{{Status: StatusError, Name: "RDAP", Value: err.Error()}}, "Failed", start, false)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 256*1024))
	if res.StatusCode >= 400 {
		return Base(tool, title, query, []Row{{Status: StatusFail, Name: "RDAP", Value: res.Status}}, "Failed", start, false)
	}
	// Lightweight field scrape without full JSON schema coupling
	text := string(body)
	var rows []Row
	for _, key := range []string{"ldhName", "name", "handle", "startAddress", "endAddress", "country"} {
		if v := jsonString(text, key); v != "" {
			rows = append(rows, Row{Status: StatusInfo, Name: key, Value: v})
		}
	}
	if len(rows) == 0 {
		rows = append(rows, Row{Status: StatusInfo, Name: "RDAP", Value: "Received response (see raw via whois CLI if needed)"})
	}
	sum := rows[0].Value
	return Base(tool, title, query, rows, sum, start, true)
}

func jsonString(raw, key string) string {
	needle := `"` + key + `"`
	i := strings.Index(raw, needle)
	if i < 0 {
		return ""
	}
	rest := raw[i+len(needle):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	rest = rest[j+1:]
	k := strings.Index(rest, `"`)
	if k < 0 {
		return ""
	}
	return rest[:k]
}
