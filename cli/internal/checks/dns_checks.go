package checks

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func lookup(name string, qtype uint16) ([]dns.RR, error) {
	c := new(dns.Client)
	c.Timeout = 5 * time.Second
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	r, _, err := c.Exchange(m, "1.1.1.1:53")
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("rcode %s", dns.RcodeToString[r.Rcode])
	}
	return r.Answer, nil
}

func resolveIPs(host string) []string {
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}
	}
	var out []string
	if ans, err := lookup(host, dns.TypeA); err == nil {
		for _, rr := range ans {
			if a, ok := rr.(*dns.A); ok {
				out = append(out, a.A.String())
			}
		}
	}
	if ans, err := lookup(host, dns.TypeAAAA); err == nil {
		for _, rr := range ans {
			if a, ok := rr.(*dns.AAAA); ok {
				out = append(out, a.AAAA.String())
			}
		}
	}
	return out
}

func reverseIPv4(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
}

func RunA(target string) Result {
	start := time.Now()
	ans, err := lookup(target, dns.TypeA)
	if err != nil {
		return Base("a", "A Record", target, []Row{{Status: StatusError, Name: "Error", Value: err.Error()}}, "Failed", start, false)
	}
	var rows []Row
	for _, rr := range ans {
		if a, ok := rr.(*dns.A); ok {
			rows = append(rows, Row{Status: StatusOK, Name: a.Hdr.Name, Value: a.A.String(), Info: fmt.Sprintf("TTL %d", a.Hdr.Ttl)})
		}
	}
	sum := "No A records"
	if len(rows) > 0 {
		sum = fmt.Sprintf("%d A record(s)", len(rows))
	}
	return Base("a", "A Record", target, rows, sum, start, len(rows) > 0)
}

func RunAAAA(target string) Result {
	start := time.Now()
	ans, err := lookup(target, dns.TypeAAAA)
	if err != nil {
		return Base("aaaa", "AAAA Record", target, []Row{{Status: StatusError, Name: "Error", Value: err.Error()}}, "Failed", start, false)
	}
	var rows []Row
	for _, rr := range ans {
		if a, ok := rr.(*dns.AAAA); ok {
			rows = append(rows, Row{Status: StatusOK, Name: a.Hdr.Name, Value: a.AAAA.String(), Info: fmt.Sprintf("TTL %d", a.Hdr.Ttl)})
		}
	}
	sum := "No AAAA records"
	if len(rows) > 0 {
		sum = fmt.Sprintf("%d AAAA record(s)", len(rows))
	}
	return Base("aaaa", "AAAA Record", target, rows, sum, start, len(rows) > 0)
}

func RunCNAME(target string) Result {
	start := time.Now()
	ans, err := lookup(target, dns.TypeCNAME)
	if err != nil {
		return Base("cname", "CNAME Record", target, []Row{{Status: StatusError, Name: "Error", Value: err.Error()}}, "Failed", start, false)
	}
	var rows []Row
	for _, rr := range ans {
		if c, ok := rr.(*dns.CNAME); ok {
			rows = append(rows, Row{Status: StatusOK, Name: c.Hdr.Name, Value: strings.TrimSuffix(c.Target, ".")})
		}
	}
	sum := "No CNAME"
	ok := len(rows) > 0
	if ok {
		sum = rows[0].Value
	}
	return Base("cname", "CNAME Record", target, rows, sum, start, ok)
}

func RunMX(target string) Result {
	start := time.Now()
	ans, err := lookup(target, dns.TypeMX)
	if err != nil {
		return Base("mx", "MX Lookup", target, []Row{{Status: StatusError, Name: "Error", Value: err.Error()}}, "Failed", start, false)
	}
	type mx struct {
		pref uint16
		host string
	}
	var list []mx
	for _, rr := range ans {
		if m, ok := rr.(*dns.MX); ok {
			list = append(list, mx{m.Preference, strings.TrimSuffix(m.Mx, ".")})
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].pref < list[j].pref })
	var rows []Row
	var related []Related
	for _, m := range list {
		if m.host == "" || m.host == "." {
			rows = append(rows, Row{Status: StatusInfo, Name: fmt.Sprintf("Preference %d", m.pref), Value: "(null MX)", Info: "Explicitly no mail service"})
			continue
		}
		ips := resolveIPs(m.host)
		st := StatusOK
		info := "IP: " + strings.Join(ips, ", ")
		if len(ips) == 0 {
			st = StatusWarn
			info = "No A/AAAA"
		}
		rows = append(rows, Row{Status: st, Name: fmt.Sprintf("Preference %d", m.pref), Value: m.host, Info: info})
		related = append(related,
			Related{Tool: "smtp", Label: "SMTP " + m.host, Query: "smtp:" + m.host},
			Related{Tool: "blacklist", Label: "Blacklist " + m.host, Query: "blacklist:" + m.host},
		)
	}
	sum := "No MX records"
	if len(rows) > 0 {
		sum = fmt.Sprintf("%d mail server(s)", len(rows))
	}
	r := Base("mx", "MX Lookup", target, rows, sum, start, len(rows) > 0)
	r.Related = related
	return r
}

func RunNS(target string) Result {
	start := time.Now()
	ans, err := lookup(target, dns.TypeNS)
	if err != nil {
		return Base("ns", "NS Records", target, []Row{{Status: StatusError, Name: "Error", Value: err.Error()}}, "Failed", start, false)
	}
	var rows []Row
	for _, rr := range ans {
		if n, ok := rr.(*dns.NS); ok {
			rows = append(rows, Row{Status: StatusOK, Name: "NS", Value: strings.TrimSuffix(n.Ns, ".")})
		}
	}
	sum := "No NS"
	if len(rows) > 0 {
		sum = fmt.Sprintf("%d nameserver(s)", len(rows))
	}
	return Base("ns", "NS Records", target, rows, sum, start, len(rows) > 0)
}

func RunPTR(target string) Result {
	start := time.Now()
	names, err := net.LookupAddr(target)
	if err != nil {
		return Base("ptr", "PTR Lookup", target, []Row{{Status: StatusFail, Name: "PTR", Value: err.Error()}}, "No PTR", start, false)
	}
	var rows []Row
	for _, n := range names {
		rows = append(rows, Row{Status: StatusOK, Name: target, Value: strings.TrimSuffix(n, ".")})
	}
	sum := "No PTR"
	if len(rows) > 0 {
		sum = rows[0].Value
	}
	return Base("ptr", "PTR Lookup", target, rows, sum, start, len(rows) > 0)
}

func RunSOA(target string) Result {
	start := time.Now()
	ans, err := lookup(target, dns.TypeSOA)
	if err != nil {
		return Base("soa", "SOA Record", target, []Row{{Status: StatusError, Name: "Error", Value: err.Error()}}, "Failed", start, false)
	}
	var rows []Row
	var serial string
	for _, rr := range ans {
		if s, ok := rr.(*dns.SOA); ok {
			rows = append(rows,
				Row{Status: StatusOK, Name: "Primary NS", Value: strings.TrimSuffix(s.Ns, ".")},
				Row{Status: StatusOK, Name: "Admin", Value: strings.TrimSuffix(s.Mbox, ".")},
				Row{Status: StatusOK, Name: "Serial", Value: fmt.Sprintf("%d", s.Serial)},
				Row{Status: StatusOK, Name: "Refresh", Value: fmt.Sprintf("%d", s.Refresh)},
				Row{Status: StatusOK, Name: "Retry", Value: fmt.Sprintf("%d", s.Retry)},
				Row{Status: StatusOK, Name: "Expire", Value: fmt.Sprintf("%d", s.Expire)},
				Row{Status: StatusOK, Name: "Minimum", Value: fmt.Sprintf("%d", s.Minttl)},
			)
			serial = fmt.Sprintf("%d", s.Serial)
		}
	}
	sum := "No SOA"
	if serial != "" {
		sum = "Serial " + serial
	}
	return Base("soa", "SOA Record", target, rows, sum, start, len(rows) > 0)
}

func RunTXT(target string) Result {
	start := time.Now()
	ans, err := lookup(target, dns.TypeTXT)
	if err != nil {
		return Base("txt", "TXT Records", target, []Row{{Status: StatusError, Name: "Error", Value: err.Error()}}, "Failed", start, false)
	}
	var rows []Row
	for _, rr := range ans {
		if t, ok := rr.(*dns.TXT); ok {
			rows = append(rows, Row{Status: StatusOK, Name: t.Hdr.Name, Value: strings.Join(t.Txt, "")})
		}
	}
	sum := "No TXT"
	if len(rows) > 0 {
		sum = fmt.Sprintf("%d TXT record(s)", len(rows))
	}
	return Base("txt", "TXT Records", target, rows, sum, start, len(rows) > 0)
}

func txtValues(name string) []string {
	ans, err := lookup(name, dns.TypeTXT)
	if err != nil {
		return nil
	}
	var out []string
	for _, rr := range ans {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out
}

func RunSPF(target string) Result {
	start := time.Now()
	var spf []string
	for _, v := range txtValues(target) {
		if strings.HasPrefix(strings.ToLower(v), "v=spf1") {
			spf = append(spf, v)
		}
	}
	var rows []Row
	for _, v := range spf {
		st := StatusInfo
		switch {
		case strings.Contains(strings.ToLower(v), "+all"):
			st = StatusFail
		case strings.Contains(strings.ToLower(v), "~all"):
			st = StatusWarn
		case strings.Contains(strings.ToLower(v), "-all"):
			st = StatusOK
		}
		rows = append(rows, Row{Status: st, Name: "SPF", Value: v})
	}
	if len(spf) > 1 {
		rows = append(rows, Row{Status: StatusFail, Name: "Policy", Value: "Multiple SPF records (invalid)"})
	}
	if len(spf) == 0 {
		rows = append(rows, Row{Status: StatusFail, Name: "SPF", Value: "Not found"})
	}
	sum := "Missing SPF"
	if len(spf) > 0 {
		sum = spf[0]
	}
	return Base("spf", "SPF Record", target, rows, sum, start, len(spf) == 1)
}

func RunDMARC(target string) Result {
	start := time.Now()
	vals := txtValues("_dmarc." + strings.TrimSuffix(target, "."))
	var records []string
	for _, v := range vals {
		if strings.Contains(strings.ToUpper(v), "V=DMARC1") {
			records = append(records, v)
		}
	}
	if len(records) == 0 {
		return Base("dmarc", "DMARC Record", target, []Row{{Status: StatusFail, Name: "DMARC", Value: "Not found"}}, "Missing DMARC", start, false)
	}
	rec := records[0]
	rows := []Row{{Status: StatusOK, Name: "Record", Value: rec}}
	policy := "?"
	for _, part := range strings.Split(rec, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "p=") {
			policy = strings.TrimSpace(part[2:])
		}
	}
	st := StatusInfo
	switch strings.ToLower(policy) {
	case "none":
		st = StatusWarn
	case "reject":
		st = StatusOK
	}
	rows = append(rows, Row{Status: st, Name: "Policy (p)", Value: policy})
	return Base("dmarc", "DMARC Record", target, rows, "p="+policy, start, true)
}

func RunDKIM(target, selector string) Result {
	start := time.Now()
	if selector == "" {
		selector = "default"
	}
	name := selector + "._domainkey." + strings.TrimSuffix(target, ".")
	vals := txtValues(name)
	var rows []Row
	for _, v := range vals {
		rows = append(rows, Row{Status: StatusOK, Name: name, Value: v})
	}
	if len(rows) == 0 {
		rows = append(rows, Row{Status: StatusFail, Name: selector, Value: "No DKIM key found"})
	}
	sum := "Missing"
	if len(vals) > 0 {
		sum = "Found"
	}
	return Base("dkim", "DKIM Record", selector+":"+target, rows, sum, start, len(vals) > 0)
}

func RunBIMI(target string) Result {
	start := time.Now()
	vals := txtValues("default._bimi." + strings.TrimSuffix(target, "."))
	var rows []Row
	found := false
	for _, v := range vals {
		if strings.Contains(strings.ToUpper(v), "V=BIMI1") {
			rows = append(rows, Row{Status: StatusOK, Name: "BIMI", Value: v})
			found = true
		}
	}
	if !found {
		rows = append(rows, Row{Status: StatusInfo, Name: "BIMI", Value: "Not found (optional)"})
	}
	sum := "No BIMI"
	if found {
		sum = rows[0].Value
	}
	return Base("bimi", "BIMI Record", target, rows, sum, start, found)
}

func RunTLSRPT(target string) Result {
	start := time.Now()
	vals := txtValues("_smtp._tls." + strings.TrimSuffix(target, "."))
	var rows []Row
	found := false
	for _, v := range vals {
		if strings.Contains(strings.ToUpper(v), "V=TLSRPTV1") {
			rows = append(rows, Row{Status: StatusOK, Name: "TLSRPT", Value: v})
			found = true
		}
	}
	if !found {
		rows = append(rows, Row{Status: StatusInfo, Name: "TLSRPT", Value: "Not found"})
	}
	sum := "No TLSRPT"
	if found {
		sum = rows[0].Value
	}
	return Base("tlsrpt", "TLSRPT Record", target, rows, sum, start, found)
}
