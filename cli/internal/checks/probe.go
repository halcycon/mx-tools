package checks

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Structured probe used by the Worker's health check / full report (POST /api/v1/probe on `mx agent`).
// The Worker maps these raw facts to stable codes; nothing here is user-facing wording.

type ProbeAddr struct {
	IP   string `json:"ip"`
	Role string `json:"role"`
}

type ProbeDNSBLHit struct {
	List    string   `json:"list"`
	Zone    string   `json:"zone"` // public zone name; never contains a DQS key
	IP      string   `json:"ip"`
	Role    string   `json:"role"`
	Answers []string `json:"answers"`
	Rcode   *int     `json:"rcode"`
	Error   string   `json:"error,omitempty"`
}

type ProbeDNSBL struct {
	DQS       bool            `json:"dqs"`
	Checked   []ProbeAddr     `json:"checked"`
	Skipped   []ProbeAddr     `json:"skipped"`
	MX        []ProbeMXHost   `json:"mx"`
	ListCount int             `json:"listCount"`
	Hits      []ProbeDNSBLHit `json:"hits"`
}

type ProbeMXHost struct {
	Host string   `json:"host"`
	IPs  []string `json:"ips"`
}

type ProbePTR struct {
	IP      string   `json:"ip"`
	Role    string   `json:"role"`
	PTR     []string `json:"ptr"`
	Forward []string `json:"forward"`
	FCrDNS  bool     `json:"fcrdns"`
	Error   string   `json:"error,omitempty"`
}

type ProbeCert struct {
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	DNSNames      []string  `json:"dnsNames"`
	NotBefore     time.Time `json:"notBefore"`
	NotAfter      time.Time `json:"notAfter"`
	Verified      bool      `json:"verified"`
	VerifyError   string    `json:"verifyError,omitempty"`
	HostnameMatch bool      `json:"hostnameMatch"`
}

type ProbeSMTP struct {
	Host       string     `json:"host"`
	Port       int        `json:"port"`
	Mode       string     `json:"mode"` // "starttls" (25/587) or "implicit" (465)
	Role       string     `json:"role"` // "mx" or "submission"
	Connected  bool       `json:"connected"`
	BannerCode int        `json:"bannerCode"`
	Banner     string     `json:"banner"`
	StartTLS   bool       `json:"startTls"` // advertised in EHLO
	TLS        bool       `json:"tls"`      // handshake completed
	TLSVersion string     `json:"tlsVersion,omitempty"`
	Cert       *ProbeCert `json:"cert,omitempty"`
	Error      string     `json:"error,omitempty"`
	ElapsedMs  int64      `json:"elapsedMs"`
}

type ProbeResult struct {
	Domain     string      `json:"domain"`
	Mode       string      `json:"mode"`
	Resolver   string      `json:"resolver"`
	DNSBL      ProbeDNSBL  `json:"dnsbl"`
	PTR        []ProbePTR  `json:"ptr,omitempty"`
	SMTP       []ProbeSMTP `json:"smtp,omitempty"`
	SMTPEgress *bool       `json:"smtpEgress,omitempty"` // can this host open outbound :25 at all?
	ElapsedMs  int64       `json:"elapsedMs"`
}

func exchangeRcode(name string, qtype uint16) ([]string, *int, error) {
	r, err := exchange(name, qtype)
	if err != nil {
		return nil, nil, err
	}
	rc := r.Rcode
	var out []string
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok {
			out = append(out, a.A.String())
		}
	}
	return out, &rc, nil
}

func mxHosts(domain string, max int) []ProbeMXHost {
	ans, _ := lookup(domain, dns.TypeMX)
	type pref struct {
		p    uint16
		host string
	}
	var hosts []pref
	for _, rr := range ans {
		if m, ok := rr.(*dns.MX); ok {
			h := strings.TrimSuffix(m.Mx, ".")
			if h != "" && h != "." {
				hosts = append(hosts, pref{m.Preference, h})
			}
		}
	}
	sort.SliceStable(hosts, func(i, j int) bool { return hosts[i].p < hosts[j].p })
	if len(hosts) > max {
		hosts = hosts[:max]
	}
	out := make([]ProbeMXHost, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			out[i] = ProbeMXHost{Host: host, IPs: resolveIPs(host)}
		}(i, h.host)
	}
	wg.Wait()
	return out
}

// ProbeBlacklist queries every DNSBL for the domain's MX (and non-CDN web) IPs.
func ProbeBlacklist(domain string, mx []ProbeMXHost) ProbeDNSBL {
	var web []string
	for _, ip := range resolveIPs(domain) {
		if IsPublicIP(ip) {
			web = append(web, ip)
		}
	}
	in := make([]struct {
		host string
		ips  []string
	}, len(mx))
	for i, m := range mx {
		in[i].host, in[i].ips = m.Host, m.IPs
	}
	check, skipped := selectBlacklistIPs(web, in)

	sz, sn := SpamhausZone()
	type list struct{ zone, query, name string }
	lists := make([]list, 0, len(DNSBLs))
	for _, bl := range DNSBLs {
		if strings.Contains(bl.Zone, "spamhaus") {
			lists = append(lists, list{zone: bl.Zone, query: sz, name: sn})
		} else {
			lists = append(lists, list{zone: bl.Zone, query: bl.Zone, name: bl.Name})
		}
	}

	res := ProbeDNSBL{DQS: strings.Contains(sz, "dq.spamhaus.net"), MX: mx, ListCount: len(lists)}
	for _, a := range check {
		res.Checked = append(res.Checked, ProbeAddr{IP: a.ip, Role: a.role})
	}
	for _, a := range skipped {
		res.Skipped = append(res.Skipped, ProbeAddr{IP: a.ip, Role: a.role})
	}

	type job struct {
		addr blacklistAddr
		rev  string
		bl   list
	}
	var jobs []job
	for _, a := range check {
		if rev := reverseIPv4(a.ip); rev != "" {
			for _, bl := range lists {
				jobs = append(jobs, job{a, rev, bl})
			}
		}
	}
	res.Hits = make([]ProbeDNSBLHit, len(jobs))
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, j job) {
			defer wg.Done()
			defer func() { <-sem }()
			answers, rc, err := exchangeRcode(j.rev+"."+j.bl.query, dns.TypeA)
			hit := ProbeDNSBLHit{List: j.bl.name, Zone: j.bl.zone, IP: j.addr.ip, Role: j.addr.role, Answers: answers, Rcode: rc}
			if hit.Answers == nil {
				hit.Answers = []string{}
			}
			if err != nil {
				hit.Error = "lookup failed"
			}
			res.Hits[i] = hit
		}(i, j)
	}
	wg.Wait()
	return res
}

func reverseName(ip string) string {
	name, err := dns.ReverseAddr(ip)
	if err != nil {
		return ""
	}
	return name
}

// ProbePTRs checks reverse DNS and forward-confirmed reverse DNS for each MX IP.
func ProbePTRs(mx []ProbeMXHost, max int) []ProbePTR {
	var addrs []ProbeAddr
	seen := map[string]bool{}
	for _, m := range mx {
		for _, ip := range m.IPs {
			if !seen[ip] && len(addrs) < max {
				seen[ip] = true
				addrs = append(addrs, ProbeAddr{IP: ip, Role: "MX " + m.Host})
			}
		}
	}
	out := make([]ProbePTR, len(addrs))
	var wg sync.WaitGroup
	for i, a := range addrs {
		wg.Add(1)
		go func(i int, a ProbeAddr) {
			defer wg.Done()
			p := ProbePTR{IP: a.IP, Role: a.Role, PTR: []string{}, Forward: []string{}}
			rev := reverseName(a.IP)
			ans, err := lookup(rev, dns.TypePTR)
			if rev == "" || err != nil {
				p.Error = "lookup failed"
				out[i] = p
				return
			}
			for _, rr := range ans {
				if ptr, ok := rr.(*dns.PTR); ok {
					p.PTR = append(p.PTR, strings.TrimSuffix(ptr.Ptr, "."))
				}
			}
			for _, host := range p.PTR {
				for _, ip := range resolveIPs(host) {
					p.Forward = append(p.Forward, ip)
					if net.ParseIP(ip).Equal(net.ParseIP(a.IP)) {
						p.FCrDNS = true
					}
				}
			}
			out[i] = p
		}(i, a)
	}
	wg.Wait()
	return out
}

func certFacts(state tls.ConnectionState, host string) *ProbeCert {
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	leaf := state.PeerCertificates[0]
	c := &ProbeCert{
		Subject:   leaf.Subject.CommonName,
		Issuer:    leaf.Issuer.CommonName,
		DNSNames:  leaf.DNSNames,
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
	}
	if c.DNSNames == nil {
		c.DNSNames = []string{}
	}
	c.HostnameMatch = leaf.VerifyHostname(host) == nil
	inter := x509.NewCertPool()
	for _, ic := range state.PeerCertificates[1:] {
		inter.AddCert(ic)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter}); err != nil {
		c.VerifyError = err.Error()
	} else {
		c.Verified = true
	}
	return c
}

var tlsVersionNames = map[uint16]string{
	tls.VersionTLS10: "TLS1.0",
	tls.VersionTLS11: "TLS1.1",
	tls.VersionTLS12: "TLS1.2",
	tls.VersionTLS13: "TLS1.3",
}

// ProbeSMTPHost connects, reads the banner, EHLOs, and (for 25/587) upgrades with STARTTLS.
// Certificates are captured even when invalid so the Worker can report why.
func ProbeSMTPHost(host string, port int, role string) (p ProbeSMTP) {
	start := time.Now()
	implicit := port == 465
	p = ProbeSMTP{Host: host, Port: port, Role: role, Mode: "starttls"}
	if implicit {
		p.Mode = "implicit"
	}
	defer func() { p.ElapsedMs = time.Since(start).Milliseconds() }()

	ip := firstPublicIP(resolveIPs(host))
	if ip == "" {
		p.Error = "no public address"
		return p
	}
	tlsConf := &tls.Config{ServerName: host, InsecureSkipVerify: true} //nolint:gosec // verified manually in certFacts
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: 8 * time.Second}
	var conn net.Conn
	var err error
	if implicit {
		conn, err = tls.DialWithDialer(&dialer, "tcp", addr, tlsConf)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		p.Error = err.Error()
		return p
	}
	defer conn.Close()
	p.Connected = true
	if implicit {
		tc := conn.(*tls.Conn)
		st := tc.ConnectionState()
		p.TLS, p.TLSVersion, p.Cert = true, tlsVersionNames[st.Version], certFacts(st, host)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	code, greet, err := smtpReadReply(br)
	p.BannerCode, p.Banner = code, firstLine(greet)
	if err != nil {
		p.Error = "banner: " + err.Error()
		return p
	}
	if _, err := fmt.Fprintf(conn, "EHLO dart.invalid\r\n"); err != nil {
		p.Error = err.Error()
		return p
	}
	_, ehlo, err := smtpReadReply(br)
	if err != nil {
		p.Error = "ehlo: " + err.Error()
		return p
	}
	p.StartTLS = ehloHas(ehlo, "STARTTLS")
	if !implicit && p.StartTLS {
		if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err == nil {
			ready, _, rerr := smtpReadReply(br)
			if rerr == nil && ready == 220 {
				tc := tls.Client(conn, tlsConf)
				if herr := tc.Handshake(); herr != nil {
					p.Error = "starttls handshake: " + herr.Error()
					return p
				}
				st := tc.ConnectionState()
				p.TLS, p.TLSVersion, p.Cert = true, tlsVersionNames[st.Version], certFacts(st, host)
				conn = tc
			}
		}
	}
	_, _ = fmt.Fprintf(conn, "QUIT\r\n")
	return p
}

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// IsPublicIP rejects loopback, private, CGNAT, link-local, multicast and unspecified addresses,
// so a hostile MX record cannot point the agent at its own network.
func IsPublicIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || cgnat.Contains(ip))
}

func firstPublicIP(ips []string) string {
	for _, ip := range ips {
		if IsPublicIP(ip) {
			return ip
		}
	}
	return ""
}

func publicOnly(mx []ProbeMXHost) []ProbeMXHost {
	out := make([]ProbeMXHost, len(mx))
	for i, m := range mx {
		out[i] = ProbeMXHost{Host: m.Host, IPs: []string{}}
		for _, ip := range m.IPs {
			if IsPublicIP(ip) {
				out[i].IPs = append(out[i].IPs, ip)
			}
		}
	}
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// submissionHosts finds the domain's own submission service: RFC 6186 SRV, then smtp./mail. names that resolve.
func submissionHosts(domain string) []string {
	var out []string
	for _, srv := range []string{"_submissions._tcp.", "_submission._tcp."} {
		ans, _ := lookup(srv+domain, dns.TypeSRV)
		for _, rr := range ans {
			if s, ok := rr.(*dns.SRV); ok {
				if t := strings.TrimSuffix(s.Target, "."); t != "" && t != "." {
					out = append(out, t)
				}
			}
		}
	}
	if len(out) == 0 {
		for _, h := range []string{"smtp." + domain, "mail." + domain} {
			if len(resolveIPs(h)) > 0 {
				out = append(out, h)
				break
			}
		}
	}
	return uniqStrings(out)
}

var (
	egressMu      sync.Mutex
	egressChecked time.Time
	egressOK      bool
)

// SMTPEgress reports whether this host can open outbound TCP :25 at all (many VPS providers block it).
func SMTPEgress() bool {
	egressMu.Lock()
	defer egressMu.Unlock()
	if time.Since(egressChecked) < 10*time.Minute {
		return egressOK
	}
	egressOK = false
	for _, h := range []string{"gmail-smtp-in.l.google.com", "mx1.mail.icloud.com"} {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(h, "25"), 5*time.Second)
		if err == nil {
			_ = c.Close()
			egressOK = true
			break
		}
	}
	egressChecked = time.Now()
	return egressOK
}

// Probe runs the agent-side checks. mode "quick" = DNSBL only; "full" adds PTR/FCrDNS and SMTP.
func Probe(domain, mode string) ProbeResult {
	start := time.Now()
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if mode != "full" {
		mode = "quick"
	}
	res := ProbeResult{Domain: domain, Mode: mode, Resolver: Resolver()}
	mx := publicOnly(mxHosts(domain, 3))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		res.DNSBL = ProbeBlacklist(domain, mx)
	}()
	if mode == "full" {
		wg.Add(2)
		go func() {
			defer wg.Done()
			res.PTR = ProbePTRs(mx, 6)
		}()
		go func() {
			defer wg.Done()
			egress := SMTPEgress()
			res.SMTP = probeAllSMTP(domain, mx, egress)
			res.SMTPEgress = &egress
		}()
	}
	wg.Wait()
	res.ElapsedMs = time.Since(start).Milliseconds()
	return res
}

func probeAllSMTP(domain string, mx []ProbeMXHost, egress bool) []ProbeSMTP {
	type target struct {
		host string
		port int
		role string
	}
	var targets []target
	if egress {
		for i, m := range mx {
			if i >= 2 {
				break
			}
			targets = append(targets, target{m.Host, 25, "mx"})
		}
	}
	for _, h := range submissionHosts(domain) {
		targets = append(targets, target{h, 587, "submission"}, target{h, 465, "submission"})
	}
	out := make([]ProbeSMTP, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t target) {
			defer wg.Done()
			out[i] = ProbeSMTPHost(t.host, t.port, t.role)
		}(i, t)
	}
	wg.Wait()
	return out
}
