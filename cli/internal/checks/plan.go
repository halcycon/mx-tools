package checks

// Planned returns the check names that Run will execute for a query.
func Planned(q ParsedQuery) []string {
	switch q.Tool {
	case "auto":
		return []string{"mx", "spf", "dmarc", "blacklist", "soa"}
	case "full":
		return []string{
			"mx", "spf", "spf-flat", "dmarc", "dkim", "blacklist", "soa",
			"txt", "ns", "bimi", "mta-sts", "tlsrpt", "dns", "https", "whois", "asn", "arin",
		}
	case "headers":
		return []string{"headers"}
	default:
		return []string{q.Tool}
	}
}

// RunEach runs checks one at a time and calls fn for each result (for SSE agents).
func RunEach(q ParsedQuery, fn func(Result)) {
	switch q.Tool {
	case "auto":
		fn(RunMX(q.Target))
		fn(RunSPF(q.Target))
		fn(RunDMARC(q.Target))
		fn(RunBlacklist(q.Target))
		fn(RunSOA(q.Target))
	case "full":
		fn(RunMX(q.Target))
		fn(RunSPF(q.Target))
		fn(RunSPFFlat(q.Target))
		fn(RunDMARC(q.Target))
		fn(RunDKIM(q.Target, "default"))
		fn(RunBlacklist(q.Target))
		fn(RunSOA(q.Target))
		fn(RunTXT(q.Target))
		fn(RunNS(q.Target))
		fn(RunBIMI(q.Target))
		fn(RunMTASTS(q.Target))
		fn(RunTLSRPT(q.Target))
		fn(RunDNSHealth(q.Target))
		fn(RunHTTP(q.Target, true))
		fn(RunWhois(q.Target))
		fn(RunASN(q.Target))
		fn(RunARIN(q.Target))
	case "headers":
		for _, r := range RunHeaders(q.Target) {
			fn(r)
		}
	default:
		for _, r := range Run(q) {
			fn(r)
		}
	}
}
