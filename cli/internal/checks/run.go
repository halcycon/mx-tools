package checks

func Run(q ParsedQuery) []Result {
	switch q.Tool {
	case "auto":
		return []Result{
			RunMX(q.Target),
			RunSPF(q.Target),
			RunDMARC(q.Target),
			RunBlacklist(q.Target),
			RunSOA(q.Target),
		}
	case "full":
		return []Result{
			RunMX(q.Target),
			RunSPF(q.Target),
			RunSPFFlat(q.Target),
			RunDMARC(q.Target),
			RunDKIM(q.Target, "default"),
			RunBlacklist(q.Target),
			RunSOA(q.Target),
			RunTXT(q.Target),
			RunNS(q.Target),
			RunBIMI(q.Target),
			RunMTASTS(q.Target),
			RunTLSRPT(q.Target),
			RunDNSHealth(q.Target),
			RunHTTP(q.Target, true),
			RunWhois(q.Target),
			RunASN(q.Target),
			RunARIN(q.Target),
		}
	case "a":
		return []Result{RunA(q.Target)}
	case "aaaa":
		return []Result{RunAAAA(q.Target)}
	case "cname":
		return []Result{RunCNAME(q.Target)}
	case "mx":
		return []Result{RunMX(q.Target)}
	case "ns":
		return []Result{RunNS(q.Target)}
	case "ptr":
		return []Result{RunPTR(q.Target)}
	case "soa":
		return []Result{RunSOA(q.Target)}
	case "txt":
		return []Result{RunTXT(q.Target)}
	case "spf":
		return []Result{RunSPF(q.Target)}
	case "spf-flat":
		return []Result{RunSPFFlat(q.Target)}
	case "dmarc":
		return []Result{RunDMARC(q.Target)}
	case "dkim":
		return []Result{RunDKIM(q.Target, q.Extra)}
	case "bimi":
		return []Result{RunBIMI(q.Target)}
	case "mta-sts":
		return []Result{RunMTASTS(q.Target)}
	case "tlsrpt":
		return []Result{RunTLSRPT(q.Target)}
	case "blacklist":
		return []Result{RunBlacklist(q.Target)}
	case "dns":
		return []Result{RunDNSHealth(q.Target)}
	case "whois":
		return []Result{RunWhois(q.Target)}
	case "arin":
		return []Result{RunARIN(q.Target)}
	case "asn":
		return []Result{RunASN(q.Target)}
	case "http":
		return []Result{RunHTTP(q.Target, false)}
	case "https":
		return []Result{RunHTTP(q.Target, true)}
	case "tcp":
		return []Result{RunTCP(q.Target, q.Extra)}
	case "smtp":
		return []Result{RunSMTP(q.Target, q.Extra)}
	case "headers":
		return RunHeaders(q.Target)
	case "ping":
		return []Result{RunPing(q.Target)}
	case "trace":
		return []Result{RunTrace(q.Target)}
	default:
		return []Result{{
			Tool:    q.Tool,
			Title:   "Unknown",
			Query:   q.Target,
			OK:      false,
			Summary: "Unknown tool: " + q.Tool,
		}}
	}
}
