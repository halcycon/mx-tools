package checks

import (
	"os"
	"strings"
)

type DnsblKind string

const (
	DnsblClean      DnsblKind = "clean"
	DnsblListed     DnsblKind = "listed"
	DnsblWhitelist  DnsblKind = "whitelist"
	DnsblQueryError DnsblKind = "query_error"
)

type DnsblInterp struct {
	Kind   DnsblKind
	Status Severity
	Label  string
	Detail string
}

var spamhausListed = map[string]string{
	"127.0.0.2":  "SBL — spam source / snowshoe",
	"127.0.0.3":  "CSS — snowshoe / exploited",
	"127.0.0.4":  "XBL/CBL — exploited host",
	"127.0.0.9":  "SBL DROP / hijacked",
	"127.0.0.10": "PBL — ISP dynamic/end-user",
	"127.0.0.11": "PBL — ISP dynamic/end-user",
}

var queryErrors = map[string]string{
	"127.255.255.252": "Malformed DNSBL zone name.",
	"127.255.255.254": "Blocked as an anonymous/open-resolver query. Public resolvers cannot use Spamhaus public mirrors. Set SPAMHAUS_DQS_KEY for a private DQS query. This is not a listing.",
	"127.255.255.255": "Excessive queries — rate limited. Not a listing.",
}

func InterpretDnsbl(zone string, answers []string, whitelist bool) DnsblInterp {
	if len(answers) == 0 {
		return DnsblInterp{Kind: DnsblClean, Status: StatusOK, Label: "OK", Detail: "Not listed"}
	}
	for _, a := range answers {
		if detail, ok := queryErrors[a]; ok || strings.HasPrefix(a, "127.255.255.") {
			if !ok {
				detail = "DNSBL returned error code " + a + " (127.255.255.0/24). This is not a reputation listing."
			}
			if strings.Contains(zone, "spamhaus") {
				detail += " For private deploys, set SPAMHAUS_DQS_KEY so queries use {key}.zen.dq.spamhaus.net."
			}
			return DnsblInterp{Kind: DnsblQueryError, Status: StatusWarn, Label: "Query error " + a, Detail: detail}
		}
	}
	if whitelist {
		return DnsblInterp{Kind: DnsblWhitelist, Status: StatusOK, Label: "Listed (good) " + strings.Join(answers, ", "), Detail: "Present on a DNS whitelist."}
	}
	labels := make([]string, 0, len(answers))
	for _, a := range answers {
		if name, ok := spamhausListed[a]; ok && strings.Contains(zone, "spamhaus") {
			labels = append(labels, a+" ("+name+")")
		} else {
			labels = append(labels, a)
		}
	}
	return DnsblInterp{Kind: DnsblListed, Status: StatusFail, Label: "LISTED " + strings.Join(labels, ", "), Detail: "Present on this DNSBL."}
}

func SpamhausZone() (zone, name string) {
	key := strings.TrimSpace(os.Getenv("SPAMHAUS_DQS_KEY"))
	if key != "" {
		return key + ".zen.dq.spamhaus.net", "Spamhaus ZEN (DQS)"
	}
	return "zen.spamhaus.org", "Spamhaus ZEN"
}
