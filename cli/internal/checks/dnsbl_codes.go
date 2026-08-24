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
	"127.0.0.4":  "XBL/CBL — exploited/compromised host",
	"127.0.0.5":  "XBL — reserved listing code",
	"127.0.0.6":  "XBL — reserved listing code",
	"127.0.0.7":  "XBL — reserved listing code",
	"127.0.0.9":  "SBL DROP / hijacked",
	"127.0.0.10": "PBL — ISP dynamic/end-user",
	"127.0.0.11": "PBL — ISP dynamic/end-user",
	"127.0.0.30": "BCL — botnet controller",
}

var cblListed = map[string]string{
	"127.0.0.2": "CBL — exploited host",
	"127.0.0.4": "CBL/XBL — exploited host",
}

var sorbsListed = map[string]string{
	"127.0.0.2":  "HTTP",
	"127.0.0.3":  "SOCKS",
	"127.0.0.4":  "MISC",
	"127.0.0.5":  "SMTP",
	"127.0.0.6":  "WEB",
	"127.0.0.7":  "BLOCK",
	"127.0.0.8":  "ZOMBIE",
	"127.0.0.9":  "DUL (dynamic)",
	"127.0.0.10": "BADCONF",
	"127.0.0.11": "NOSERVER",
}

var queryErrors = map[string]string{
	"127.255.255.252": "Malformed DNSBL zone name.",
	"127.255.255.254": "Blocked as an anonymous/open-resolver query. Public resolvers cannot use Spamhaus public mirrors. Set SPAMHAUS_DQS_KEY for a private DQS query. This is not a listing.",
	"127.255.255.255": "Excessive queries — rate limited. Not a listing.",
}

const listingNotError = "This is a listing return code (127.0.0.0/24), not a query error. Query errors are only 127.255.255.0/24."

func listingMap(zone string) map[string]string {
	z := strings.ToLower(zone)
	switch {
	case strings.Contains(z, "spamhaus"):
		return spamhausListed
	case strings.Contains(z, "abuseat"), strings.Contains(z, "cbl."):
		return cblListed
	case strings.Contains(z, "sorbs"):
		return sorbsListed
	default:
		return nil
	}
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
	mp := listingMap(zone)
	labels := make([]string, 0, len(answers))
	for _, a := range answers {
		if mp != nil {
			if name, ok := mp[a]; ok {
				labels = append(labels, a+" ("+name+")")
				continue
			}
		}
		labels = append(labels, a)
	}
	detail := "Present on this DNSBL. " + listingNotError
	if mp != nil {
		if name, ok := mp[answers[0]]; ok {
			detail = name + ". " + listingNotError
		}
	}
	return DnsblInterp{Kind: DnsblListed, Status: StatusFail, Label: "LISTED " + strings.Join(labels, ", "), Detail: detail}
}

func SpamhausZone() (zone, name string) {
	key := strings.TrimSpace(os.Getenv("SPAMHAUS_DQS_KEY"))
	if key != "" {
		return key + ".zen.dq.spamhaus.net", "Spamhaus ZEN (DQS)"
	}
	return "zen.spamhaus.org", "Spamhaus ZEN"
}
