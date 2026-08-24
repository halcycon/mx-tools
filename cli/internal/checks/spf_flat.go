package checks

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type spfTerm struct {
	raw, qual, mech, arg string
}

func parseSpfTerms(record string) []spfTerm {
	body := strings.TrimSpace(record)
	if strings.HasPrefix(strings.ToLower(record), "v=spf1") {
		body = strings.TrimSpace(record[6:])
	}
	if body == "" {
		return nil
	}
	var out []spfTerm
	for _, raw := range strings.Fields(body) {
		rest := raw
		qual := "+"
		if rest != "" && strings.ContainsRune("+?-~", rune(rest[0])) {
			qual = rest[:1]
			rest = rest[1:]
		}
		lower := strings.ToLower(rest)
		term := spfTerm{raw: raw, qual: qual, mech: lower, arg: ""}
		switch {
		case strings.HasPrefix(lower, "redirect="):
			term.mech = "redirect"
			term.arg = rest[len("redirect="):]
		case strings.HasPrefix(lower, "exp="):
			term.mech = "exp"
			term.arg = rest[len("exp="):]
		default:
			if i := strings.IndexByte(rest, ':'); i >= 0 {
				term.mech = strings.ToLower(rest[:i])
				term.arg = rest[i+1:]
			} else {
				term.mech = lower
			}
		}
		out = append(out, term)
	}
	return out
}

type flattenState struct {
	lookups int
	ips     []string
	kept    []string
	notes   []Row
	seen    map[string]bool
}

func spfTXT(domain string) string {
	for _, v := range txtValues(domain) {
		if strings.HasPrefix(strings.ToLower(v), "v=spf1") {
			return v
		}
	}
	return ""
}

func hostIPTerms(host string) []string {
	var out []string
	if ans, err := lookup(host, dns.TypeA); err == nil {
		for _, rr := range ans {
			if a, ok := rr.(*dns.A); ok {
				out = append(out, "ip4:"+a.A.String())
			}
		}
	}
	if ans, err := lookup(host, dns.TypeAAAA); err == nil {
		for _, rr := range ans {
			if a, ok := rr.(*dns.AAAA); ok {
				out = append(out, "ip6:"+a.AAAA.String())
			}
		}
	}
	return out
}

func lookupMech(mech string) bool {
	switch mech {
	case "include", "a", "mx", "ptr", "exists", "redirect":
		return true
	}
	return false
}

func flattenDomain(domain string, state *flattenState, depth int) string {
	key := strings.ToLower(strings.TrimSuffix(domain, "."))
	if state.seen[key] {
		state.notes = append(state.notes, Row{Status: StatusWarn, Name: "Loop", Value: "Already visited " + key})
		return ""
	}
	if depth > 10 {
		state.notes = append(state.notes, Row{Status: StatusFail, Name: "Depth", Value: "Too much nesting at " + key})
		return ""
	}
	state.seen[key] = true
	rec := spfTXT(key)
	if rec == "" {
		state.notes = append(state.notes, Row{Status: StatusFail, Name: "Missing", Value: "No SPF at " + key})
		return ""
	}
	state.notes = append(state.notes, Row{Status: StatusInfo, Name: key, Value: rec})

	allQual := "?all"
	for _, term := range parseSpfTerms(rec) {
		if term.mech == "all" {
			q := term.qual
			if q == "+" {
				q = "+"
			}
			allQual = q + "all"
			continue
		}
		if term.mech == "exp" {
			continue
		}
		if lookupMech(term.mech) {
			state.lookups++
		}
		if term.mech == "ip4" || term.mech == "ip6" {
			q := ""
			if term.qual != "+" {
				q = term.qual
			}
			state.ips = append(state.ips, q+term.mech+":"+term.arg)
			continue
		}
		if term.mech == "include" {
			flattenDomain(term.arg, state, depth+1)
			continue
		}
		if term.mech == "redirect" {
			if nested := flattenDomain(term.arg, state, depth+1); nested != "" {
				allQual = nested
			}
			continue
		}
		q := ""
		if term.qual != "+" {
			q = term.qual
		}
		if term.mech == "a" {
			host := term.arg
			cidr := ""
			if host == "" {
				host = key
			}
			if i := strings.LastIndexByte(host, '/'); i > 0 {
				tail := host[i+1:]
				ok := true
				for _, c := range tail {
					if c < '0' || c > '9' {
						ok = false
						break
					}
				}
				if ok {
					cidr = host[i:]
					host = host[:i]
				}
			}
			for _, ip := range hostIPTerms(host) {
				if cidr != "" {
					state.ips = append(state.ips, q+ip+cidr)
				} else {
					state.ips = append(state.ips, q+ip)
				}
			}
			continue
		}
		if term.mech == "mx" {
			host := term.arg
			if host == "" {
				host = key
			}
			ans, err := lookup(host, dns.TypeMX)
			if err == nil {
				for _, rr := range ans {
					mx, ok := rr.(*dns.MX)
					if !ok {
						continue
					}
					mxHost := strings.TrimSuffix(mx.Mx, ".")
					if mxHost == "" || mxHost == "." {
						continue
					}
					state.lookups++
					for _, ip := range hostIPTerms(mxHost) {
						state.ips = append(state.ips, q+ip)
					}
				}
			}
			continue
		}
		if term.mech == "ptr" || term.mech == "exists" || strings.Contains(term.raw, "%{") {
			state.kept = append(state.kept, term.raw)
			state.notes = append(state.notes, Row{
				Status: StatusWarn,
				Name:   "Cannot flatten",
				Value:  term.raw,
				Info:   "ptr/exists/macros still need DNS at evaluation time",
			})
			continue
		}
		state.kept = append(state.kept, term.raw)
	}
	return allQual
}

func uniqStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func RunSPFFlat(target string) Result {
	start := time.Now()
	domain := strings.TrimSuffix(target, ".")
	state := &flattenState{seen: map[string]bool{}}
	allQual := flattenDomain(domain, state, 0)
	if allQual == "" {
		allQual = "?all"
	}
	ips := uniqStrings(state.ips)
	kept := uniqStrings(state.kept)
	parts := append([]string{"v=spf1"}, ips...)
	parts = append(parts, kept...)
	parts = append(parts, allQual)
	flat := strings.Join(parts, " ")

	lookStatus := StatusOK
	if state.lookups > 10 {
		lookStatus = StatusFail
	} else if state.lookups > 7 {
		lookStatus = StatusWarn
	}
	lenStatus := StatusOK
	if len(flat) > 450 {
		lenStatus = StatusWarn
	}
	ipStatus := StatusOK
	if len(ips) == 0 {
		ipStatus = StatusWarn
	}
	rows := []Row{
		{Status: lookStatus, Name: "DNS lookups (orig.)", Value: fmt.Sprintf("%d", state.lookups), Info: "RFC 7208 limit is 10 mechanisms that cause DNS lookups"},
		{Status: ipStatus, Name: "Flattened IPs", Value: fmt.Sprintf("%d", len(ips))},
		{Status: lenStatus, Name: "Record length", Value: fmt.Sprintf("%d chars", len(flat))},
		{Status: StatusOK, Name: "Flattened SPF", Value: flat},
	}
	rows = append(rows, state.notes...)
	sum := fmt.Sprintf("Flattened %d CIDR/IP term(s), %d orig. lookups", len(ips), state.lookups)
	ok := state.lookups <= 10 && (len(ips) > 0 || len(kept) > 0)
	if state.lookups > 10 {
		sum = fmt.Sprintf("Over lookup budget (%d/10)", state.lookups)
	}
	r := Base("spf-flat", "SPF Flattening", domain, rows, sum, start, ok)
	r.Related = []Related{{Tool: "spf", Label: "Original SPF", Query: "spf:" + domain}}
	return r
}
