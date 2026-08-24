package checks

import (
	"fmt"
	"net"
	"strings"
)

var ToolIDs = map[string]bool{
	"auto": true, "full": true, "a": true, "aaaa": true, "cname": true, "mx": true, "ns": true,
	"ptr": true, "soa": true, "txt": true, "spf": true, "dmarc": true, "dkim": true,
	"bimi": true, "mta-sts": true, "tlsrpt": true, "blacklist": true, "blocklist": true,
	"dns": true, "whois": true, "arin": true, "asn": true, "http": true, "https": true,
	"tcp": true, "smtp": true, "ping": true, "trace": true,
}

func ParseQuery(raw string) (ParsedQuery, error) {
	input := strings.TrimSpace(raw)
	if input == "" {
		return ParsedQuery{}, fmt.Errorf("empty query")
	}
	if i := strings.IndexByte(input, ':'); i > 0 && i < 16 {
		tool := strings.ToLower(strings.TrimSpace(input[:i]))
		rest := strings.TrimSpace(input[i+1:])
		if ToolIDs[tool] {
			if tool == "blocklist" {
				tool = "blacklist"
			}
			if tool == "dkim" {
				parts := strings.SplitN(rest, ":", 2)
				if len(parts) == 2 {
					return ParsedQuery{Tool: tool, Extra: parts[0], Target: parts[1]}, nil
				}
			}
			if tool == "tcp" {
				host, port, err := net.SplitHostPort(rest)
				if err == nil {
					return ParsedQuery{Tool: tool, Target: host, Extra: port}, nil
				}
				// host:port without brackets for ipv4
				if j := strings.LastIndexByte(rest, ':'); j > 0 {
					return ParsedQuery{Tool: tool, Target: rest[:j], Extra: rest[j+1:]}, nil
				}
			}
			return ParsedQuery{Tool: tool, Target: rest}, nil
		}
	}
	return ParsedQuery{Tool: "auto", Target: input}, nil
}
