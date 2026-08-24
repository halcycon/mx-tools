package checks

import (
	"net"
	"strings"
)

// Published Cloudflare proxy ranges: https://www.cloudflare.com/ips-v4/
var cloudflareCIDRs = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

var cloudflareNets []*net.IPNet

func init() {
	for _, c := range cloudflareCIDRs {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			cloudflareNets = append(cloudflareNets, n)
		}
	}
}

func isCloudflareIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return false
	}
	for _, n := range cloudflareNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

type blacklistAddr struct {
	ip, role string
	cf       bool
}

func selectBlacklistIPs(web []string, mx []struct{ host string; ips []string }) (check, skipped []blacklistAddr) {
	seen := map[string]bool{}
	add := func(list *[]blacklistAddr, ip, role string) {
		if ip == "" || strings.Contains(ip, ":") || seen[ip] {
			return
		}
		seen[ip] = true
		*list = append(*list, blacklistAddr{ip: ip, role: role, cf: isCloudflareIPv4(ip)})
	}
	for _, m := range mx {
		for _, ip := range m.ips {
			add(&check, ip, "MX "+m.host)
		}
	}
	haveMail := len(check) > 0
	for _, ip := range web {
		if haveMail && isCloudflareIPv4(ip) {
			add(&skipped, ip, "website A")
		} else {
			add(&check, ip, "website A")
		}
	}
	if len(check) > 5 {
		check = check[:5]
	}
	return check, skipped
}
