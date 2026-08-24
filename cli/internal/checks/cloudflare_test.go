package checks

import "testing"

func TestIsCloudflareIPv4(t *testing.T) {
	if !isCloudflareIPv4("104.21.64.109") {
		t.Fatal("expected CF proxy")
	}
	if isCloudflareIPv4("8.8.8.8") {
		t.Fatal("8.8.8.8 is not CF")
	}
}

func TestSelectBlacklistIPsSkipsCDNWhenMX(t *testing.T) {
	check, skipped := selectBlacklistIPs(
		[]string{"104.21.64.109"},
		[]struct {
			host string
			ips  []string
		}{{host: "mail.example.com", ips: []string{"203.0.113.10"}}},
	)
	if len(check) != 1 || check[0].ip != "203.0.113.10" {
		t.Fatalf("check=%+v", check)
	}
	if len(skipped) != 1 || skipped[0].ip != "104.21.64.109" {
		t.Fatalf("skipped=%+v", skipped)
	}
}
