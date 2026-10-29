package checks

import "testing"

func TestIsPublicIP(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8":       true,
		"176.9.26.220":  true,
		"2a00:1450::1b": true,
		"127.0.0.1":     false,
		"10.1.2.3":      false,
		"192.168.0.10":  false,
		"172.16.5.5":    false,
		"100.65.151.67": false,
		"169.254.1.1":   false,
		"::1":           false,
		"fe80::1":       false,
		"fd00::1":       false,
		"0.0.0.0":       false,
		"not-an-ip":     false,
	} {
		if got := IsPublicIP(ip); got != want {
			t.Errorf("IsPublicIP(%q)=%v want %v", ip, got, want)
		}
	}
}

func TestPublicOnlyFiltersMX(t *testing.T) {
	got := publicOnly([]ProbeMXHost{{Host: "mx.example.com", IPs: []string{"10.0.0.5", "203.0.113.9", "127.0.0.1"}}})
	if len(got[0].IPs) != 1 || got[0].IPs[0] != "203.0.113.9" {
		t.Fatalf("got %v", got[0].IPs)
	}
}

func TestSetResolver(t *testing.T) {
	prev := resolverAddr
	defer func() { resolverAddr = prev }()
	if err := SetResolver("9.9.9.9"); err != nil || resolverAddr != "9.9.9.9:53" {
		t.Fatalf("bare IP: %v %s", err, resolverAddr)
	}
	if err := SetResolver("127.0.0.1:5353"); err != nil || resolverAddr != "127.0.0.1:5353" {
		t.Fatalf("ip:port: %v %s", err, resolverAddr)
	}
	if err := SetResolver("nonsense"); err == nil {
		t.Fatal("expected error")
	}
}
