package checks

import "testing"

func TestInterpretDnsblQueryError(t *testing.T) {
	r := InterpretDnsbl("zen.spamhaus.org", []string{"127.255.255.254"}, false)
	if r.Kind != DnsblQueryError {
		t.Fatalf("kind=%s", r.Kind)
	}
	if r.Status != StatusWarn {
		t.Fatalf("status=%s", r.Status)
	}
}

func TestInterpretDnsblListed(t *testing.T) {
	r := InterpretDnsbl("zen.spamhaus.org", []string{"127.0.0.2"}, false)
	if r.Kind != DnsblListed {
		t.Fatalf("kind=%s", r.Kind)
	}
}
