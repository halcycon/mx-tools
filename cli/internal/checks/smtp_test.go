package checks

import (
	"bufio"
	"strings"
	"testing"
)

func TestSmtpReadReplyMultiline(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("250-smtp.example.com\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n"))
	code, text, err := smtpReadReply(r)
	if err != nil {
		t.Fatal(err)
	}
	if code != 250 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(text, "STARTTLS") || !strings.Contains(text, "AUTH PLAIN") {
		t.Fatalf("text=%q", text)
	}
}

func TestParseQuerySMTPPort(t *testing.T) {
	q, err := ParseQuery("smtp:smtp.gmail.com:587")
	if err != nil {
		t.Fatal(err)
	}
	if q.Tool != "smtp" || q.Target != "smtp.gmail.com" || q.Extra != "587" {
		t.Fatalf("%+v", q)
	}
}
