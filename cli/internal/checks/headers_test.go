package checks

import "testing"

const sampleHeaders = `Return-Path: <bounces@mailer.example.com>
Received: from mx.example.net (mx.example.net [203.0.113.10])
	by inbox.example.net with ESMTPS id abc123
	for <you@example.net>;
	Mon, 24 Aug 2026 10:00:08 +0000
Received: from mail-yw1.google.com (mail-yw1.google.com [209.85.221.48])
	by mx.example.net with ESMTPS id def456;
	Mon, 24 Aug 2026 10:00:05 +0000
From: Sender Name <sender@example.com>
To: you@example.net
Subject: Lunch tomorrow
Date: Mon, 24 Aug 2026 10:00:00 +0000
Message-ID: <abc@example.com>
Authentication-Results: mx.example.net;
	dkim=pass header.d=example.com;
	spf=pass smtp.mailfrom=example.com;
	dmarc=pass action=none header.from=example.com
X-Spam-Status: No, score=-0.1 required=5.0
`

func TestAnalyzeHeaders(t *testing.T) {
	results := AnalyzeHeaders(sampleHeaders)
	if len(results) < 3 {
		t.Fatalf("results=%d", len(results))
	}
	var auth *Result
	for i := range results {
		if results[i].Tool == "headers-auth" {
			auth = &results[i]
		}
	}
	if auth == nil {
		t.Fatal("missing auth")
	}
	found := false
	for _, r := range auth.Rows {
		if r.Name == "DKIM" && r.Value == "pass" {
			found = true
		}
	}
	if !found {
		t.Fatalf("dkim pass missing: %+v", auth.Rows)
	}
}

func TestParseQueryHeaders(t *testing.T) {
	q, err := ParseQuery("headers")
	if err != nil {
		t.Fatal(err)
	}
	if q.Tool != "headers" || q.Target != "-" {
		t.Fatalf("%+v", q)
	}
}
