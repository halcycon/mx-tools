import { describe, it, expect } from 'vitest';
import { analyzeHeaders, unfoldHeaders } from '../worker/checks/headers';

const SAMPLE = `Return-Path: <bounces@mailer.example.com>
Received: from mx.example.net (mx.example.net [203.0.113.10])
	by inbox.example.net with ESMTPS id abc123
	for <you@example.net>;
	Mon, 24 Aug 2026 10:00:08 +0000
Received: from mail-yw1.google.com (mail-yw1.google.com [209.85.221.48])
	by mx.example.net with ESMTPS id def456;
	Mon, 24 Aug 2026 10:00:05 +0000
Received: by mail-yw1.google.com with SMTP id xyz;
	Mon, 24 Aug 2026 10:00:00 +0000
From: Sender Name <sender@example.com>
To: you@example.net
Subject: Lunch tomorrow
Date: Mon, 24 Aug 2026 10:00:00 +0000
Message-ID: <abc@example.com>
Authentication-Results: mx.example.net;
	dkim=pass header.d=example.com header.s=google;
	spf=pass smtp.mailfrom=example.com;
	dmarc=pass action=none header.from=example.com
Received-SPF: pass (example.com: 209.85.221.48 is permitted)
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=google; bh=abc; b=xyz
X-Spam-Status: No, score=-0.1 required=5.0 tests=none

Body is ignored.
`;

describe('header analyzer', () => {
	it('unfolds continuation lines', () => {
		const fields = unfoldHeaders(SAMPLE);
		const received = fields.filter((f) => f.name.toLowerCase() === 'received');
		expect(received).toHaveLength(3);
		expect(received[0].value).toContain('from mx.example.net');
	});

	it('extracts hops, auth, and spam', () => {
		const results = analyzeHeaders(SAMPLE);
		expect(results.some((r) => r.tool === 'headers')).toBe(true);
		expect(results.some((r) => r.tool === 'headers-hops')).toBe(true);
		expect(results.some((r) => r.tool === 'headers-auth')).toBe(true);
		expect(results.some((r) => r.tool === 'headers-spam')).toBe(true);
		const auth = results.find((r) => r.tool === 'headers-auth')!;
		expect(auth.rows.some((r) => r.name === 'DKIM' && r.value === 'pass')).toBe(true);
		expect(auth.rows.some((r) => r.name === 'SPF' && r.value === 'pass')).toBe(true);
		expect(auth.rows.some((r) => r.name === 'DMARC' && r.value === 'pass')).toBe(true);
		const hops = results.find((r) => r.tool === 'headers-hops')!;
		expect(hops.rows.filter((r) => r.name.startsWith('Hop')).length).toBe(3);
		const summary = results.find((r) => r.tool === 'headers')!;
		expect(summary.related?.some((r) => r.query === 'dmarc:example.com')).toBe(true);
	});

	it('warns on envelope vs from mismatch', () => {
		const results = analyzeHeaders(SAMPLE);
		const summary = results.find((r) => r.tool === 'headers')!;
		expect(summary.rows.some((r) => r.name === 'Envelope vs From')).toBe(true);
	});
});
