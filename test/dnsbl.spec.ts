import { describe, expect, it } from 'vitest';
import { interpretDnsblCodes, spamhausZone } from '../worker/checks/dnsbl-codes';

describe('DNSBL codes', () => {
	it('does not treat Spamhaus 127.255.255.254 as a listing', () => {
		const r = interpretDnsblCodes('zen.spamhaus.org', ['127.255.255.254']);
		expect(r.kind).toBe('query_error');
		expect(r.status).toBe('warn');
		expect(r.label).toContain('127.255.255.254');
	});

	it('maps SBL listed codes', () => {
		const r = interpretDnsblCodes('zen.spamhaus.org', ['127.0.0.2']);
		expect(r.kind).toBe('listed');
		expect(r.status).toBe('fail');
		expect(r.label).toContain('SBL');
	});

	it('treats 127.0.0.4 as XBL listing, not a query error', () => {
		const r = interpretDnsblCodes('zen.spamhaus.org', ['127.0.0.4']);
		expect(r.kind).toBe('listed');
		expect(r.label).toContain('XBL');
		expect(r.detail.toLowerCase()).toContain('not a query error');
	});

	it('uses DQS zone when a key is present', () => {
		expect(spamhausZone('abc123').zone).toBe('abc123.zen.dq.spamhaus.net');
		expect(spamhausZone('').zone).toBe('zen.spamhaus.org');
	});
});
