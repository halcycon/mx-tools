import { describe, expect, it } from 'vitest';
import { agentHeaders, signProbe, type AgentProbe, type AgentSmtp } from '../worker/agent/client';
import { CODE_STATUS } from '../worker/health/codes';
import { agentScan } from '../worker/health/run';
import { mapBlacklist } from '../worker/health/codes';
import { mapPtr, mapSmtp } from '../worker/report/full';

const NOW = Date.parse('2026-11-03T08:00:00Z');
const inDays = (d: number) => new Date(NOW + d * 86_400_000).toISOString();

function smtp(over: Partial<AgentSmtp> = {}): AgentSmtp {
	return {
		host: 'mx.example.org',
		port: 25,
		mode: 'starttls',
		role: 'mx',
		connected: true,
		bannerCode: 220,
		banner: 'mx.example.org ESMTP',
		startTls: true,
		tls: true,
		tlsVersion: 'TLS1.3',
		cert: { subject: 'mx.example.org', issuer: 'R11', dnsNames: ['mx.example.org'], notBefore: inDays(-30), notAfter: inDays(60), verified: true, hostnameMatch: true },
		elapsedMs: 120,
		...over,
	};
}

function probe(over: Partial<AgentProbe> = {}): AgentProbe {
	return {
		domain: 'example.org',
		mode: 'full',
		resolver: '127.0.0.1:53',
		dnsbl: { dqs: true, checked: [{ ip: '192.0.2.10', role: 'MX mx.example.org' }], skipped: null, mx: [{ host: 'mx.example.org', ips: ['192.0.2.10'] }], listCount: 22, hits: [] },
		smtp: [smtp()],
		smtpEgress: true,
		elapsedMs: 900,
		...over,
	};
}

describe('agent auth', () => {
	it('signs exactly like the Go agent (shared vector)', async () => {
		expect(await signProbe('shh', '1700000000', 'POST', '/api/v1/probe', '{"domain":"example.com","mode":"quick"}')).toBe(
			'c1eaedb319036c3f6b4a305b8ea560541957a3833b66e07f1cc99b4ad68bef85',
		);
	});

	it('sends Access service-token headers plus HMAC, never the raw secret', async () => {
		const h = await agentHeaders({ AGENT_HMAC_SECRET: 'topsecret', AGENT_CLIENT_ID: 'id.access', AGENT_CLIENT_SECRET: 'cs' }, '{}', 1_700_000_000_000);
		expect(h['cf-access-client-id']).toBe('id.access');
		expect(h['x-mx-timestamp']).toBe('1700000000');
		expect(h['x-mx-signature']).toMatch(/^[0-9a-f]{64}$/);
		expect(Object.values(h).join(' ')).not.toContain('topsecret');
		expect(h.authorization).toBeUndefined();
	});
});

describe('SMTP mapping', () => {
	const code = (p: AgentProbe | null) => mapSmtp(p, NOW).code;
	it('smtp_ok', () => expect(code(probe())).toBe('smtp_ok'));
	it('smtp_not_checked when the agent is down or egress is blocked', () => {
		expect(code(null)).toBe('smtp_not_checked');
		const blocked = mapSmtp(probe({ smtpEgress: false, smtp: [] }), NOW);
		expect(blocked.code).toBe('smtp_not_checked');
		expect(blocked.facts).toMatchObject({ reason: 'egress_blocked' });
	});
	it('smtp_unreachable when no MX answers', () => expect(code(probe({ smtp: [smtp({ connected: false, error: 'i/o timeout', cert: undefined, tls: false })] }))).toBe('smtp_unreachable'));
	it('smtp_starttls_missing', () => expect(code(probe({ smtp: [smtp({ startTls: false, tls: false, cert: undefined })] }))).toBe('smtp_starttls_missing'));
	it('smtp_tls_failed', () => expect(code(probe({ smtp: [smtp({ tls: false, cert: undefined, error: 'starttls handshake: bad' })] }))).toBe('smtp_tls_failed'));
	it('certificate codes', () => {
		const cert = smtp().cert!;
		expect(code(probe({ smtp: [smtp({ cert: { ...cert, notAfter: inDays(-1) } })] }))).toBe('cert_expired');
		expect(code(probe({ smtp: [smtp({ cert: { ...cert, notAfter: inDays(10) } })] }))).toBe('cert_expiring_soon');
		expect(code(probe({ smtp: [smtp({ cert: { ...cert, verified: false, verifyError: 'x509: unknown authority' } })] }))).toBe('smtp_cert_invalid');
		const sub = smtp({ host: 'smtp.example.org', port: 465, mode: 'implicit', role: 'submission', cert: { ...cert, notAfter: inDays(5) } });
		const m = mapSmtp(probe({ smtp: [smtp(), sub] }), NOW);
		expect(m.code).toBe('cert_expiring_soon');
		expect(m.technical).toContain('smtp.example.org:465');
	});
});

describe('PTR mapping', () => {
	const a = { ip: '192.0.2.10', role: 'MX mx.example.org' };
	it('ptr codes', () => {
		expect(mapPtr(null, 'agent').code).toBe('ptr_not_checked');
		expect(mapPtr([], 'agent').code).toBe('ptr_not_checked');
		expect(mapPtr([{ ...a, ptr: [], forward: [], fcrdns: false }], 'agent').code).toBe('ptr_missing');
		expect(mapPtr([{ ...a, ptr: ['host.isp.net'], forward: ['198.51.100.1'], fcrdns: false }], 'agent').code).toBe('ptr_mismatch');
		expect(mapPtr([{ ...a, ptr: ['mx.example.org'], forward: ['192.0.2.10'], fcrdns: true }], 'worker').code).toBe('ptr_ok');
	});
	it('new codes have statuses', () => {
		for (const c of ['smtp_starttls_missing', 'cert_expiring_soon', 'ptr_mismatch', 'smtp_ok', 'ptr_ok']) expect(CODE_STATUS).toHaveProperty(c);
	});
});

describe('agent DNSBL results', () => {
	it('map through the same blacklist codes with source=agent, never exposing the DQS zone', () => {
		const p = probe({
			dnsbl: {
				...probe().dnsbl,
				hits: [
					{ list: 'Spamhaus ZEN (DQS)', zone: 'zen.spamhaus.org', ip: '192.0.2.10', role: 'MX', answers: [], rcode: 3 },
					{ list: 'SpamCop', zone: 'bl.spamcop.net', ip: '192.0.2.10', role: 'MX', answers: ['127.0.0.2'], rcode: 0 },
				],
			},
		});
		const m = mapBlacklist(agentScan(p.dnsbl), { spamhausDqs: true, source: 'agent' });
		expect(m.code).toBe('blacklist_listed');
		expect(m.facts).toMatchObject({ source: 'agent', spamhausDqs: true, listed: [{ list: 'SpamCop' }] });
		const clean = mapBlacklist(agentScan({ ...p.dnsbl, hits: [p.dnsbl.hits![0]] }), { spamhausDqs: true, source: 'agent' });
		expect(clean.code).toBe('blacklist_clean');
	});
});
