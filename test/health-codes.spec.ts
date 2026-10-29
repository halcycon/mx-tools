import { describe, expect, it } from 'vitest';
import type { CheckResult, CheckRow } from '../worker/checks/types';
import type { BlacklistScan } from '../worker/checks/run';
import type { SpfFlatten } from '../worker/checks/spf-flat';
import { interpretDnsblCodes } from '../worker/checks/dnsbl-codes';
import {
	buildReport,
	CODE_STATUS,
	HEALTH_CHECK_IDS,
	isGenuineListing,
	mapBimi,
	mapBlacklist,
	mapDkim,
	mapDmarc,
	mapDns,
	mapHttps,
	mapMtaSts,
	mapMx,
	mapSpf,
	mapTlsrpt,
	toCheck,
	type HealthCheck,
} from '../worker/health/codes';
import { runJobs } from '../worker/health/run';

function result(tool: string, rows: CheckRow[], query = 'example.org'): CheckResult {
	return { tool, title: tool, query, ok: true, summary: '', rows, elapsedMs: 1 };
}

function flat(all: string, lookups = 3): SpfFlatten {
	return { lookups, ips: [], kept: [], notes: [], all, found: true };
}

const spfRow = (value: string): CheckRow => ({ status: 'ok', name: 'SPF', value });

describe('SPF mapping', () => {
	it('spf_missing', () => {
		const r = result('spf', [{ status: 'fail', name: 'SPF', value: 'Not found' }]);
		expect(mapSpf(r, flat('?all')).code).toBe('spf_missing');
	});
	it('spf_multiple', () => {
		const r = result('spf', [spfRow('v=spf1 -all'), spfRow('v=spf1 ~all'), { status: 'fail', name: 'Policy', value: 'Multiple SPF records (invalid)' }]);
		expect(mapSpf(r, flat('-all')).code).toBe('spf_multiple');
	});
	it('spf_pass_all beats lookup count', () => {
		expect(mapSpf(result('spf', [spfRow('v=spf1 +all')]), flat('+all', 20)).code).toBe('spf_pass_all');
	});
	it('spf_too_many_lookups', () => {
		const m = mapSpf(result('spf', [spfRow('v=spf1 include:a include:b -all')]), flat('-all', 11));
		expect(m.code).toBe('spf_too_many_lookups');
		expect(m.facts).toMatchObject({ lookups: 11, lookupLimit: 10 });
	});
	it('spf_softfail_all / spf_pass_hardfail / spf_neutral_all', () => {
		expect(mapSpf(result('spf', [spfRow('v=spf1 ~all')]), flat('~all')).code).toBe('spf_softfail_all');
		expect(mapSpf(result('spf', [spfRow('v=spf1 -all')]), flat('-all')).code).toBe('spf_pass_hardfail');
		expect(mapSpf(result('spf', [spfRow('v=spf1 include:x')]), flat('?all')).code).toBe('spf_neutral_all');
	});
	it('uses the redirect-resolved all qualifier', () => {
		expect(mapSpf(result('spf', [spfRow('v=spf1 redirect=_spf.example.net')]), flat('-all')).code).toBe('spf_pass_hardfail');
	});
});

describe('DMARC mapping', () => {
	const dmarc = (record?: string) =>
		result('dmarc', record ? [{ status: 'ok', name: 'Record', value: record }] : [{ status: 'fail', name: 'DMARC', value: 'Not found' }]);

	it('dmarc_missing', () => expect(mapDmarc(dmarc()).code).toBe('dmarc_missing'));
	it('dmarc_policy_none (even without rua)', () => {
		const m = mapDmarc(dmarc('v=DMARC1; p=none'));
		expect(m.code).toBe('dmarc_policy_none');
		expect(m.facts).toMatchObject({ policy: 'none', rua: null, record: 'v=DMARC1; p=none' });
	});
	it('dmarc_no_rua for enforcing policy without reports', () => {
		expect(mapDmarc(dmarc('v=DMARC1; p=reject')).code).toBe('dmarc_no_rua');
	});
	it('dmarc_policy_quarantine / dmarc_policy_reject', () => {
		expect(mapDmarc(dmarc('v=DMARC1; p=quarantine; rua=mailto:d@example.org')).code).toBe('dmarc_policy_quarantine');
		const m = mapDmarc(dmarc('v=DMARC1; p=Reject; pct=50; rua=mailto:d@example.org'));
		expect(m.code).toBe('dmarc_policy_reject');
		expect(m.facts).toMatchObject({ policy: 'reject', pct: 50, rua: 'mailto:d@example.org' });
	});
	it('dmarc_invalid when p is missing or unknown', () => {
		expect(mapDmarc(dmarc('v=DMARC1; rua=mailto:d@example.org')).code).toBe('dmarc_invalid');
		expect(mapDmarc(dmarc('v=DMARC1; p=block')).code).toBe('dmarc_invalid');
	});
});

describe('DKIM mapping', () => {
	const sel = (selector: string, values: string[]) => ({
		selector,
		result: result(
			'dkim',
			values.length ? values.map((v) => ({ status: 'ok' as const, name: `${selector}._domainkey`, value: v })) : [{ status: 'fail', name: selector, value: 'No DKIM key found' }],
		),
	});

	it('dkim_found lists selectors with keys', () => {
		const m = mapDkim([sel('default', []), sel('google', ['v=DKIM1; k=rsa; p=MIIBIjANBg'])]);
		expect(m.code).toBe('dkim_found');
		expect(m.facts).toMatchObject({ found: [{ selector: 'google' }] });
	});
	it('ignores unrelated wildcard TXT and revoked keys', () => {
		const m = mapDkim([sel('default', ['google-site-verification=abc']), sel('k1', ['v=DKIM1; p='])]);
		expect(m.code).toBe('dkim_not_found_common_selectors');
		expect(m.facts).toMatchObject({ revoked: ['k1'] });
	});
});

describe('MX mapping', () => {
	it('mx_missing / mx_null / mx_unresolved / mx_ok', () => {
		expect(mapMx(result('mx', [])).code).toBe('mx_missing');
		expect(mapMx(result('mx', [{ status: 'info', name: 'Preference 0', value: '(null MX)' }])).code).toBe('mx_null');
		expect(mapMx(result('mx', [{ status: 'warn', name: 'Preference 10', value: 'mx.example.org', info: 'No A/AAAA for MX host' }])).code).toBe('mx_unresolved');
		const ok = mapMx(result('mx', [{ status: 'ok', name: 'Preference 1', value: 'smtp.google.com', info: 'IP: 142.250.1.27, 2a00:1450::1b' }]));
		expect(ok.code).toBe('mx_ok');
		expect(ok.facts).toEqual({ hosts: [{ preference: 1, host: 'smtp.google.com', ips: ['142.250.1.27', '2a00:1450::1b'], resolves: true }] });
	});
});

describe('MTA-STS / TLSRPT / BIMI mapping', () => {
	const sts = (record: string | null, http: number | null, lines: string[]) =>
		result('mta-sts', [
			record ? { status: 'ok', name: 'DNS', value: record } : { status: 'info', name: 'DNS', value: 'No MTA-STS TXT' },
			...(http ? [{ status: http === 200 ? ('ok' as const) : ('warn' as const), name: 'Policy URL', value: 'https://mta-sts.example.org/.well-known/mta-sts.txt', info: `HTTP ${http}` }] : []),
			...lines.map((v) => ({ status: 'info' as const, name: 'Policy', value: v })),
		]);

	it('mtasts codes', () => {
		expect(mapMtaSts(sts(null, 404, [])).code).toBe('mtasts_missing');
		expect(mapMtaSts(sts('v=STSv1; id=1', 404, [])).code).toBe('mtasts_policy_error');
		expect(mapMtaSts(sts('v=STSv1; id=1', 200, ['version: STSv1', 'mode: testing'])).code).toBe('mtasts_testing');
		expect(mapMtaSts(sts('v=STSv1; id=1', 200, ['mode: none'])).code).toBe('mtasts_none');
		const enforce = mapMtaSts(sts('v=STSv1; id=1', 200, ['version: STSv1', 'mode: enforce', 'mx: *.example.org', 'max_age: 604800']));
		expect(enforce.code).toBe('mtasts_enforce');
		expect(enforce.facts).toMatchObject({ mode: 'enforce', maxAge: 604800, mx: ['*.example.org'], httpStatus: 200 });
	});

	it('tlsrpt and bimi codes', () => {
		expect(mapTlsrpt(result('tlsrpt', [{ status: 'info', name: 'TLSRPT', value: 'Not found' }])).code).toBe('tlsrpt_missing');
		expect(mapTlsrpt(result('tlsrpt', [{ status: 'ok', name: 'TLSRPT', value: 'v=TLSRPTv1; rua=mailto:t@example.org' }])).facts).toMatchObject({ rua: 'mailto:t@example.org' });
		expect(mapBimi(result('bimi', [{ status: 'info', name: 'BIMI', value: 'Not found (optional)' }])).code).toBe('bimi_missing');
		expect(mapBimi(result('bimi', [{ status: 'ok', name: 'BIMI', value: 'v=BIMI1; l=https://example.org/logo.svg' }])).code).toBe('bimi_ok');
	});
});

describe('blacklist mapping', () => {
	const W = { spamhausDqs: false, source: 'worker' as const };
	const hit = (list: string, zone: string, answers: string[], lookupFailed = false, rcode: number | null = answers.length ? 0 : 3) => ({
		list,
		ip: '192.0.2.10',
		role: 'MX mx.example.org',
		answers,
		lookupFailed,
		rcode: lookupFailed ? null : rcode,
		interp: interpretDnsblCodes(zone, answers, zone.includes('dnswl')),
	});
	const scan = (hits: BlacklistScan['hits']): BlacklistScan => ({
		mx: [{ host: 'mx.example.org', ips: ['192.0.2.10'] }],
		check: [{ ip: '192.0.2.10', role: 'MX mx.example.org', cloudflare: false }],
		skipped: [],
		listCount: 22,
		hits,
	});

	it('blacklist_clean', () => {
		expect(mapBlacklist(scan([hit('SpamCop', 'bl.spamcop.net', []), hit('DNSWL', 'list.dnswl.org', ['127.0.10.0'])]), W).code).toBe('blacklist_clean');
	});
	it('Spamhaus open-resolver errors are inconclusive (info), never listed', () => {
		const m = mapBlacklist(scan([hit('Spamhaus ZEN', 'zen.spamhaus.org', ['127.255.255.254']), hit('SpamCop', 'bl.spamcop.net', [])]), W);
		expect(m.code).toBe('blacklist_inconclusive');
		expect(CODE_STATUS[m.code]).toBe('info');
		expect(m.facts).toMatchObject({ listed: [], inconclusive: [{ list: 'Spamhaus ZEN', reason: 'query_refused' }] });
	});
	it('non-127 or 127.0.0.1 answers and failed lookups are inconclusive', () => {
		expect(isGenuineListing(['127.0.0.2'])).toBe(true);
		expect(isGenuineListing(['127.0.0.1'])).toBe(false);
		expect(isGenuineListing(['203.0.113.5'])).toBe(false);
		const m = mapBlacklist(scan([hit('Parked', 'bhnc.njabl.org', ['203.0.113.5']), hit('SORBS', 'dnsbl.sorbs.net', [], true)]), W);
		expect(m.code).toBe('blacklist_inconclusive');
		expect(m.facts).toMatchObject({ inconclusive: [{ reason: 'unexpected_answer' }, { reason: 'lookup_failed' }] });
	});
	it('SERVFAIL is inconclusive, not clean', () => {
		const m = mapBlacklist(scan([hit('SpamCop', 'bl.spamcop.net', []), hit('PSBL', 'psbl.surriel.com', [], false, 2)]), W);
		expect(m.code).toBe('blacklist_inconclusive');
		expect(m.facts).toMatchObject({ inconclusive: [{ list: 'PSBL', reason: 'lookup_failed' }] });
	});

	it('blacklist_listed for real listing codes', () => {
		const m = mapBlacklist(scan([hit('SpamCop', 'bl.spamcop.net', ['127.0.0.2']), hit('Spamhaus ZEN', 'zen.spamhaus.org', ['127.255.255.254'])]), W);
		expect(m.code).toBe('blacklist_listed');
		expect(m.facts).toMatchObject({ listed: [{ list: 'SpamCop', ip: '192.0.2.10', codes: ['127.0.0.2'] }] });
	});
	it('blacklist_no_ips', () => {
		expect(mapBlacklist({ mx: [], check: [], skipped: [], listCount: 22, hits: [] }, W).code).toBe('blacklist_no_ips');
	});
});

describe('DNS / HTTPS mapping', () => {
	const ns = (hosts: Array<[string, boolean]>) =>
		result('dns', [
			{ status: hosts.length < 2 ? 'warn' : 'ok', name: 'NS count', value: String(hosts.length) },
			...hosts.map(([h, ok]) => ({ status: ok ? ('ok' as const) : ('fail' as const), name: h, value: ok ? '192.0.2.53' : 'unresolved' })),
			{ status: 'ok', name: 'SOA', value: '2026110301' },
		]);

	it('dns codes', () => {
		expect(mapDns(ns([])).code).toBe('dns_no_nameservers');
		expect(mapDns(ns([['ns1.example.org', true]])).code).toBe('dns_single_ns');
		expect(mapDns(ns([['ns1.example.org', true], ['ns2.example.org', false]])).code).toBe('dns_ns_unresolved');
		const ok = mapDns(ns([['ns1.example.org', true], ['ns2.example.org', true]]));
		expect(ok.code).toBe('dns_ok');
		expect(ok.facts).toMatchObject({ count: 2, soaSerial: '2026110301' });
	});

	const http = (status: number | null, query = 'example.org') =>
		result(
			'https',
			status === null
				? [{ status: 'fail', name: 'Error', value: 'connection refused' }]
				: [
						{ status: status < 400 ? 'ok' : 'warn', name: 'Status', value: String(status) },
						{ status: 'info', name: 'URL', value: `https://${query}` },
					],
			query,
		);

	it('https codes', () => {
		expect(mapHttps(http(200)).code).toBe('https_ok');
		expect(mapHttps(http(301)).code).toBe('https_ok');
		const wwwOnly = mapHttps(http(null), http(200, 'www.example.org'));
		expect(wwwOnly.code).toBe('https_www_only');
		expect(CODE_STATUS[wwwOnly.code]).toBe('warn');
		expect(mapHttps(http(503), http(null, 'www.example.org')).code).toBe('https_http_error');
		const fail = mapHttps(http(null), http(null, 'www.example.org'));
		expect(fail.code).toBe('https_fail');
		expect(fail.facts).toMatchObject({ apex: { error: 'connection refused' } });
	});
});

describe('report shape', () => {
	const checks: HealthCheck[] = [
		toCheck('dmarc', { code: 'dmarc_policy_none', facts: { policy: 'none' }, technical: 'v=DMARC1; p=none' }),
		toCheck('spf', { code: 'spf_pass_hardfail', facts: {}, technical: 'v=spf1 -all' }),
		toCheck('bimi', { code: 'bimi_missing', facts: {}, technical: '' }),
		toCheck('mx', { code: 'mx_missing', facts: {}, technical: '' }),
	];

	it('scores, orders, and formats per the contract', () => {
		const report = buildReport('example.org', checks, new Date('2026-11-03T08:00:00.123Z'));
		expect(report).toEqual({
			domain: 'example.org',
			checkedAt: '2026-11-03T08:00:00Z',
			score: { pass: 1, warn: 1, fail: 1 },
			overall: 'fail',
			checks: [
				{ id: 'spf', status: 'pass', code: 'spf_pass_hardfail', facts: {}, technical: 'v=spf1 -all' },
				{ id: 'dmarc', status: 'warn', code: 'dmarc_policy_none', facts: { policy: 'none' }, technical: 'v=DMARC1; p=none' },
				{ id: 'mx', status: 'fail', code: 'mx_missing', facts: {}, technical: '' },
				{ id: 'bimi', status: 'info', code: 'bimi_missing', facts: {}, technical: '' },
			],
		});
	});

	it('overall is warn/pass when there are no fails', () => {
		expect(buildReport('example.org', checks.slice(0, 3), new Date()).overall).toBe('warn');
		expect(buildReport('example.org', [checks[1], checks[2]], new Date()).overall).toBe('pass');
	});

	it('every code maps to a contract status', () => {
		for (const status of Object.values(CODE_STATUS)) expect(['pass', 'warn', 'fail', 'info']).toContain(status);
		expect(HEALTH_CHECK_IDS).toEqual(['spf', 'dmarc', 'dkim', 'mx', 'mta-sts', 'tlsrpt', 'blacklist', 'bimi', 'dns', 'https']);
	});

	it('includes every code required by the website brief', () => {
		const required = [
			'spf_missing', 'spf_multiple', 'spf_too_many_lookups', 'spf_softfail_all', 'spf_pass_hardfail',
			'dmarc_missing', 'dmarc_policy_none', 'dmarc_policy_quarantine', 'dmarc_policy_reject', 'dmarc_no_rua',
			'dkim_found', 'dkim_not_found_common_selectors', 'mx_missing', 'mx_ok',
			'mtasts_missing', 'mtasts_testing', 'mtasts_enforce', 'tlsrpt_missing', 'tlsrpt_ok',
			'blacklist_clean', 'blacklist_listed', 'blacklist_inconclusive', 'bimi_missing', 'bimi_ok',
			'dns_single_ns', 'dns_ok', 'https_ok', 'https_fail',
		];
		for (const code of required) expect(CODE_STATUS).toHaveProperty(code);
	});
});

describe('runJobs', () => {
	it('returns completed checks and flags incomplete on timeout', async () => {
		const ok = toCheck('spf', { code: 'spf_pass_hardfail', facts: {}, technical: '' });
		const out = await runJobs(
			[
				{ id: 'spf', run: async () => ok },
				{ id: 'dmarc', run: () => new Promise<HealthCheck>(() => {}) },
				{ id: 'mx', run: async () => Promise.reject(new Error('DoH 500')) },
			],
			50,
		);
		expect(out.complete).toBe(false);
		expect(out.checks.map((c) => [c.id, c.code])).toEqual([
			['spf', 'spf_pass_hardfail'],
			['mx', 'check_error'],
		]);
	});

	it('is complete when every job settles in time', async () => {
		const out = await runJobs([{ id: 'bimi', run: async () => toCheck('bimi', { code: 'bimi_ok', facts: {}, technical: '' }) }], 1000);
		expect(out.complete).toBe(true);
	});
});
