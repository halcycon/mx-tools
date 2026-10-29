import type { CheckResult } from '../checks/types';
import type { BlacklistScan } from '../checks/run';
import type { SpfFlatten } from '../checks/spf-flat';

export const HEALTH_CHECK_IDS = ['spf', 'dmarc', 'dkim', 'mx', 'mta-sts', 'tlsrpt', 'blacklist', 'bimi', 'dns', 'https'] as const;
/** Full (gated) report adds agent-only checks after the public ten. */
export const CHECK_ORDER = [...HEALTH_CHECK_IDS, 'smtp', 'ptr'] as const;
export type HealthCheckId = (typeof CHECK_ORDER)[number];
export type HealthStatus = 'pass' | 'warn' | 'fail' | 'info';

export type HealthCheck = {
	id: HealthCheckId;
	status: HealthStatus;
	code: HealthCode;
	facts: Record<string, unknown>;
	technical: string;
};

export type HealthReport = {
	domain: string;
	checkedAt: string;
	score: { pass: number; warn: number; fail: number };
	overall: 'pass' | 'warn' | 'fail';
	checks: HealthCheck[];
};

/** Stable reason codes → status. Part of the public API: never rename, only add. */
export const CODE_STATUS = {
	spf_missing: 'fail',
	spf_multiple: 'fail',
	spf_pass_all: 'fail',
	spf_too_many_lookups: 'fail',
	spf_softfail_all: 'warn',
	spf_neutral_all: 'warn',
	spf_pass_hardfail: 'pass',

	dmarc_missing: 'fail',
	dmarc_invalid: 'fail',
	dmarc_policy_none: 'fail',
	dmarc_no_rua: 'warn',
	dmarc_policy_quarantine: 'warn',
	dmarc_policy_reject: 'pass',

	dkim_found: 'pass',
	dkim_not_found_common_selectors: 'info',

	mx_missing: 'fail',
	mx_unresolved: 'warn',
	mx_null: 'info',
	mx_ok: 'pass',

	mtasts_missing: 'info',
	mtasts_policy_error: 'warn',
	mtasts_none: 'info',
	mtasts_testing: 'info',
	mtasts_enforce: 'pass',

	tlsrpt_missing: 'info',
	tlsrpt_ok: 'pass',

	blacklist_listed: 'fail',
	blacklist_inconclusive: 'info',
	blacklist_no_ips: 'info',
	blacklist_clean: 'pass',

	bimi_missing: 'info',
	bimi_ok: 'pass',

	dns_no_nameservers: 'fail',
	dns_single_ns: 'warn',
	dns_ns_unresolved: 'warn',
	dns_ok: 'pass',

	https_fail: 'fail',
	https_http_error: 'warn',
	https_www_only: 'warn',
	https_ok: 'pass',

	// Full (gated) report only — need the VPS agent.
	cert_expired: 'fail',
	smtp_starttls_missing: 'fail',
	cert_invalid: 'fail',
	smtp_tls_failed: 'warn',
	cert_expiring_soon: 'warn',
	smtp_unreachable: 'info',
	smtp_not_checked: 'info',
	smtp_ok: 'pass',

	ptr_missing: 'fail',
	ptr_mismatch: 'warn',
	ptr_not_checked: 'info',
	ptr_ok: 'pass',

	check_error: 'info',
} as const satisfies Record<string, HealthStatus>;

export type HealthCode = keyof typeof CODE_STATUS;

export type Mapped = { code: HealthCode; facts: Record<string, unknown>; technical: string };

export function toCheck(id: HealthCheckId, m: Mapped): HealthCheck {
	return { id, status: CODE_STATUS[m.code], code: m.code, facts: m.facts, technical: m.technical };
}

export function errorCheck(id: HealthCheckId): HealthCheck {
	return toCheck(id, { code: 'check_error', facts: { reason: 'lookup_failed' }, technical: '' });
}

export function buildReport(domain: string, checks: HealthCheck[], checkedAt: Date): HealthReport {
	const score = { pass: 0, warn: 0, fail: 0 };
	for (const c of checks) if (c.status !== 'info') score[c.status] += 1;
	const overall = score.fail ? 'fail' : score.warn ? 'warn' : 'pass';
	return {
		domain,
		checkedAt: checkedAt.toISOString().replace(/\.\d{3}Z$/, 'Z'),
		score,
		overall,
		checks: [...checks].sort((a, b) => CHECK_ORDER.indexOf(a.id) - CHECK_ORDER.indexOf(b.id)),
	};
}

/** Parse `k=v; k=v` tag lists (DMARC, BIMI, TLSRPT, DKIM). Keys are lowercased. */
export function parseTags(record: string): Record<string, string> {
	const out: Record<string, string> = {};
	for (const part of record.split(';')) {
		const eq = part.indexOf('=');
		if (eq <= 0) continue;
		const key = part.slice(0, eq).trim().toLowerCase();
		if (key && !(key in out)) out[key] = part.slice(eq + 1).trim();
	}
	return out;
}

function numberOrNull(s: string | undefined): number | null {
	return s !== undefined && /^\d+$/.test(s) ? Number(s) : null;
}

const SPF_LOOKUP_LIMIT = 10;

export function mapSpf(spf: CheckResult, flat: SpfFlatten): Mapped {
	const records = spf.rows.filter((r) => r.name === 'SPF' && /^v=spf1\b/i.test(r.value)).map((r) => r.value);
	const technical = records.join('\n');
	if (!records.length) return { code: 'spf_missing', facts: { records: [] }, technical };
	if (records.length > 1) return { code: 'spf_multiple', facts: { records }, technical };

	const facts = { record: records[0], all: flat.all, lookups: flat.lookups, lookupLimit: SPF_LOOKUP_LIMIT };
	if (flat.all === '+all') return { code: 'spf_pass_all', facts, technical };
	if (flat.lookups > SPF_LOOKUP_LIMIT) return { code: 'spf_too_many_lookups', facts, technical };
	if (flat.all === '~all') return { code: 'spf_softfail_all', facts, technical };
	if (flat.all === '-all') return { code: 'spf_pass_hardfail', facts, technical };
	return { code: 'spf_neutral_all', facts, technical };
}

export function mapDmarc(dmarc: CheckResult): Mapped {
	const record = dmarc.rows.find((r) => r.name === 'Record')?.value;
	if (!record) return { code: 'dmarc_missing', facts: {}, technical: '' };
	const tags = parseTags(record);
	const policy = tags.p?.toLowerCase() ?? null;
	const facts = {
		record,
		policy,
		subdomainPolicy: tags.sp?.toLowerCase() ?? null,
		pct: numberOrNull(tags.pct) ?? 100,
		rua: tags.rua ?? null,
		ruf: tags.ruf ?? null,
	};
	if (policy === 'none') return { code: 'dmarc_policy_none', facts, technical: record };
	if (policy !== 'quarantine' && policy !== 'reject') return { code: 'dmarc_invalid', facts, technical: record };
	if (!facts.rua) return { code: 'dmarc_no_rua', facts, technical: record };
	return { code: policy === 'reject' ? 'dmarc_policy_reject' : 'dmarc_policy_quarantine', facts, technical: record };
}

export function mapDkim(results: Array<{ selector: string; result: CheckResult }>): Mapped {
	const found: Array<{ selector: string; record: string }> = [];
	const revoked: string[] = [];
	for (const { selector, result } of results) {
		for (const row of result.rows) {
			if (row.status !== 'ok') continue;
			const tags = parseTags(row.value);
			if (!('p' in tags) && !/v=DKIM1/i.test(row.value)) continue;
			if (tags.p === '') revoked.push(selector);
			else found.push({ selector, record: row.value });
		}
	}
	const facts = { selectorsChecked: results.map((r) => r.selector), found, revoked };
	const technical = found.map((f) => `${f.selector}._domainkey: ${f.record}`).join('\n');
	return { code: found.length ? 'dkim_found' : 'dkim_not_found_common_selectors', facts, technical };
}

export function mapMx(mx: CheckResult): Mapped {
	const hosts = mx.rows.map((r) => ({
		preference: numberOrNull(/(\d+)/.exec(r.name)?.[1]),
		host: r.value === '(null MX)' ? '.' : r.value,
		ips: r.info?.startsWith('IP: ') ? r.info.slice(4).split(', ') : [],
		resolves: r.status === 'ok',
	}));
	const technical = hosts.map((h) => `${h.preference} ${h.host}${h.ips.length ? ` (${h.ips.join(', ')})` : ''}`).join('\n');
	const facts = { hosts };
	const real = hosts.filter((h) => h.host !== '.');
	if (!hosts.length) return { code: 'mx_missing', facts, technical };
	if (!real.length) return { code: 'mx_null', facts, technical };
	if (real.some((h) => !h.resolves)) return { code: 'mx_unresolved', facts, technical };
	return { code: 'mx_ok', facts, technical };
}

export function mapMtaSts(r: CheckResult): Mapped {
	const dns = r.rows.find((x) => x.name === 'DNS');
	const record = dns?.status === 'ok' ? dns.value : null;
	const urlRow = r.rows.find((x) => x.name === 'Policy URL');
	const httpStatus = numberOrNull(/HTTP (\d+)/.exec(urlRow?.info ?? '')?.[1]);
	const lines = r.rows.filter((x) => x.name === 'Policy').map((x) => x.value);
	const policy: Record<string, string[]> = {};
	for (const line of lines) {
		const i = line.indexOf(':');
		if (i <= 0) continue;
		(policy[line.slice(0, i).trim().toLowerCase()] ??= []).push(line.slice(i + 1).trim());
	}
	const mode = policy.mode?.[0]?.toLowerCase() ?? null;
	const facts = {
		record,
		policyUrl: urlRow?.value ?? `https://mta-sts.${r.query.replace(/\.$/, '')}/.well-known/mta-sts.txt`,
		httpStatus,
		policyError: r.rows.find((x) => x.name === 'Policy fetch')?.value ?? null,
		mode,
		maxAge: numberOrNull(policy.max_age?.[0]),
		mx: policy.mx ?? [],
	};
	const technical = [record, ...lines].filter(Boolean).join('\n');
	if (!record) return { code: 'mtasts_missing', facts, technical };
	if (urlRow?.status !== 'ok' || !mode) return { code: 'mtasts_policy_error', facts, technical };
	if (mode === 'enforce') return { code: 'mtasts_enforce', facts, technical };
	if (mode === 'testing') return { code: 'mtasts_testing', facts, technical };
	if (mode === 'none') return { code: 'mtasts_none', facts, technical };
	return { code: 'mtasts_policy_error', facts, technical };
}

export function mapTlsrpt(r: CheckResult): Mapped {
	const record = r.rows.find((x) => x.status === 'ok')?.value ?? null;
	if (!record) return { code: 'tlsrpt_missing', facts: { record: null }, technical: '' };
	return { code: 'tlsrpt_ok', facts: { record, rua: parseTags(record).rua ?? null }, technical: record };
}

export function mapBimi(r: CheckResult): Mapped {
	const record = r.rows.find((x) => x.status === 'ok')?.value ?? null;
	if (!record) return { code: 'bimi_missing', facts: { record: null }, technical: '' };
	const tags = parseTags(record);
	return { code: 'bimi_ok', facts: { record, logo: tags.l || null, authority: tags.a || null }, technical: record };
}

/**
 * Only 127.0.0.0/8 answers (excluding 127.0.0.1 and the 127.255.255.0/24 error block)
 * count as listings. Anything else (parked/wildcard zones, refusals) is inconclusive.
 */
export function isGenuineListing(answers: string[]): boolean {
	return (
		answers.length > 0 &&
		answers.every((a) => /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(a) && a !== '127.0.0.1' && !a.startsWith('127.255.255.'))
	);
}

export type BlacklistSource = { spamhausDqs: boolean; source: 'agent' | 'worker' };

export function mapBlacklist(scan: BlacklistScan, { spamhausDqs, source }: BlacklistSource): Mapped {
	const checkedIps = scan.check.map((a) => ({ ip: a.ip, role: a.role }));
	const listed: Array<{ list: string; ip: string; role: string; codes: string[] }> = [];
	const inconclusive: Array<{ list: string; ip: string; reason: 'query_refused' | 'lookup_failed' | 'unexpected_answer' }> = [];
	const technical: string[] = [];

	for (const h of scan.hits) {
		technical.push(`${h.list} ${h.ip}: ${h.lookupFailed ? 'lookup failed' : h.interp.label}`);
		if (h.lookupFailed || (h.rcode !== 0 && h.rcode !== 3)) inconclusive.push({ list: h.list, ip: h.ip, reason: 'lookup_failed' });
		else if (h.interp.kind === 'query_error') inconclusive.push({ list: h.list, ip: h.ip, reason: 'query_refused' });
		else if (h.interp.kind === 'listed') {
			if (isGenuineListing(h.answers)) listed.push({ list: h.list, ip: h.ip, role: h.role, codes: h.answers });
			else inconclusive.push({ list: h.list, ip: h.ip, reason: 'unexpected_answer' });
		}
	}

	const facts = { checkedIps, listsChecked: scan.listCount, listed, inconclusive, spamhausDqs, source };
	const text = technical.join('\n');
	if (!scan.check.length) return { code: 'blacklist_no_ips', facts, technical: text };
	if (listed.length) return { code: 'blacklist_listed', facts, technical: text };
	if (inconclusive.length) return { code: 'blacklist_inconclusive', facts, technical: text };
	return { code: 'blacklist_clean', facts, technical: text };
}

export function mapDns(r: CheckResult): Mapped {
	const nameservers = r.rows
		.filter((x) => x.name !== 'NS count' && x.name !== 'SOA')
		.map((x) => ({ host: x.name, ips: x.status === 'ok' ? x.value.split(', ') : [], resolves: x.status === 'ok' }));
	const soaSerial = r.rows.find((x) => x.name === 'SOA')?.value ?? null;
	const facts = { nameservers, count: nameservers.length, soaSerial };
	const technical = nameservers.map((n) => `NS ${n.host}${n.ips.length ? ` (${n.ips.join(', ')})` : ' (unresolved)'}`).join('\n');
	if (!nameservers.length) return { code: 'dns_no_nameservers', facts, technical };
	if (nameservers.length < 2) return { code: 'dns_single_ns', facts, technical };
	if (nameservers.some((n) => !n.resolves)) return { code: 'dns_ns_unresolved', facts, technical };
	return { code: 'dns_ok', facts, technical };
}

function httpFacts(r: CheckResult) {
	const get = (name: string) => r.rows.find((x) => x.name === name)?.value ?? null;
	const status = get('Status');
	return {
		url: get('URL') ?? `https://${r.query}`,
		status: numberOrNull(status ?? undefined),
		location: get('Location'),
		error: get('Error'),
	};
}

function httpReachable(f: ReturnType<typeof httpFacts>): boolean {
	return f.status !== null && f.status < 400;
}

/** `www` is only consulted when the apex itself cannot be reached. */
export function mapHttps(apex: CheckResult, www?: CheckResult): Mapped {
	const a = httpFacts(apex);
	const w = www ? httpFacts(www) : null;
	const line = (f: ReturnType<typeof httpFacts>) => `${f.url}: ${f.status ?? f.error ?? 'no response'}${f.location ? ` → ${f.location}` : ''}`;
	const technical = [a, w].filter((f): f is ReturnType<typeof httpFacts> => f !== null).map(line).join('\n');
	const facts = { apex: a, www: w };
	if (httpReachable(a)) return { code: 'https_ok', facts, technical };
	if (w && httpReachable(w)) return { code: 'https_www_only', facts, technical };
	if (a.status !== null) return { code: 'https_http_error', facts, technical };
	if (w?.status != null) return { code: 'https_http_error', facts, technical };
	return { code: 'https_fail', facts, technical };
}
