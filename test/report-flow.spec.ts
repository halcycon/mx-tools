import { env } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildReport, toCheck } from '../worker/health/codes';
import { handleReportConfirm, handleReportRequest, type FullReportEnv } from '../worker/report/handler';
import { failReport, handleReportCron, processReport } from '../worker/report/queue';
import { getRequest } from '../worker/report/store';

const DB = (env as unknown as { DB: D1Database }).DB;
const SECRETS = ['turnstile-secret-xyz', 'hmac-secret-xyz', 'access-secret-xyz'];
const SITE = 'https://www.thecuckoocamp.co.uk';

type Sent = { to: unknown; subject: string; html?: string; text?: string; replyTo?: unknown };

function makeEnv(over: Record<string, string> = {}) {
	const sent: Sent[] = [];
	const queued: Array<{ id: string }> = [];
	const e = {
		DB,
		EMAIL: { send: async (m: Sent) => (sent.push(m), { messageId: String(sent.length) }) },
		REPORT_QUEUE: { send: async (b: { id: string }) => void queued.push(b) },
		TURNSTILE_SECRET: SECRETS[0],
		AGENT_HMAC_SECRET: SECRETS[1],
		AGENT_CLIENT_SECRET: SECRETS[2],
		REPORT_FROM: 'reports@thecuckoocamp.co.uk',
		REPLY_TO: 'adam@example.net',
		LEAD_NOTIFY_TO: 'leads@example.net',
		SITE_URL: SITE,
		BOOKING_URL: `${SITE}/contact/`,
		...over,
	} as unknown as FullReportEnv;
	return { e, sent, queued };
}

const fakeRun = async (domain: string) => ({
	report: buildReport(domain, [toCheck('dmarc', { code: 'dmarc_policy_none', facts: {}, technical: 'v=DMARC1; p=none' })], new Date()),
	usedAgent: true,
});

let n = 0;
function body(over: Record<string, unknown> = {}) {
	n += 1;
	return { name: 'Ann', email: `ann${n}-${crypto.randomUUID().slice(0, 6)}@example.org`, organisation: '', domain: `site${n}-${crypto.randomUUID().slice(0, 6)}.org`, discoveryCall: true, consent: true, turnstileToken: 'tok', ...over };
}

function request(b: unknown, ip = `203.0.113.${n % 250}`) {
	return new Request('https://dart.thecuckoocamp.co.uk/api/v1/report-request', {
		method: 'POST',
		headers: { 'content-type': 'application/json', origin: SITE, 'cf-connecting-ip': ip },
		body: JSON.stringify(b),
	});
}

let logs: string[] = [];
beforeEach(() => {
	logs = [];
	vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => void logs.push(a.join(' ')));
	vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
		if (String(input instanceof Request ? input.url : input).includes('turnstile/v0/siteverify')) return Response.json({ success: true });
		throw new Error('unexpected fetch');
	});
});
afterEach(() => vi.restoreAllMocks());

function expectNoSecrets(...texts: string[]) {
	for (const t of [...texts, ...logs]) for (const s of SECRETS) expect(t).not.toContain(s);
}

describe('full report flow', () => {
	it('request → confirm → queue → report + lead emails', async () => {
		const { e, sent, queued } = makeEnv();
		const b = body();
		const res = await handleReportRequest(request(b), e);
		const resText = await res.text();
		expect(res.status).toBe(202);
		expect(JSON.parse(resText)).toEqual({ ok: true, delayed: false });
		expect(res.headers.get('access-control-allow-origin')).toBe(SITE);

		expect(sent).toHaveLength(1);
		expect(sent[0].to).toBe(b.email);
		const link = /https:\/\/dart\.thecuckoocamp\.co\.uk\/api\/v1\/report-confirm\?token=[\w-]+/.exec(sent[0].text!)![0];

		const confirm = await handleReportConfirm(new Request(link), e);
		expect(confirm.status).toBe(303);
		expect(confirm.headers.get('location')).toBe(`${SITE}/health-check/thanks/?status=confirmed`);
		expect(queued).toHaveLength(1);

		const again = await handleReportConfirm(new Request(link), e);
		expect(again.headers.get('location')).toContain('status=invalid');
		expect(queued).toHaveLength(1);

		expect(await processReport(e, queued[0].id, Date.now(), fakeRun)).toBe('sent');
		const [report, lead] = sent.slice(1);
		expect(report.to).toBe(b.email);
		expect(report.subject).toContain(b.domain);
		expect(report.replyTo).toBe('adam@example.net');
		expect(lead.to).toBe('leads@example.net');
		expect(lead.replyTo).toBe(b.email);
		expect(lead.subject).toContain('Call request');
		const row = await getRequest(DB, queued[0].id);
		expect(row).toMatchObject({ status: 'sent', wants_call: 1, overall: 'fail' });

		expect(await processReport(e, queued[0].id, Date.now(), fakeRun)).toBe('skipped');
		expect(sent).toHaveLength(3);
		expectNoSecrets(resText, ...sent.map((m) => `${m.html}${m.text}`));
		for (const l of logs) expect(l).not.toContain(b.email);
	});

	it('rejects missing consent and bad input with field hints', async () => {
		const { e, sent } = makeEnv();
		for (const [over, error, field] of [
			[{ consent: false }, 'consent_required', 'consent'],
			[{ email: 'nope' }, 'invalid_email', 'email'],
			[{ email: 'x@mailinator.com' }, 'invalid_email', 'email'],
			[{ domain: '10.0.0.1' }, 'invalid_domain', 'domain'],
			[{ name: '' }, 'invalid_name', 'name'],
		] as const) {
			const res = await handleReportRequest(request(body(over)), e);
			expect(res.status).toBe(400);
			expect(await res.json()).toEqual({ error, fields: { [field]: 'invalid' } });
		}
		expect(sent).toHaveLength(0);
	});

	it('rate limits per IP with a generic 429 + retryAfter before any email', async () => {
		const { e, sent } = makeEnv();
		const ip = '198.51.100.200';
		for (let i = 0; i < 5; i++) expect((await handleReportRequest(request(body(), ip), e)).status).toBe(202);
		const res = await handleReportRequest(request(body(), ip), e);
		expect(res.status).toBe(429);
		const j = (await res.json()) as { error: string; retryAfter: number };
		expect(j.error).toBe('rate_limited');
		expect(j.retryAfter).toBeGreaterThan(3500);
		expect(res.headers.get('retry-after')).toBe(String(j.retryAfter));
		expect(Object.keys(j).sort()).toEqual(['error', 'retryAfter']);
		expect(sent).toHaveLength(5);
	});

	it('sends at most one confirmation per address per 10 minutes, silently', async () => {
		const { e, sent } = makeEnv();
		const b = body();
		expect((await handleReportRequest(request(b), e)).status).toBe(202);
		const second = await handleReportRequest(request({ ...b, domain: 'other-domain.org' }), e);
		expect(second.status).toBe(202);
		expect(await second.json()).toEqual({ ok: true, delayed: false });
		expect(sent).toHaveLength(1);
	});

	it('daily cap: accepts, defers on confirm, tells the visitor it is delayed, notifies Adam once, cron releases later', async () => {
		const { e, sent, queued } = makeEnv({ DAILY_REPORT_CAP: '0' });
		await handleReportRequest(request(body()), e);
		const link = /https:\S+token=[\w-]+/.exec(sent.at(-1)!.text!)![0];
		const res = await handleReportConfirm(new Request(link), e);
		expect(res.headers.get('location')).toContain('status=delayed');
		expect(queued).toHaveLength(0);
		const capMails = sent.filter((m) => m.subject.includes('daily cap'));
		expect(capMails.length).toBeLessThanOrEqual(1);

		const lifted = makeEnv();
		await handleReportCron({ ...lifted.e } as never);
		expect(lifted.queued.length).toBeGreaterThanOrEqual(1);
	});

	it('final failure sends an apology and notifies Adam', async () => {
		const { e, sent, queued } = makeEnv();
		const b = body();
		await handleReportRequest(request(b), e);
		const link = /https:\S+token=[\w-]+/.exec(sent[0].text!)![0];
		await handleReportConfirm(new Request(link), e);
		await expect(processReport(e, queued[0].id, Date.now(), async () => Promise.reject(new Error('agent down')))).rejects.toThrow();
		await failReport(e, queued[0].id);
		expect(sent.some((m) => m.to === b.email && m.text?.includes("couldn't finish"))).toBe(true);
		expect(sent.some((m) => m.to === 'leads@example.net' && m.subject.startsWith('Full report failed'))).toBe(true);
		expect((await getRequest(DB, queued[0].id))?.status).toBe('failed');
	});

	it('an unknown token lands on the invalid thanks page', async () => {
		const { e } = makeEnv();
		const res = await handleReportConfirm(new Request('https://dart.thecuckoocamp.co.uk/api/v1/report-confirm?token=bogus'), e);
		expect(res.headers.get('location')).toBe(`${SITE}/health-check/thanks/?status=invalid`);
	});
});
