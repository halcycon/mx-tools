import { createExecutionContext, env, SELF, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleHealthCheck } from '../worker/health/handler';
import { attribution, beginUsage, type UsageRow } from '../worker/usage/store';
import { handleUsageCron, previousLondonDay } from '../worker/usage/digest';
import { currentLondonDay } from '../worker/usage/time';
import type { ReportEnv } from '../worker/report/config';

const DB = (env as unknown as { DB: D1Database }).DB;
const SITE = 'https://www.thecuckoocamp.co.uk';

beforeEach(async () => {
	await DB.batch([DB.prepare('DELETE FROM health_usage'), DB.prepare('DELETE FROM health_usage_digests')]);
});
afterEach(() => vi.restoreAllMocks());

describe('website usage collection', () => {
	it('strips arbitrary URL parameters, credentials and fragments; bounds and allowlists UTM values', () => {
		expect(attribution({ pageUrl: 'https://u:p@example.org/check?token=secret#hash', referrer: 'javascript:bad', utm: { utm_source: 'a\nb', utm_campaign: 'x'.repeat(300), secret: 'bad' } }, 'https://search.example/?q=private')).toEqual({
			page: 'https://example.org/check', referrer: null, utm: { utm_source: 'ab', utm_campaign: 'x'.repeat(200) },
		});
		expect(attribution({ referrer: '' }, 'https://site.example/').referrer).toBeNull();
		expect(attribution({}, 'https://site.example/?private=secret').referrer).toBe('https://site.example/');
	});

	it('records JSON, streaming and cached checks once each, but excludes rejected requests and main UI routes', async () => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
		vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
			const url = String(input instanceof Request ? input.url : input);
			if (url.includes('siteverify')) return Response.json({ success: true });
			if (url.includes('cloudflare-dns.com')) return Response.json({ Status: 3 });
			throw new Error('offline');
		});
		const domain = `usage-${crypto.randomUUID().slice(0, 8)}.org`;
		for (const accept of ['application/json', 'text/event-stream', 'application/json']) {
			const ctx = createExecutionContext();
			const res = await handleHealthCheck(new Request('https://dart.example/api/v1/health-check', {
				method: 'POST', headers: { origin: SITE, accept, 'cf-connecting-ip': '198.51.100.5' },
				body: JSON.stringify({ domain, turnstileToken: 'tok', attribution: { referrer: 'https://search.example/', utm: { utm_source: 'newsletter' } } }),
			}), { DB, TURNSTILE_SECRET: 'test' }, ctx);
			await res.text();
			await waitOnExecutionContext(ctx);
		}
		const rows = (await DB.prepare('SELECT * FROM health_usage ORDER BY requested_at,id').all<UsageRow>()).results;
		expect(rows).toHaveLength(3);
		expect(rows.every(r => r.domain === domain && r.outcome === 'ok' && r.client_ip === '198.51.100.5')).toBe(true);
		expect(rows.filter(r => r.cached)).toHaveLength(2);
		expect(rows[0].utm_json).toBe('{"utm_source":"newsletter"}');
		// No token: fails before recording. OPTIONS and the main UI route also stay out.
		await SELF.fetch('https://dart.example/api/v1/health-check', { method: 'POST', body: JSON.stringify({ domain }) });
		await SELF.fetch('https://dart.example/api/v1/health-check', { method: 'OPTIONS' });
		await SELF.fetch('https://dart.example/api/lookup?q=');
		expect((await DB.prepare('SELECT COUNT(*) AS n FROM health_usage').first<{ n: number }>())?.n).toBe(3);
	});

	it('records the day for catch-up even if the cron misses a whole day', async () => {
		const now = Date.parse('2026-11-04T12:00:00Z');
		vi.spyOn(Date, 'now').mockReturnValue(now);
		await beginUsage({ DB }, new Request('https://example.org'), 'example.org', null);
		const send = vi.fn().mockResolvedValue({});
		const bindings = { DB, EMAIL: { send }, REPORT_FROM: 'reports@example.org', LEAD_NOTIFY_TO: 'admin@example.org' } as unknown as ReportEnv;
		await handleUsageCron(bindings, Date.parse('2026-11-06T00:00:00Z'));
		expect(send).toHaveBeenCalledTimes(2);
		expect(send.mock.calls[0][0].subject).toContain('2026-11-04');
	});

	it('fails open when storage is unavailable', async () => {
		const request = new Request('https://example.org');
		expect(await beginUsage({}, request, 'example.org', null)).toBeNull();
		const log = vi.spyOn(console, 'log').mockImplementation(() => {});
		const broken = { prepare() { throw new Error('no database'); } } as unknown as D1Database;
		expect(await beginUsage({ DB: broken }, request, 'example.org', null)).toBeNull();
		expect(log).toHaveBeenCalledWith('{"event":"health_usage_storage_failed","operation":"insert"}');
	});
});

describe('daily UK summary', () => {
	it('uses calendar days through summer, winter and both clock changes', () => {
		for (const [now, start, end] of [
			['2026-01-02T00:00:00Z', '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z'],
			['2026-07-01T23:00:00Z', '2026-06-30T23:00:00Z', '2026-07-01T23:00:00Z'],
			['2026-03-29T23:00:00Z', '2026-03-29T00:00:00Z', '2026-03-29T23:00:00Z'],
			['2026-10-26T00:00:00Z', '2026-10-24T23:00:00Z', '2026-10-26T00:00:00Z'],
		]) {
			const result = previousLondonDay(Date.parse(now));
			expect(result.start).toBe(Date.parse(start));
			expect(result.end).toBe(Date.parse(end));
			expect(currentLondonDay(result.start)).toEqual(result);
		}
	});

	const now = Date.parse('2026-11-05T00:00:00Z');
	const setup = () => {
		const send = vi.fn().mockResolvedValue({ messageId: 'test' });
		return { send, bindings: { DB, EMAIL: { send }, REPORT_FROM: 'reports@example.org', LEAD_NOTIFY_TO: 'admin@example.org' } as unknown as ReportEnv };
	};
	async function insert(id: string, at = now - 1000) {
		await DB.prepare(`INSERT INTO health_usage(id,domain,requested_at,client_ip,utm_json,outcome) VALUES(?,?,?,?,?,?)`)
			.bind(id, 'example.org', at, '198.51.100.1', '{"utm_source":"<newsletter>"}', 'ok').run();
	}

	it('sends only yesterday, escapes attribution, sends once per day and cleans up old records', async () => {
		const { send, bindings } = setup();
		await insert('yesterday');
		await insert('today', now);
		await insert('old', now - 8 * 86_400_000);
		await handleUsageCron(bindings, now);
		expect(send).toHaveBeenCalledTimes(1);
		const mail = send.mock.calls[0][0];
		expect(mail.to).toBe('admin@example.org');
		expect(mail.subject).toContain('2026-11-04');
		expect(mail.text).toContain('1 checks across 1 domains');
		expect(mail.text).toContain('198.51.100.1');
		expect(mail.html).toContain('&lt;newsletter&gt;');
		expect(await DB.prepare("SELECT id FROM health_usage WHERE id='old'").first()).toBeNull();
		await handleUsageCron(bindings, now + 15 * 60_000);
		expect(send).toHaveBeenCalledTimes(1);
	});

	it('resumes unsent pages after failure, including after another midnight', async () => {
		const { send, bindings } = setup();
		await DB.batch(Array.from({ length: 101 }, (_, i) => DB.prepare('INSERT INTO health_usage(id,domain,requested_at,utm_json) VALUES(?,?,?,?)').bind(`row-${i}`, 'example.org', now - 1000, '{}')));
		send.mockResolvedValueOnce({}).mockRejectedValueOnce(new Error('email offline'));
		await expect(handleUsageCron(bindings, now)).rejects.toThrow('email offline');
		expect((await DB.prepare('SELECT next_offset FROM health_usage_digests').first<{ next_offset: number }>())?.next_offset).toBe(100);
		send.mockClear();
		await handleUsageCron(bindings, now + 86_400_000);
		expect(send).toHaveBeenCalledTimes(2); // Yesterday's page 2, then today's empty summary.
		expect(send.mock.calls[0][0].subject).toContain('(2/2)');
		expect(send.mock.calls[1][0].text).toContain('No checks recorded.');
	});

	it('does not overlap an active sender lease and cleans retention even without a recipient', async () => {
		const { send, bindings } = setup();
		await DB.prepare('INSERT INTO health_usage_digests(day,start_at,end_at,lease_until) VALUES(?,?,?,?)').bind('2026-11-04', now - 86_400_000, now, now + 60_000).run();
		await handleUsageCron(bindings, now);
		expect(send).not.toHaveBeenCalled();
		await insert('old', now - 8 * 86_400_000);
		await handleUsageCron({ ...bindings, LEAD_NOTIFY_TO: '' }, now);
		expect(await DB.prepare("SELECT id FROM health_usage WHERE id='old'").first()).toBeNull();
	});
});
