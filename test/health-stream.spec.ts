import { createExecutionContext, SELF, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { HEALTH_CHECK_IDS, toCheck, type HealthCheck } from '../worker/health/codes';
import { allowedOrigin, handleHealthCheck, type HealthEnv } from '../worker/health/handler';
import { runJobs } from '../worker/health/run';

const URL = 'http://example.com/api/v1/health-check';
const SITE = 'https://www.thecuckoocamp.co.uk';

type Event = { event: string; data: Record<string, unknown> };

async function readEvents(res: Response): Promise<Event[]> {
	const text = await res.text();
	return text
		.split('\n\n')
		.filter(Boolean)
		.map((block) => {
			const event = /^event: (.+)$/m.exec(block)![1];
			const data = JSON.parse(/^data: (.+)$/m.exec(block)![1]) as Record<string, unknown>;
			return { event, data };
		});
}

describe('origins', () => {
	it('allows Cloudflare Pages previews of the website, and nothing like them', () => {
		for (const o of ['https://abc123.cuckoo-site.pages.dev', 'https://feat-health-check.cuckoo-site.pages.dev']) expect(allowedOrigin(o, {})).toBe(o);
		for (const o of [
			'https://cuckoo-site.pages.dev.evil.com',
			'https://evil.pages.dev',
			'http://abc.cuckoo-site.pages.dev',
			'https://a.b.cuckoo-site.pages.dev',
			'https://xcuckoo-site.pages.dev',
		])
			expect(allowedOrigin(o, {})).toBeNull();
	});

	it('preflight from a Pages preview gets CORS headers', async () => {
		const origin = 'https://pr-12.cuckoo-site.pages.dev';
		const res = await SELF.fetch(URL, { method: 'OPTIONS', headers: { origin, 'access-control-request-method': 'POST' } });
		expect(res.headers.get('access-control-allow-origin')).toBe(origin);
		const rr = await SELF.fetch('http://example.com/api/v1/report-request', { method: 'OPTIONS', headers: { origin } });
		expect(rr.headers.get('access-control-allow-origin')).toBe(origin);
	});
});

describe('errors before streaming stay plain JSON', () => {
	it('400 / 403 with Accept: text/event-stream', async () => {
		const headers = { 'content-type': 'application/json', accept: 'text/event-stream', origin: SITE, 'cf-connecting-ip': '198.51.100.90' };
		const bad = await SELF.fetch(URL, { method: 'POST', headers, body: JSON.stringify({ domain: '10.0.0.1' }) });
		expect(bad.status).toBe(400);
		expect(bad.headers.get('content-type')).toContain('application/json');
		expect(await bad.json()).toEqual({ error: 'invalid_domain' });
		const ts = await SELF.fetch(URL, { method: 'POST', headers, body: JSON.stringify({ domain: 'example.org', turnstileToken: 'x' }) });
		expect(ts.status).toBe(403);
		expect(ts.headers.get('content-type')).toContain('application/json');
		expect(await ts.json()).toEqual({ error: 'turnstile_failed' });
	});
});

describe('streaming', () => {
	beforeEach(() => {
		vi.spyOn(console, 'log').mockImplementation(() => {});
		vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
			const url = String(input instanceof Request ? input.url : input);
			if (url.includes('turnstile/v0/siteverify')) return Response.json({ success: true });
			if (url.includes('cloudflare-dns.com')) return Response.json({ Status: 3 });
			throw new Error('offline');
		});
	});
	afterEach(() => vi.restoreAllMocks());

	const env: HealthEnv = { TURNSTILE_SECRET: 'test' };
	const req = (domain: string, accept?: string) =>
		new Request(URL, {
			method: 'POST',
			headers: { 'content-type': 'application/json', origin: SITE, ...(accept ? { accept } : {}) },
			body: JSON.stringify({ domain, turnstileToken: 'tok' }),
		});

	it('sends start, ten checks, then done (complete), and replays from cache', async () => {
		const domain = `stream-${crypto.randomUUID().slice(0, 8)}.org`;
		const ctx = createExecutionContext();
		const res = await handleHealthCheck(req(domain, 'text/event-stream'), env, ctx);
		expect(res.status).toBe(200);
		expect(res.headers.get('content-type')).toBe('text/event-stream; charset=utf-8');
		expect(res.headers.get('cache-control')).toBe('no-cache');
		expect(res.headers.get('access-control-allow-origin')).toBe(SITE);
		expect(res.headers.get('vary')).toBe('Origin');
		const events = await readEvents(res);
		await waitOnExecutionContext(ctx);

		expect(events.map((e) => e.event)).toEqual(['start', ...Array(10).fill('check'), 'done']);
		const [start, ...rest] = events;
		const done = rest.pop()!;
		expect(start.data).toEqual({ domain, checkedAt: done.data.checkedAt, expected: 10, checks: [...HEALTH_CHECK_IDS] });
		expect(new Set(rest.map((e) => e.data.id))).toEqual(new Set(HEALTH_CHECK_IDS));
		for (const e of rest) expect(Object.keys(e.data).sort()).toEqual(['code', 'facts', 'id', 'status', 'technical']);
		expect(done.data).toMatchObject({ domain, complete: true });
		expect(Object.keys(done.data).sort()).toEqual(['checkedAt', 'checks', 'complete', 'domain', 'overall', 'score']);
		expect(done.data.checks).toHaveLength(10);

		const ctx2 = createExecutionContext();
		const replay = await readEvents(await handleHealthCheck(req(domain, 'text/event-stream'), env, ctx2));
		await waitOnExecutionContext(ctx2);
		expect(replay.map((e) => e.event)).toEqual(['start', ...Array(10).fill('check'), 'done']);
		expect(replay.at(-1)!.data).toEqual(done.data);

		const json = await handleHealthCheck(req(domain), env, createExecutionContext());
		expect(json.headers.get('content-type')).toContain('application/json');
		const body = (await json.json()) as Record<string, unknown>;
		expect(body).not.toHaveProperty('complete');
		expect(body.checkedAt).toBe(done.data.checkedAt);
	});
});

describe('runJobs onCheck', () => {
	it('reports checks in completion order and never after the deadline', async () => {
		const seen: string[] = [];
		const later = (id: HealthCheck['id'], ms: number) => ({
			id,
			run: () => new Promise<HealthCheck>((r) => setTimeout(() => r(toCheck(id, { code: 'bimi_ok', facts: {}, technical: '' })), ms)),
		});
		const out = await runJobs([later('spf', 30), later('dmarc', 5), later('mx', 400)], 100, (c) => seen.push(c.id));
		expect(seen).toEqual(['dmarc', 'spf']);
		expect(out.complete).toBe(false);
		await new Promise((r) => setTimeout(r, 400));
		expect(seen).toEqual(['dmarc', 'spf']);
	});
});
