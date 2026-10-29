import { SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { allowedOrigin } from '../worker/health/handler';

const URL = 'http://example.com/api/v1/health-check';
const SITE = 'https://www.thecuckoocamp.co.uk';

function post(body: unknown, headers: Record<string, string> = {}) {
	return SELF.fetch(URL, {
		method: 'POST',
		headers: { 'content-type': 'application/json', origin: SITE, ...headers },
		body: typeof body === 'string' ? body : JSON.stringify(body),
	});
}

describe('POST /api/v1/health-check', () => {
	it('answers CORS preflight for the site origins only', async () => {
		for (const origin of [SITE, 'https://thecuckoocamp.co.uk']) {
			const res = await SELF.fetch(URL, {
				method: 'OPTIONS',
				headers: { origin, 'access-control-request-method': 'POST', 'access-control-request-headers': 'content-type' },
			});
			expect(res.status).toBe(204);
			expect(res.headers.get('access-control-allow-origin')).toBe(origin);
			expect(res.headers.get('access-control-allow-methods')).toContain('POST');
			expect(res.headers.get('access-control-allow-headers')).toContain('content-type');
		}
		const evil = await SELF.fetch(URL, { method: 'OPTIONS', headers: { origin: 'https://evil.example' } });
		expect(evil.headers.get('access-control-allow-origin')).toBeNull();
		const hugo = await SELF.fetch(URL, { method: 'OPTIONS', headers: { origin: 'http://localhost:1313' } });
		expect(hugo.headers.get('access-control-allow-origin')).toBeNull();
	});

	it('allows Hugo dev origins only behind the env flag', () => {
		expect(allowedOrigin('http://localhost:1313', { HEALTH_CHECK_ALLOW_DEV_ORIGINS: 'true' })).toBe('http://localhost:1313');
		expect(allowedOrigin('http://localhost:1313', { HEALTH_CHECK_ALLOW_DEV_ORIGINS: 'false' })).toBeNull();
		expect(allowedOrigin('http://localhost:5173', { HEALTH_CHECK_ALLOW_DEV_ORIGINS: 'true' })).toBeNull();
	});

	it('rejects invalid domains and bad bodies with 400 invalid_domain', async () => {
		for (const body of [{ domain: '10.0.0.1', turnstileToken: 'x' }, { domain: 'printer.local' }, {}, 'not json']) {
			const res = await post(body);
			expect(res.status).toBe(400);
			expect(await res.json()).toEqual({ error: 'invalid_domain' });
			expect(res.headers.get('access-control-allow-origin')).toBe(SITE);
		}
	});

	it('fails closed with 403 turnstile_failed (no secret configured / missing token)', async () => {
		const res = await post({ domain: 'example.org', turnstileToken: 'XXXX.DUMMY.TOKEN' }, { 'cf-connecting-ip': '198.51.100.1' });
		expect(res.status).toBe(403);
		expect(await res.json()).toEqual({ error: 'turnstile_failed' });
		const missing = await post({ domain: 'example.org' }, { 'cf-connecting-ip': '198.51.100.2' });
		expect(missing.status).toBe(403);
	});

	it('rate limits per client with 429 rate_limited', async () => {
		const statuses: number[] = [];
		for (let i = 0; i < 5; i++) {
			const res = await post({ domain: 'example.org' }, { 'cf-connecting-ip': '203.0.113.77' });
			statuses.push(res.status);
		}
		expect(statuses.slice(0, 3)).toEqual([403, 403, 403]);
		expect(statuses.at(-1)).toBe(429);
		const other = await post({ domain: 'example.org' }, { 'cf-connecting-ip': '203.0.113.78' });
		expect(other.status).toBe(403);
	});

	it('rejects other methods', async () => {
		const res = await SELF.fetch(URL);
		expect(res.status).toBe(405);
	});

	it('leaves existing API CORS behaviour unchanged', async () => {
		const res = await SELF.fetch('http://example.com/api/lookup', { method: 'OPTIONS' });
		expect(res.headers.get('access-control-allow-origin')).toBe('*');
	});
});
