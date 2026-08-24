import { SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import { plannedChecks } from '../worker/checks/run';

describe('mx-tools API', () => {
	it('/api/health', async () => {
		const res = await SELF.fetch('http://example.com/api/health');
		expect(res.status).toBe(200);
		const body = await res.json<{ ok: boolean; service: string }>();
		expect(body.ok).toBe(true);
		expect(body.service).toBe('mx-tools');
	});

	it('/api/tools lists commands', async () => {
		const res = await SELF.fetch('http://example.com/api/tools');
		const body = await res.json<{ tools: Array<{ id: string }> }>();
		expect(body.tools.some((t) => t.id === 'mx')).toBe(true);
	});

	it('/api/lookup parses query', async () => {
		const res = await SELF.fetch('http://example.com/api/lookup?q=a:example.com');
		expect(res.status).toBe(200);
		const body = await res.json<{ tool: string; results: unknown[] }>();
		expect(body.tool).toBe('a');
		expect(body.results.length).toBeGreaterThan(0);
	});

	it('plans auto and full health suites', () => {
		expect(plannedChecks('auto', 'example.com')).toEqual(['mx', 'spf', 'dmarc', 'blacklist', 'soa']);
		expect(plannedChecks('full', 'example.com').length).toBe(16);
	});

	it('/api/config does not leak secrets', async () => {
		const res = await SELF.fetch('http://example.com/api/config');
		const body = await res.json<Record<string, unknown>>();
		expect(body.spamhausDqsConfigured).toBe(false);
		expect(body).not.toHaveProperty('SPAMHAUS_DQS_KEY');
	});
});
