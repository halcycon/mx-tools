import { env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { DAY, HOUR, readLimits } from '../worker/report/config';
import { cleanup, consumeToken, createPending, getRequest, hashEmail, hashIp, newToken, tokenExpired } from '../worker/report/store';

const DB = (env as unknown as { DB: D1Database }).DB;
const L = readLimits({});

async function pending(createdAt: number) {
	return createPending(
		DB,
		{ name: 'Ann', email: 'ann@example.org', organisation: 'Charity', domain: 'example.org', wantsCall: true, ipHash: await hashIp('1.2.3.4'), emailHash: await hashEmail('ann@example.org') },
		createdAt,
		L,
	);
}

describe('confirmation token lifecycle', () => {
	it('tokens are long, URL-safe and unique', () => {
		const a = newToken();
		expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(newToken()).not.toBe(a);
	});

	it('stores only the token hash', async () => {
		const { id, token } = await pending(Date.now());
		const row = await getRequest(DB, id);
		expect(row?.token_hash).toMatch(/^[0-9a-f]{64}$/);
		expect(JSON.stringify(row)).not.toContain(token);
	});

	it('is single-use', async () => {
		const now = Date.now();
		const { id, token } = await pending(now);
		const first = await consumeToken(DB, token, now + 1000);
		expect(first?.id).toBe(id);
		expect(first?.confirmed_at).toBe(now + 1000);
		expect(await consumeToken(DB, token, now + 2000)).toBeNull();
		expect(await tokenExpired(DB, token)).toBe(false);
	});

	it('expires after 24 hours', async () => {
		const now = Date.now();
		const { token } = await pending(now - 25 * HOUR);
		expect(await consumeToken(DB, token, now)).toBeNull();
		expect(await tokenExpired(DB, token)).toBe(true);
	});

	it('rejects unknown and oversized tokens', async () => {
		expect(await consumeToken(DB, 'nope', Date.now())).toBeNull();
		expect(await consumeToken(DB, 'x'.repeat(500), Date.now())).toBeNull();
		expect(await tokenExpired(DB, 'nope')).toBe(false);
	});

	it('cleanup deletes expired pending rows, IP hashes after a day, and personal data after retention', async () => {
		const now = Date.now();
		const expired = await pending(now - 25 * HOUR);
		const fresh = await pending(now - 2 * HOUR);
		const old = await pending(now - 91 * DAY);
		await DB.prepare(`UPDATE report_requests SET status='sent', token_hash=NULL WHERE id=?`).bind(old.id).run();
		const sentYesterday = await pending(now - 2 * DAY);
		await DB.prepare(`UPDATE report_requests SET status='sent', token_hash=NULL WHERE id=?`).bind(sentYesterday.id).run();

		const removed = await cleanup(DB, now, L);
		expect(removed.expiredPending).toBeGreaterThanOrEqual(1);
		expect(await getRequest(DB, expired.id)).toBeNull();
		expect(await getRequest(DB, old.id)).toBeNull();
		expect((await getRequest(DB, fresh.id))?.ip_hash).not.toBeNull();
		expect((await getRequest(DB, sentYesterday.id))?.ip_hash).toBeNull();
	});
});
