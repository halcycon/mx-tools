import { env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { DAY, HOUR, MINUTE, readLimits } from '../worker/report/config';
import { checkRequestLimits, deliveryDecision, inConfirmationCooldown, windowCheck } from '../worker/report/limits';
import { createPending, hashEmail, hashIp } from '../worker/report/store';

const DB = (env as unknown as { DB: D1Database }).DB;
const L = readLimits({});
const uid = () => crypto.randomUUID().slice(0, 8);

async function insert(opts: { email?: string; ip?: string; domain?: string; createdAt: number; queuedAt?: number }) {
	const emailHash = await hashEmail(opts.email ?? `${uid()}@example.org`);
	const ipHash = await hashIp(opts.ip ?? uid());
	const { id } = await createPending(
		DB,
		{ name: 'T', email: opts.email ?? 'x@example.org', organisation: null, domain: opts.domain ?? `${uid()}.org`, wantsCall: false, ipHash, emailHash },
		opts.createdAt,
		L,
	);
	if (opts.queuedAt) await DB.prepare(`UPDATE report_requests SET status='sent', queued_at=? WHERE id=?`).bind(opts.queuedAt, id).run();
	return { id, emailHash, ipHash };
}

describe('windowCheck', () => {
	const now = 10 * HOUR;
	it('allows under the limit and ignores events outside the window', () => {
		expect(windowCheck([now - 2 * HOUR, now - 10 * MINUTE], 2, HOUR, now)).toEqual({ ok: true });
	});
	it('computes retryAfter from the event that must age out', () => {
		const r = windowCheck([now - 50 * MINUTE, now - 20 * MINUTE, now - 5 * MINUTE], 2, HOUR, now);
		expect(r).toEqual({ ok: false, retryAfter: 40 * 60 });
	});
	it('limit 0 blocks for the whole window', () => {
		expect(windowCheck([], 0, HOUR, now)).toEqual({ ok: false, retryAfter: 3600 });
	});
	it('reads overrides from env and ignores junk', () => {
		const l = readLimits({ DAILY_REPORT_CAP: '5', REPORT_IP_PER_HOUR: 'lots', RETENTION_DAYS: '' });
		expect(l.DAILY_REPORT_CAP).toBe(5);
		expect(l.REPORT_IP_PER_HOUR).toBe(5);
		expect(l.RETENTION_DAYS).toBe(90);
	});
});

describe('request limits (D1)', () => {
	it('per IP: 5 per hour, 10 per day', async () => {
		const ip = `ip-${uid()}`;
		const now = Date.now();
		const ipHash = await hashIp(ip);
		for (let i = 0; i < 5; i++) await insert({ ip, createdAt: now - (50 - i) * MINUTE });
		const r = await checkRequestLimits(DB, { ipHash, emailHash: 'e', domain: 'd.org' }, now, L);
		expect(r).toMatchObject({ ok: false, rule: 'ip_hour' });
		if (!r.ok) expect(r.retryAfter).toBe(10 * 60);

		const ip2 = `ip-${uid()}`;
		for (let i = 0; i < 10; i++) await insert({ ip: ip2, createdAt: now - (20 - i) * HOUR });
		expect(await checkRequestLimits(DB, { ipHash: await hashIp(ip2), emailHash: 'e', domain: 'd.org' }, now, L)).toMatchObject({ ok: false, rule: 'ip_day' });
	});

	it('per email: 5 pending per day, 3 confirmed per day', async () => {
		const now = Date.now();
		const pending = `${uid()}@example.org`;
		for (let i = 0; i < 5; i++) await insert({ email: pending, createdAt: now - (10 - i) * HOUR });
		expect(await checkRequestLimits(DB, { ipHash: 'i', emailHash: await hashEmail(pending), domain: 'd.org' }, now, L)).toMatchObject({ ok: false, rule: 'email_pending' });

		const confirmed = `${uid()}@example.org`;
		for (let i = 0; i < 3; i++) await insert({ email: confirmed, createdAt: now - 30 * HOUR, queuedAt: now - (5 - i) * HOUR });
		expect(await checkRequestLimits(DB, { ipHash: 'i', emailHash: await hashEmail(confirmed), domain: 'd.org' }, now, L)).toMatchObject({ ok: false, rule: 'email_confirmed' });
	});

	it('per domain: 1 per hour, 3 per day (counted on delivered reports)', async () => {
		const now = Date.now();
		const domain = `${uid()}.org`;
		await insert({ domain, createdAt: now - 2 * HOUR, queuedAt: now - 30 * MINUTE });
		const hour = await checkRequestLimits(DB, { ipHash: 'i', emailHash: 'e', domain }, now, L);
		expect(hour).toMatchObject({ ok: false, rule: 'domain_hour' });
		if (!hour.ok) expect(hour.retryAfter).toBe(30 * 60);

		const d2 = `${uid()}.org`;
		for (const h of [20, 10, 2]) await insert({ domain: d2, createdAt: now - 21 * HOUR, queuedAt: now - h * HOUR });
		expect(await checkRequestLimits(DB, { ipHash: 'i', emailHash: 'e', domain: d2 }, now, L)).toMatchObject({ ok: false, rule: 'domain_day' });
		expect(await deliveryDecision(DB, 'e', d2, now, L)).toBe('domain');
		expect(await deliveryDecision(DB, 'e', `${uid()}.org`, now, L)).toBe('ok');
	});

	it('confirmation email cooldown is 10 minutes per address', async () => {
		const now = Date.now();
		const email = `${uid()}@example.org`;
		const { emailHash } = await insert({ email, createdAt: now - 9 * MINUTE });
		expect(await inConfirmationCooldown(DB, emailHash, now, L)).toBe(true);
		expect(await inConfirmationCooldown(DB, emailHash, now + 2 * MINUTE, L)).toBe(false);
	});

	it('daily cap defers delivery', async () => {
		const now = Date.now();
		const cap = readLimits({ DAILY_REPORT_CAP: '2' });
		await insert({ createdAt: now - HOUR, queuedAt: now - 30 * MINUTE });
		await insert({ createdAt: now - HOUR, queuedAt: now - 20 * MINUTE });
		expect(await deliveryDecision(DB, 'e', `${uid()}.org`, now, cap)).toBe('cap');
		expect(await deliveryDecision(DB, 'e', `${uid()}.org`, now + DAY, cap)).toBe('ok');
	});
});
