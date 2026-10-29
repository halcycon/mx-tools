import { DAY, HOUR, MINUTE, type Limits } from './config';
import { dailyCapReached } from './store';

export type WindowResult = { ok: true } | { ok: false; retryAfter: number };

/**
 * Sliding-window check over event timestamps (unix ms). When over the limit, `retryAfter`
 * is the seconds until enough events age out to allow one more.
 */
export function windowCheck(times: number[], limit: number, windowMs: number, now: number): WindowResult {
	const inWindow = times.filter((t) => t > now - windowMs).sort((a, b) => a - b);
	if (inWindow.length < limit) return { ok: true };
	if (limit <= 0) return { ok: false, retryAfter: Math.ceil(windowMs / 1000) };
	const freesAt = inWindow[inWindow.length - limit] + windowMs;
	return { ok: false, retryAfter: Math.max(1, Math.ceil((freesAt - now) / 1000)) };
}

type Column = 'created_at' | 'queued_at';
type KeyColumn = 'ip_hash' | 'email_hash' | 'domain';

async function times(db: D1Database, col: Column, keyCol: KeyColumn, key: string, since: number): Promise<number[]> {
	const { results } = await db
		.prepare(`SELECT ${col} AS t FROM report_requests WHERE ${keyCol} = ? AND ${col} > ?`)
		.bind(key, since)
		.all<{ t: number }>();
	return results.map((r) => r.t);
}

type Rule = { name: string; col: Column; keyCol: KeyColumn; key: string; limit: number; windowMs: number };

async function evaluate(db: D1Database, rules: Rule[], now: number): Promise<{ ok: true } | { ok: false; retryAfter: number; rule: string }> {
	let worst: { retryAfter: number; rule: string } | null = null;
	for (const r of rules) {
		const res = windowCheck(await times(db, r.col, r.keyCol, r.key, now - r.windowMs), r.limit, r.windowMs, now);
		if (!res.ok && (!worst || res.retryAfter > worst.retryAfter)) worst = { retryAfter: res.retryAfter, rule: r.name };
	}
	return worst ? { ok: false, ...worst } : { ok: true };
}

export type RequestKeys = { ipHash: string; emailHash: string; domain: string };

/** Limits checked before a confirmation email is sent. Callers must not reveal which rule tripped. */
export function checkRequestLimits(db: D1Database, k: RequestKeys, now: number, l: Limits) {
	return evaluate(
		db,
		[
			{ name: 'ip_hour', col: 'created_at', keyCol: 'ip_hash', key: k.ipHash, limit: l.REPORT_IP_PER_HOUR, windowMs: HOUR },
			{ name: 'ip_day', col: 'created_at', keyCol: 'ip_hash', key: k.ipHash, limit: l.REPORT_IP_PER_DAY, windowMs: DAY },
			{ name: 'email_pending', col: 'created_at', keyCol: 'email_hash', key: k.emailHash, limit: l.REPORT_EMAIL_PENDING_PER_DAY, windowMs: DAY },
			...deliveryRules(k.emailHash, k.domain, l),
		],
		now,
	);
}

function deliveryRules(emailHash: string, domain: string, l: Limits): Rule[] {
	return [
		{ name: 'email_confirmed', col: 'queued_at', keyCol: 'email_hash', key: emailHash, limit: l.REPORT_EMAIL_CONFIRMED_PER_DAY, windowMs: DAY },
		{ name: 'domain_hour', col: 'queued_at', keyCol: 'domain', key: domain, limit: l.REPORT_DOMAIN_PER_HOUR, windowMs: HOUR },
		{ name: 'domain_day', col: 'queued_at', keyCol: 'domain', key: domain, limit: l.REPORT_DOMAIN_PER_DAY, windowMs: DAY },
	];
}

/** True when a confirmation email went to this address within the cooldown (don't send another). */
export async function inConfirmationCooldown(db: D1Database, emailHash: string, now: number, l: Limits): Promise<boolean> {
	const recent = await times(db, 'created_at', 'email_hash', emailHash, now - l.CONFIRM_EMAIL_COOLDOWN_MINUTES * MINUTE);
	return recent.length > 0;
}

export type DeliveryDecision = 'ok' | 'domain' | 'email' | 'cap';

/** Re-checked at confirm time (and for deferred rows), since several pending requests may confirm at once. */
export async function deliveryDecision(db: D1Database, emailHash: string, domain: string, now: number, l: Limits): Promise<DeliveryDecision> {
	if (await dailyCapReached(db, now, l.DAILY_REPORT_CAP)) return 'cap';
	const res = await evaluate(db, deliveryRules(emailHash, domain, l), now);
	if (res.ok) return 'ok';
	return res.rule.startsWith('domain') ? 'domain' : 'email';
}
