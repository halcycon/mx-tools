import { DAY, HOUR, type Limits } from './config';
import type { HealthReport } from '../health/codes';

export type ReportRequestRow = {
	id: string;
	token_hash: string | null;
	status: 'pending' | 'queued' | 'deferred' | 'sent' | 'failed';
	defer_reason: string | null;
	name: string;
	email: string;
	email_hash: string;
	organisation: string | null;
	domain: string;
	wants_call: number;
	ip_hash: string | null;
	created_at: number;
	expires_at: number;
	confirmed_at: number | null;
	queued_at: number | null;
	completed_at: number | null;
	report_sent_at: number | null;
	lead_sent_at: number | null;
	attempts: number;
};

const enc = new TextEncoder();

export async function sha256Hex(s: string): Promise<string> {
	const d = await crypto.subtle.digest('SHA-256', enc.encode(s));
	return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** 256-bit URL-safe token. Only its hash is stored. */
export function newToken(): string {
	const b = crypto.getRandomValues(new Uint8Array(32));
	return btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export const hashToken = (token: string) => sha256Hex(`report-token:${token}`);
export const hashEmail = (email: string) => sha256Hex(`report-email:${email.trim().toLowerCase()}`);
export const hashIp = (ip: string | null) => sha256Hex(`report-ip:${ip ?? 'unknown'}`);

export type NewRequest = {
	name: string;
	email: string;
	organisation: string | null;
	domain: string;
	wantsCall: boolean;
	ipHash: string;
	emailHash: string;
};

export async function createPending(db: D1Database, r: NewRequest, now: number, l: Limits): Promise<{ id: string; token: string }> {
	const id = crypto.randomUUID();
	const token = newToken();
	await db
		.prepare(
			`INSERT INTO report_requests (id, token_hash, status, name, email, email_hash, organisation, domain, wants_call, ip_hash, created_at, expires_at)
			 VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		)
		.bind(id, await hashToken(token), r.name, r.email, r.emailHash, r.organisation, r.domain, r.wantsCall ? 1 : 0, r.ipHash, now, now + l.TOKEN_TTL_HOURS * HOUR)
		.run();
	return { id, token };
}

export async function deleteRequest(db: D1Database, id: string): Promise<void> {
	await db.prepare('DELETE FROM report_requests WHERE id = ?').bind(id).run();
}

/** Single-use: atomically consumes a live pending token. Returns null for unknown, used, or expired tokens. */
export async function consumeToken(db: D1Database, token: string, now: number): Promise<ReportRequestRow | null> {
	if (!token || token.length > 128) return null;
	return db
		.prepare(
			`UPDATE report_requests SET token_hash = NULL, confirmed_at = ?
			 WHERE token_hash = ? AND status = 'pending' AND expires_at > ?
			 RETURNING *`,
		)
		.bind(now, await hashToken(token), now)
		.first<ReportRequestRow>();
}

/** Distinguishes an expired-but-unused token from an unknown or already-used one (for the thanks page). */
export async function tokenExpired(db: D1Database, token: string): Promise<boolean> {
	if (!token || token.length > 128) return false;
	const row = await db.prepare(`SELECT 1 AS x FROM report_requests WHERE token_hash = ? AND status = 'pending'`).bind(await hashToken(token)).first();
	return row !== null;
}

export async function markQueued(db: D1Database, id: string, now: number): Promise<void> {
	await db.prepare(`UPDATE report_requests SET status = 'queued', queued_at = ?, defer_reason = NULL WHERE id = ?`).bind(now, id).run();
}

export async function markDeferred(db: D1Database, id: string, reason: string): Promise<void> {
	await db.prepare(`UPDATE report_requests SET status = 'deferred', defer_reason = ?, queued_at = NULL WHERE id = ?`).bind(reason, id).run();
}

export async function dailyCapReached(db: D1Database, now: number, cap: number): Promise<boolean> {
	const row = await db.prepare('SELECT COUNT(*) AS n FROM report_requests WHERE queued_at > ?').bind(now - DAY).first<{ n: number }>();
	return (row?.n ?? 0) >= cap;
}

export async function getRequest(db: D1Database, id: string): Promise<ReportRequestRow | null> {
	return db.prepare('SELECT * FROM report_requests WHERE id = ?').bind(id).first<ReportRequestRow>();
}

export async function bumpAttempts(db: D1Database, id: string): Promise<void> {
	await db.prepare('UPDATE report_requests SET attempts = attempts + 1 WHERE id = ?').bind(id).run();
}

export async function markStep(db: D1Database, id: string, step: 'report_sent_at' | 'lead_sent_at', now: number): Promise<void> {
	await db.prepare(`UPDATE report_requests SET ${step} = ? WHERE id = ?`).bind(now, id).run();
}

export async function markSent(
	db: D1Database,
	id: string,
	report: HealthReport,
	meta: { usedCache: boolean; usedAgent: boolean },
	now: number,
): Promise<void> {
	await db
		.prepare(
			`UPDATE report_requests SET status = 'sent', completed_at = ?, overall = ?, score_pass = ?, score_warn = ?, score_fail = ?, used_cache = ?, used_agent = ?
			 WHERE id = ?`,
		)
		.bind(now, report.overall, report.score.pass, report.score.warn, report.score.fail, meta.usedCache ? 1 : 0, meta.usedAgent ? 1 : 0, id)
		.run();
}

export async function markFailed(db: D1Database, id: string, now: number): Promise<void> {
	await db.prepare(`UPDATE report_requests SET status = 'failed', completed_at = ? WHERE id = ?`).bind(now, id).run();
}

export async function cachedResult(db: D1Database, domain: string, now: number, l: Limits): Promise<{ report: HealthReport; usedAgent: boolean } | null> {
	const row = await db
		.prepare('SELECT report_json, used_agent FROM report_results WHERE domain = ? AND created_at > ?')
		.bind(domain, now - l.RESULT_CACHE_HOURS * HOUR)
		.first<{ report_json: string; used_agent: number }>();
	return row ? { report: JSON.parse(row.report_json) as HealthReport, usedAgent: row.used_agent === 1 } : null;
}

export async function storeResult(db: D1Database, domain: string, report: HealthReport, usedAgent: boolean, now: number): Promise<void> {
	await db
		.prepare('INSERT OR REPLACE INTO report_results (domain, report_json, used_agent, created_at) VALUES (?, ?, ?, ?)')
		.bind(domain, JSON.stringify(report), usedAgent ? 1 : 0, now)
		.run();
}

/** Returns true the first time `kind` is noted on this UTC day. */
export async function noticeOnce(db: D1Database, kind: string, now: number): Promise<boolean> {
	const day = new Date(now).toISOString().slice(0, 10);
	const res = await db.prepare('INSERT OR IGNORE INTO notices (kind, day) VALUES (?, ?)').bind(kind, day).run();
	return (res.meta.changes ?? 0) > 0;
}

export async function deferredRequests(db: D1Database, limit = 50): Promise<ReportRequestRow[]> {
	const { results } = await db
		.prepare(`SELECT * FROM report_requests WHERE status = 'deferred' ORDER BY confirmed_at LIMIT ?`)
		.bind(limit)
		.all<ReportRequestRow>();
	return results;
}

/** Retention: expired pending rows, IP hashes after a day, personal data after RETENTION_DAYS, stale results. */
export async function cleanup(db: D1Database, now: number, l: Limits): Promise<Record<string, number>> {
	const run = async (sql: string, ...args: unknown[]) => (await db.prepare(sql).bind(...args).run()).meta.changes ?? 0;
	return {
		expiredPending: await run(`DELETE FROM report_requests WHERE status = 'pending' AND expires_at <= ?`, now),
		ipHashes: await run('UPDATE report_requests SET ip_hash = NULL WHERE ip_hash IS NOT NULL AND created_at <= ?', now - DAY),
		retention: await run('DELETE FROM report_requests WHERE created_at <= ?', now - l.RETENTION_DAYS * DAY),
		results: await run('DELETE FROM report_results WHERE created_at <= ?', now - l.RESULT_CACHE_HOURS * HOUR),
		notices: await run('DELETE FROM notices WHERE day < ?', new Date(now - 7 * DAY).toISOString().slice(0, 10)),
	};
}
