import { allowedOrigin, corsHeaders, reply, verifyTurnstile, type HealthEnv } from '../health/handler';
import { readLimits, type ReportEnv } from './config';
import { checkRequestLimits, deliveryDecision, inConfirmationCooldown } from './limits';
import { notifyAdmin, sendEmail } from './mailer';
import { consumeToken, createPending, dailyCapReached, deleteRequest, hashEmail, hashIp, markDeferred, markQueued, noticeOnce, tokenExpired } from './store';
import { renderAdminNotice, renderConfirmation } from './templates';
import { validateReportRequest } from './validate';

export const REPORT_REQUEST_PATH = '/api/v1/report-request';
export const REPORT_CONFIRM_PATH = '/api/v1/report-confirm';
const MAX_BODY_BYTES = 8192;

export type FullReportEnv = ReportEnv & HealthEnv;

/** Counts only — never names, emails, domains, IPs, or tokens. */
export function metric(action: string, extra: Record<string, string | number | boolean> = {}): void {
	console.log(JSON.stringify({ event: 'report', action, ...extra }));
}

const FIELD_FOR_ERROR: Record<string, string> = {
	invalid_name: 'name',
	invalid_email: 'email',
	invalid_domain: 'domain',
	invalid_organisation: 'organisation',
	consent_required: 'consent',
};

export async function handleReportRequest(request: Request, env: FullReportEnv): Promise<Response> {
	const origin = allowedOrigin(request.headers.get('origin'), env);
	if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(origin) });
	if (request.method !== 'POST') return reply({ error: 'method_not_allowed' }, 405, origin, { allow: 'POST, OPTIONS' });

	let body: Record<string, unknown>;
	try {
		const text = await request.text();
		if (text.length > MAX_BODY_BYTES) throw new Error('too large');
		body = JSON.parse(text) as Record<string, unknown>;
		if (!body || typeof body !== 'object') throw new Error('not an object');
	} catch {
		return reply({ error: 'invalid_request' }, 400, origin);
	}
	if (body.wantsCall === undefined && body.discoveryCall !== undefined) body.wantsCall = body.discoveryCall;

	const v = validateReportRequest(body);
	if (!v.ok) {
		metric('invalid', { reason: v.error });
		return reply({ error: v.error, fields: { [FIELD_FOR_ERROR[v.error]]: 'invalid' } }, 400, origin);
	}

	const ip = request.headers.get('cf-connecting-ip');
	if (!(await verifyTurnstile(v.value.turnstileToken, env.TURNSTILE_SECRET, ip))) {
		metric('turnstile_failed');
		return reply({ error: 'turnstile_failed' }, 403, origin);
	}

	const now = Date.now();
	const limits = readLimits(env);
	const [ipHash, emailHash] = await Promise.all([hashIp(ip), hashEmail(v.value.email)]);
	const lim = await checkRequestLimits(env.DB, { ipHash, emailHash, domain: v.value.domain }, now, limits);
	if (!lim.ok) {
		metric('rate_limited', { rule: lim.rule });
		return reply({ error: 'rate_limited', retryAfter: lim.retryAfter }, 429, origin, { 'retry-after': String(lim.retryAfter) });
	}
	const delayed = await dailyCapReached(env.DB, now, limits.DAILY_REPORT_CAP);

	if (await inConfirmationCooldown(env.DB, emailHash, now, limits)) {
		metric('confirmation_cooldown');
		return reply({ ok: true, delayed }, 202, origin);
	}

	const { id, token } = await createPending(env.DB, { ...v.value, ipHash, emailHash }, now, limits);
	const confirmUrl = new URL(REPORT_CONFIRM_PATH, request.url);
	confirmUrl.searchParams.set('token', token);
	try {
		await sendEmail(env, {
			to: v.value.email,
			...renderConfirmation({ name: v.value.name, domain: v.value.domain, confirmUrl: confirmUrl.toString(), ttlHours: limits.TOKEN_TTL_HOURS }),
		});
	} catch (e) {
		await deleteRequest(env.DB, id);
		metric('confirmation_email_failed', { code: (e as { code?: string }).code ?? 'unknown' });
		return reply({ error: 'email_failed' }, 502, origin);
	}
	metric('requested', { wantsCall: v.value.wantsCall, delayed });
	return reply({ ok: true, delayed }, 202, origin);
}

function thanks(env: ReportEnv, status: 'confirmed' | 'delayed' | 'expired' | 'invalid'): Response {
	const site = (env.SITE_URL || 'https://www.thecuckoocamp.co.uk').replace(/\/$/, '');
	return new Response(null, { status: 303, headers: { location: `${site}/health-check/thanks/?status=${status}`, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' } });
}

/** Releases a confirmed request to the queue, or defers it when a delivery limit or the daily cap is hit. */
export async function release(env: ReportEnv, row: { id: string; email_hash: string; domain: string }, now: number): Promise<'queued' | 'deferred'> {
	const limits = readLimits(env);
	const decision = await deliveryDecision(env.DB, row.email_hash, row.domain, now, limits);
	if (decision !== 'ok') {
		await markDeferred(env.DB, row.id, decision);
		if (decision === 'cap' && (await noticeOnce(env.DB, 'daily_cap', now))) {
			await notifyAdmin(
				env,
				renderAdminNotice('Full-report daily cap reached', [
					`DAILY_REPORT_CAP (${limits.DAILY_REPORT_CAP}) was reached. New confirmed requests are deferred and will be sent as the 24-hour window frees up.`,
					'Raise DAILY_REPORT_CAP if this is legitimate demand.',
				]),
			);
		}
		metric('deferred', { reason: decision });
		return 'deferred';
	}
	await markQueued(env.DB, row.id, now);
	try {
		await env.REPORT_QUEUE.send({ id: row.id });
	} catch {
		await markDeferred(env.DB, row.id, 'queue');
		metric('deferred', { reason: 'queue' });
		return 'deferred';
	}
	metric('queued');
	return 'queued';
}

export async function handleReportConfirm(request: Request, env: FullReportEnv): Promise<Response> {
	if (request.method === 'HEAD') return new Response(null, { status: 200, headers: { 'cache-control': 'no-store' } });
	if (request.method !== 'GET') return new Response(null, { status: 405, headers: { allow: 'GET' } });
	const token = new URL(request.url).searchParams.get('token') ?? '';
	const now = Date.now();
	const row = await consumeToken(env.DB, token, now);
	if (!row) {
		const expired = await tokenExpired(env.DB, token);
		metric('confirm_rejected', { reason: expired ? 'expired' : 'invalid' });
		return thanks(env, expired ? 'expired' : 'invalid');
	}
	metric('confirmed');
	return thanks(env, (await release(env, row, now)) === 'queued' ? 'confirmed' : 'delayed');
}
