import { normalizeDomain } from './domain';
import { runHealthCheck } from './run';
import { formatCheckedAt, HEALTH_CHECK_IDS, type HealthCheck, type HealthReport } from './codes';
import type { AgentEnv } from '../agent/client';

export const HEALTH_CHECK_PATH = '/api/v1/health-check';

export type HealthEnv = AgentEnv & {
	TURNSTILE_SECRET?: string;
	HEALTH_CHECK_ALLOW_DEV_ORIGINS?: string;
	HEALTH_CHECK_RATE_LIMITER?: RateLimit;
};

const PROD_ORIGINS = ['https://www.thecuckoocamp.co.uk', 'https://thecuckoocamp.co.uk'];
const DEV_ORIGINS = ['http://localhost:1313', 'http://127.0.0.1:1313'];
/** Cloudflare Pages previews of the website (one label: branch alias or deployment hash). */
const PAGES_PREVIEW_ORIGIN = /^https:\/\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cuckoo-site\.pages\.dev$/;
const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const CACHE_TTL_S = 600;
const MAX_BODY_BYTES = 4096;

export function allowedOrigin(origin: string | null, env: HealthEnv): string | null {
	if (!origin) return null;
	if (PROD_ORIGINS.includes(origin) || PAGES_PREVIEW_ORIGIN.test(origin)) return origin;
	if (env.HEALTH_CHECK_ALLOW_DEV_ORIGINS === 'true' && DEV_ORIGINS.includes(origin)) return origin;
	return null;
}

export function corsHeaders(origin: string | null): Record<string, string> {
	const h: Record<string, string> = { vary: 'Origin' };
	if (origin) {
		h['access-control-allow-origin'] = origin;
		h['access-control-allow-methods'] = 'POST, OPTIONS';
		h['access-control-allow-headers'] = 'content-type';
		h['access-control-max-age'] = '86400';
	}
	return h;
}

export function reply(body: unknown, status: number, origin: string | null, extra: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
			...corsHeaders(origin),
			...extra,
		},
	});
}

export async function verifyTurnstile(token: unknown, secret: string | undefined, remoteIp: string | null): Promise<boolean> {
	if (!secret || typeof token !== 'string' || !token || token.length > 2048) return false;
	const form = new FormData();
	form.append('secret', secret);
	form.append('response', token);
	if (remoteIp) form.append('remoteip', remoteIp);
	try {
		const res = await fetch(SITEVERIFY_URL, { method: 'POST', body: form, signal: AbortSignal.timeout(5000) });
		if (!res.ok) return false;
		const data = (await res.json()) as { success?: boolean };
		return data.success === true;
	} catch {
		return false;
	}
}

/** Rate-limit key: hashed so raw client IPs never leave this function. */
async function clientKey(ip: string | null): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`health-check:${ip ?? 'unknown'}`));
	return [...new Uint8Array(digest).slice(0, 12)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

const memoryCache = new Map<string, { expires: number; report: HealthReport }>();

/** The DOM lib's CacheStorage type shadows the Workers one, which adds `default`. */
function edgeCache(): Cache {
	return (caches as unknown as { default: Cache }).default;
}

function cacheKey(domain: string): string {
	return `https://health-check.mx-tools.internal/v1/${domain}`;
}

async function cachedReport(domain: string): Promise<HealthReport | null> {
	const mem = memoryCache.get(domain);
	if (mem && mem.expires > Date.now()) return mem.report;
	try {
		const hit = await edgeCache().match(cacheKey(domain));
		if (hit) return (await hit.json()) as HealthReport;
	} catch {
		/* Cache API unavailable (e.g. workers.dev); memory cache still applies */
	}
	return null;
}

async function storeReport(domain: string, report: HealthReport): Promise<void> {
	memoryCache.set(domain, { expires: Date.now() + CACHE_TTL_S * 1000, report });
	if (memoryCache.size > 500) memoryCache.clear();
	try {
		await edgeCache().put(
			cacheKey(domain),
			new Response(JSON.stringify(report), {
				headers: { 'content-type': 'application/json', 'cache-control': `max-age=${CACHE_TTL_S}` },
			}),
		);
	} catch {
		/* best effort */
	}
}

function logOutcome(fields: Record<string, string | number | boolean>): void {
	console.log(JSON.stringify({ event: 'health_check', ...fields }));
}

export async function handleHealthCheck(request: Request, env: HealthEnv, ctx: ExecutionContext): Promise<Response> {
	const origin = allowedOrigin(request.headers.get('origin'), env);

	if (request.method === 'OPTIONS') {
		return new Response(null, { status: 204, headers: corsHeaders(origin) });
	}
	if (request.method !== 'POST') {
		return reply({ error: 'method_not_allowed' }, 405, origin, { allow: 'POST, OPTIONS' });
	}

	let body: { domain?: unknown; turnstileToken?: unknown };
	try {
		const text = await request.text();
		if (text.length > MAX_BODY_BYTES) throw new Error('too large');
		body = JSON.parse(text) as typeof body;
		if (!body || typeof body !== 'object') throw new Error('not an object');
	} catch {
		logOutcome({ outcome: 'invalid_domain' });
		return reply({ error: 'invalid_domain' }, 400, origin);
	}

	const domain = normalizeDomain(body.domain);
	if (!domain) {
		logOutcome({ outcome: 'invalid_domain' });
		return reply({ error: 'invalid_domain' }, 400, origin);
	}

	const ip = request.headers.get('cf-connecting-ip');
	if (env.HEALTH_CHECK_RATE_LIMITER) {
		const { success } = await env.HEALTH_CHECK_RATE_LIMITER.limit({ key: await clientKey(ip) });
		if (!success) {
			logOutcome({ outcome: 'rate_limited' });
			return reply({ error: 'rate_limited' }, 429, origin, { 'retry-after': '60' });
		}
	}

	if (!(await verifyTurnstile(body.turnstileToken, env.TURNSTILE_SECRET, ip))) {
		logOutcome({ outcome: 'turnstile_failed' });
		return reply({ error: 'turnstile_failed' }, 403, origin);
	}

	const started = Date.now();
	if (request.headers.get('accept')?.includes('text/event-stream')) {
		return streamHealthCheck(domain, env, ctx, origin, started);
	}
	const cached = await cachedReport(domain);
	if (cached) {
		logOutcome({ outcome: 'ok', domain, overall: cached.overall, ...cached.score, cached: true, ms: Date.now() - started });
		return reply(cached, 200, origin);
	}

	const { complete, report } = await runHealthCheck(domain, { agent: env });
	logOutcome({
		outcome: complete ? 'ok' : 'upstream_timeout',
		domain,
		overall: report.overall,
		...report.score,
		checks: report.checks.length,
		cached: false,
		ms: Date.now() - started,
	});
	if (!complete) return reply({ error: 'upstream_timeout', partial: report }, 502, origin);

	ctx.waitUntil(storeReport(domain, report));
	return reply(report, 200, origin);
}

/**
 * SSE variant (opt-in with `Accept: text/event-stream`): `start`, one `check` per finished check,
 * then `done` with the report plus `complete`. Called only after validation, rate limit and Turnstile.
 */
function streamHealthCheck(domain: string, env: HealthEnv, ctx: ExecutionContext, origin: string | null, started: number): Response {
	const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
	const writer = writable.getWriter();
	const enc = new TextEncoder();
	let closed = false;
	const send = (event: string, data: unknown): Promise<void> =>
		closed ? Promise.resolve() : writer.write(enc.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)).catch(() => {});
	const start = (checkedAt: string) =>
		send('start', { domain, checkedAt, expected: HEALTH_CHECK_IDS.length, checks: [...HEALTH_CHECK_IDS] });

	const run = (async () => {
		try {
			const cached = await cachedReport(domain);
			if (cached) {
				await start(cached.checkedAt);
				for (const check of cached.checks) await send('check', check);
				await send('done', { ...cached, complete: true });
				logOutcome({ outcome: 'ok', domain, overall: cached.overall, ...cached.score, cached: true, stream: true, ms: Date.now() - started });
				return;
			}
			const checkedAt = new Date();
			await start(formatCheckedAt(checkedAt));
			const { complete, report } = await runHealthCheck(domain, {
				agent: env,
				checkedAt,
				onCheck: (check: HealthCheck) => void send('check', check),
			});
			await send('done', { ...report, complete });
			logOutcome({
				outcome: complete ? 'ok' : 'upstream_timeout',
				domain,
				overall: report.overall,
				...report.score,
				checks: report.checks.length,
				cached: false,
				stream: true,
				ms: Date.now() - started,
			});
			if (complete) await storeReport(domain, report);
		} catch {
			await send('error', { error: 'internal_error' });
		} finally {
			closed = true;
			await writer.close().catch(() => {});
		}
	})();
	ctx.waitUntil(run);

	return new Response(readable, {
		status: 200,
		headers: {
			'content-type': 'text/event-stream; charset=utf-8',
			'cache-control': 'no-cache',
			...corsHeaders(origin),
		},
	});
}
