import { currentLondonDay } from './time';

export type UsageEnv = { DB?: D1Database };
export type UsageRow = {
	id: string;
	domain: string;
	requested_at: number;
	client_ip: string | null;
	page_url: string | null;
	referrer: string | null;
	utm_json: string;
	outcome: string;
	cached: number;
};

const UTM_KEYS = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content'] as const;
const clean = (value: unknown, limit: number): string | null =>
	typeof value === 'string' ? value.replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, limit) || null : null;

/** Keep only HTTP(S) origin/path, never credentials, arbitrary query strings or fragments. */
function safeUrl(value: unknown): string | null {
	if (typeof value !== 'string' || value.length > 4096) return null;
	try {
		const url = new URL(value);
		return ['https:', 'http:'].includes(url.protocol) ? `${url.origin}${url.pathname}`.slice(0, 512) : null;
	} catch { return null; }
}

export function attribution(input: unknown, fallbackReferrer: string | null) {
	const a = input && typeof input === 'object' ? input as Record<string, unknown> : {};
	const rawUtm = a.utm && typeof a.utm === 'object' ? a.utm as Record<string, unknown> : {};
	const utm: Record<string, string> = {};
	for (const key of UTM_KEYS) {
		const value = clean(rawUtm[key], 200);
		if (value) utm[key] = value;
	}
	return { page: safeUrl(a.pageUrl), referrer: typeof a.referrer === 'string' ? safeUrl(a.referrer) : safeUrl(fallbackReferrer), utm };
}

/** Best effort: diagnostics must still work if usage storage is unavailable. */
export async function beginUsage(env: UsageEnv, request: Request, domain: string, input: unknown): Promise<string | null> {
	if (!env.DB) return null;
	const id = crypto.randomUUID();
	const now = Date.now();
	const window = currentLondonDay(now);
	const a = attribution(input, request.headers.get('referer'));
	try {
		await env.DB.batch([env.DB.prepare(`INSERT INTO health_usage
			(id, domain, requested_at, client_ip, page_url, referrer, utm_json) VALUES (?, ?, ?, ?, ?, ?, ?)`)
			.bind(id, domain, now, clean(request.headers.get('cf-connecting-ip'), 64), a.page, a.referrer, JSON.stringify(a.utm)),
			env.DB.prepare('INSERT OR IGNORE INTO health_usage_digests(day,start_at,end_at) VALUES(?,?,?)')
				.bind(window.day, window.start, window.end),
		]);
		return id;
	} catch {
		console.log(JSON.stringify({ event: 'health_usage_storage_failed', operation: 'insert' }));
		return null;
	}
}

export async function finishUsage(env: UsageEnv, id: string | null, outcome: string, cached = false): Promise<void> {
	if (!env.DB || !id) return;
	try {
		await env.DB.prepare('UPDATE health_usage SET outcome=?, cached=? WHERE id=?').bind(outcome, cached ? 1 : 0, id).run();
	} catch {
		console.log(JSON.stringify({ event: 'health_usage_storage_failed', operation: 'update' }));
	}
}
