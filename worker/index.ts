import { parseQuery, TOOLS, type CheckResult } from './checks/types';
import { plannedChecks, runOne, streamOne } from './checks/run';

function json(data: unknown, status = 200): Response {
	return new Response(JSON.stringify(data, null, 2), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'access-control-allow-origin': '*',
			'cache-control': 'no-store',
		},
	});
}

function sseHeaders(): HeadersInit {
	return {
		'content-type': 'text/event-stream; charset=utf-8',
		'cache-control': 'no-cache',
		connection: 'keep-alive',
		'access-control-allow-origin': '*',
	};
}

async function handleLookup(request: Request, url: URL): Promise<Response> {
	let raw = url.searchParams.get('q') ?? url.searchParams.get('query') ?? '';
	if (request.method === 'POST') {
		try {
			const body = (await request.json()) as { q?: string; query?: string };
			raw = body.q ?? body.query ?? raw;
		} catch {
			/* keep query param */
		}
	}
	if (!raw.trim()) return json({ error: 'Missing q' }, 400);
	if (raw.length > 512) return json({ error: 'Query too long' }, 400);
	if (/[\x00-\x1F\x7F]/.test(raw)) return json({ error: 'Invalid characters in query' }, 400);

	let parsed;
	try {
		parsed = parseQuery(raw);
	} catch (e) {
		return json({ error: e instanceof Error ? e.message : String(e) }, 400);
	}
	if (parsed.target.length > 255) return json({ error: 'Target too long' }, 400);
	if (/[\x00-\x1F\x7F]/.test(parsed.target)) return json({ error: 'Invalid characters in target' }, 400);

	const stream = url.searchParams.get('stream') === '1' || request.headers.get('accept')?.includes('text/event-stream');

	if (stream) {
		const { readable, writable } = new TransformStream();
		const writer = writable.getWriter();
		const enc = new TextEncoder();
		const send = async (event: string, data: unknown) => {
			await writer.write(enc.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
		};

		(async () => {
			try {
				const planned = plannedChecks(parsed.tool, parsed.target);
				await send('start', {
					query: raw,
					tool: parsed.tool,
					target: parsed.target,
					expected: planned.length,
					checks: planned,
				});
				let count = 0;
				for await (const r of streamOne(parsed)) {
					count += 1;
					await send('result', r);
				}
				await send('done', { count });
			} catch (e) {
				await send('error', { message: e instanceof Error ? e.message : String(e) });
			} finally {
				await writer.close();
			}
		})();

		return new Response(readable, { headers: sseHeaders() });
	}

	try {
		const results: CheckResult[] = await runOne(parsed);
		return json({ query: raw, ...parsed, results });
	} catch (e) {
		return json({ error: e instanceof Error ? e.message : String(e) }, 500);
	}
}

export default {
	async fetch(request, env): Promise<Response> {
		const url = new URL(request.url);

		if (request.method === 'OPTIONS') {
			return new Response(null, {
				headers: {
					'access-control-allow-origin': '*',
					'access-control-allow-methods': 'GET, POST, OPTIONS',
					'access-control-allow-headers': 'content-type, accept',
				},
			});
		}

		if (url.pathname === '/api/tools') {
			return json({ tools: TOOLS });
		}

		if (url.pathname === '/api/lookup' || url.pathname === '/api/supertool') {
			return handleLookup(request, url);
		}

		if (url.pathname === '/api/health') {
			return json({ ok: true, service: 'mx-tools' });
		}

		// Static assets (SPA)
		return env.ASSETS.fetch(request);
	},
} satisfies ExportedHandler<Env>;
