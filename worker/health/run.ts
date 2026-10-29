import { runBimi, runDkim, runDmarc, runDnsHealth, runHttp, runMtaSts, runMx, runSpf, runTlsrpt, scanBlacklist } from '../checks/run';
import { flattenSpf } from '../checks/spf-flat';
import {
	buildReport,
	errorCheck,
	mapBimi,
	mapBlacklist,
	mapDkim,
	mapDmarc,
	mapDns,
	mapHttps,
	mapMtaSts,
	mapMx,
	mapSpf,
	mapTlsrpt,
	toCheck,
	type HealthCheck,
	type HealthCheckId,
	type HealthReport,
} from './codes';

export const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 's1', 'mail'] as const;
export const HEALTH_CHECK_TIMEOUT_MS = 15_000;
const FETCH_TIMEOUT_MS = 6_000;

/** Lists that never answer through public DoH resolvers (defunct, or refuse 1.1.1.1), so they only add latency. */
export const DOH_UNREACHABLE_DNSBLS: ReadonlySet<string> = new Set([
	'bhnc.njabl.org',
	'db.wpbl.info',
	'dyna.spamrats.com',
	'noptr.spamrats.com',
	'spam.spamrats.com',
]);

export type HealthJob = { id: HealthCheckId; run: () => Promise<HealthCheck> };

export function healthJobs(domain: string, spamhausDqsKey?: string): HealthJob[] {
	return [
		{
			id: 'spf',
			run: async () => {
				const [spf, flat] = await Promise.all([runSpf(domain), flattenSpf(domain)]);
				return toCheck('spf', mapSpf(spf, flat));
			},
		},
		{ id: 'dmarc', run: async () => toCheck('dmarc', mapDmarc(await runDmarc(domain))) },
		{
			id: 'dkim',
			run: async () => {
				const results = await Promise.all(
					DKIM_SELECTORS.map(async (selector) => ({ selector, result: await runDkim(domain, selector) })),
				);
				return toCheck('dkim', mapDkim(results));
			},
		},
		{ id: 'mx', run: async () => toCheck('mx', mapMx(await runMx(domain))) },
		{ id: 'mta-sts', run: async () => toCheck('mta-sts', mapMtaSts(await runMtaSts(domain, FETCH_TIMEOUT_MS))) },
		{ id: 'tlsrpt', run: async () => toCheck('tlsrpt', mapTlsrpt(await runTlsrpt(domain))) },
		{
			id: 'blacklist',
			run: async () => {
				const scan = await scanBlacklist(
					domain,
					{ spamhausDqsKey },
					{ skipZones: DOH_UNREACHABLE_DNSBLS, queryTimeoutMs: 4_000, concurrency: 6 },
				);
				return toCheck('blacklist', mapBlacklist(scan, Boolean(spamhausDqsKey?.trim())));
			},
		},
		{ id: 'bimi', run: async () => toCheck('bimi', mapBimi(await runBimi(domain))) },
		{ id: 'dns', run: async () => toCheck('dns', mapDns(await runDnsHealth(domain))) },
		{
			id: 'https',
			run: async () => {
				const apex = await runHttp(domain, true, FETCH_TIMEOUT_MS);
				const mapped = mapHttps(apex);
				if (mapped.code === 'https_ok') return toCheck('https', mapped);
				return toCheck('https', mapHttps(apex, await runHttp(`www.${domain}`, true, 5_000)));
			},
		},
	];
}

/** Run all jobs concurrently; anything unfinished at the deadline is omitted and `complete` is false. */
export async function runJobs(jobs: HealthJob[], timeoutMs: number): Promise<{ complete: boolean; checks: HealthCheck[] }> {
	const done = new Map<HealthCheckId, HealthCheck>();
	const all = Promise.all(
		jobs.map((job) =>
			job.run().then(
				(check) => void done.set(job.id, check),
				() => void done.set(job.id, errorCheck(job.id)),
			),
		),
	);
	let timer: ReturnType<typeof setTimeout> | undefined;
	const deadline = new Promise<void>((resolve) => {
		timer = setTimeout(resolve, timeoutMs);
	});
	await Promise.race([all, deadline]);
	clearTimeout(timer);
	const checks = jobs.map((j) => done.get(j.id)).filter((c): c is HealthCheck => c !== undefined);
	return { complete: checks.length === jobs.length, checks };
}

export async function runHealthCheck(
	domain: string,
	opts: { spamhausDqsKey?: string; timeoutMs?: number } = {},
): Promise<{ complete: boolean; report: HealthReport }> {
	const checkedAt = new Date();
	const { complete, checks } = await runJobs(healthJobs(domain, opts.spamhausDqsKey), opts.timeoutMs ?? HEALTH_CHECK_TIMEOUT_MS);
	return { complete, report: buildReport(domain, checks, checkedAt) };
}
