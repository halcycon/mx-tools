import { runBimi, runDkim, runDmarc, runDnsHealth, runHttp, runMtaSts, runMx, runSpf, runTlsrpt, scanBlacklist, type BlacklistScan } from '../checks/run';
import { flattenSpf } from '../checks/spf-flat';
import { interpretDnsblCodes } from '../checks/dnsbl-codes';
import { probeAgent, type AgentEnv, type AgentProbe } from '../agent/client';
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

export const AGENT_QUICK_TIMEOUT_MS = 7_000;

export type HealthJob = { id: HealthCheckId; run: () => Promise<HealthCheck> };

export type HealthJobOptions = {
	/** VPS agent for accurate DNSBL; the Worker's DoH scan is the fallback. */
	agent?: AgentEnv;
	dkimSelectors?: readonly string[];
};

export function agentScan(dnsbl: AgentProbe['dnsbl']): BlacklistScan {
	const addr = (a: { ip: string; role: string }) => ({ ip: a.ip, role: a.role, cloudflare: false });
	return {
		mx: dnsbl.mx ?? [],
		check: (dnsbl.checked ?? []).map(addr),
		skipped: (dnsbl.skipped ?? []).map(addr),
		listCount: dnsbl.listCount,
		hits: (dnsbl.hits ?? []).map((h) => ({
			list: h.list,
			ip: h.ip,
			role: h.role,
			answers: h.answers ?? [],
			lookupFailed: Boolean(h.error),
			rcode: h.rcode,
			interp: interpretDnsblCodes(h.zone, h.answers ?? [], h.zone.includes('dnswl')),
		})),
	};
}

export async function workerBlacklistCheck(domain: string): Promise<HealthCheck> {
	const scan = await scanBlacklist(domain, {}, { skipZones: DOH_UNREACHABLE_DNSBLS, queryTimeoutMs: 4_000, concurrency: 6 });
	return toCheck('blacklist', mapBlacklist(scan, { spamhausDqs: false, source: 'worker' }));
}

export function agentBlacklistCheck(probe: AgentProbe): HealthCheck {
	return toCheck('blacklist', mapBlacklist(agentScan(probe.dnsbl), { spamhausDqs: probe.dnsbl.dqs, source: 'agent' }));
}

export function healthJobs(domain: string, opts: HealthJobOptions = {}): HealthJob[] {
	const selectors = opts.dkimSelectors ?? DKIM_SELECTORS;
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
					selectors.map(async (selector) => ({ selector, result: await runDkim(domain, selector) })),
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
				const probe = opts.agent ? await probeAgent(opts.agent, domain, 'quick', AGENT_QUICK_TIMEOUT_MS) : null;
				return probe ? agentBlacklistCheck(probe) : workerBlacklistCheck(domain);
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

/**
 * Run all jobs concurrently; anything unfinished at the deadline is omitted and `complete` is false.
 * `onCheck` fires in completion order, and never after the deadline.
 */
export async function runJobs(
	jobs: HealthJob[],
	timeoutMs: number,
	onCheck?: (check: HealthCheck) => void,
): Promise<{ complete: boolean; checks: HealthCheck[] }> {
	const done = new Map<HealthCheckId, HealthCheck>();
	let open = true;
	const record = (id: HealthCheckId, check: HealthCheck) => {
		if (!open) return;
		done.set(id, check);
		onCheck?.(check);
	};
	const all = Promise.all(
		jobs.map((job) =>
			job.run().then(
				(check) => record(job.id, check),
				() => record(job.id, errorCheck(job.id)),
			),
		),
	);
	let timer: ReturnType<typeof setTimeout> | undefined;
	const deadline = new Promise<void>((resolve) => {
		timer = setTimeout(resolve, timeoutMs);
	});
	await Promise.race([all, deadline]);
	open = false;
	clearTimeout(timer);
	const checks = jobs.map((j) => done.get(j.id)).filter((c): c is HealthCheck => c !== undefined);
	return { complete: checks.length === jobs.length, checks };
}

export async function runHealthCheck(
	domain: string,
	opts: { agent?: AgentEnv; timeoutMs?: number; checkedAt?: Date; onCheck?: (check: HealthCheck) => void } = {},
): Promise<{ complete: boolean; report: HealthReport }> {
	const checkedAt = opts.checkedAt ?? new Date();
	const { complete, checks } = await runJobs(healthJobs(domain, { agent: opts.agent }), opts.timeoutMs ?? HEALTH_CHECK_TIMEOUT_MS, opts.onCheck);
	return { complete, report: buildReport(domain, checks, checkedAt) };
}
