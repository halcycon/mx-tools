import { answersOf, doh, resolveHostToIps } from '../checks/dns';
import { probeAgent, type AgentEnv, type AgentProbe, type AgentSmtp } from '../agent/client';
import { buildReport, errorCheck, toCheck, type HealthCheck, type HealthReport, type Mapped } from '../health/codes';
import { agentBlacklistCheck, healthJobs, runJobs, workerBlacklistCheck, type HealthJob } from '../health/run';

/** Common DKIM selectors by provider (Google, Microsoft 365, Mailchimp, SendGrid, Fastmail, Proton, Zoho, Mailgun, …). */
export const DKIM_DISCOVERY_SELECTORS = [
	'default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'k3', 's1', 's2', 'mail', 'dkim', 'dkim1', 'smtp',
	'email', 'key1', 'key2', 'sig1', 'mx', 'fm1', 'fm2', 'fm3', 'protonmail', 'protonmail2', 'protonmail3', 'zoho',
	'zmail', 'mandrill', 'mxvault', 'mailjet', 'cm', 'mg', 'krs', 'pic', 'smtpapi', 'mlsend', 'mlsend2', 'resend',
	'cf2024-1', 'everlytickey1', 'everlytickey2', 'zendesk1', 'zendesk2', 'turbo-smtp',
] as const;

export const CERT_EXPIRY_WARN_DAYS = 21;
const AGENT_FULL_TIMEOUT_MS = 45_000;
const FULL_DEADLINE_MS = 60_000;

const daysLeft = (notAfter: string, now: number) => Math.floor((Date.parse(notAfter) - now) / 86_400_000);

function smtpFacts(p: AgentSmtp, now: number) {
	return {
		host: p.host,
		port: p.port,
		role: p.role,
		connected: p.connected,
		banner: p.banner || null,
		startTls: p.startTls,
		tls: p.tls,
		tlsVersion: p.tlsVersion ?? null,
		cert: p.cert
			? {
					subject: p.cert.subject,
					issuer: p.cert.issuer,
					notAfter: p.cert.notAfter,
					daysLeft: daysLeft(p.cert.notAfter, now),
					verified: p.cert.verified,
					hostnameMatch: p.cert.hostnameMatch,
					verifyError: p.cert.verifyError ?? null,
				}
			: null,
		error: p.error ?? null,
	};
}

function smtpLine(f: ReturnType<typeof smtpFacts>): string {
	if (!f.connected) return `${f.host}:${f.port} (${f.role}) not reachable: ${f.error ?? 'no response'}`;
	const tls = f.tls ? `${f.tlsVersion ?? 'TLS'}` : f.startTls ? 'STARTTLS offered, handshake failed' : 'no TLS';
	const cert = f.cert
		? ` | cert ${f.cert.subject} by ${f.cert.issuer}, expires ${f.cert.notAfter.slice(0, 10)} (${f.cert.daysLeft} days), ${f.cert.verified ? 'valid' : `invalid: ${f.cert.verifyError}`}`
		: '';
	return `${f.host}:${f.port} (${f.role}) ${f.banner ?? ''} | ${tls}${cert}`;
}

export function mapSmtp(probe: AgentProbe | null, now: number): Mapped {
	if (!probe) return { code: 'smtp_not_checked', facts: { reason: 'agent_unavailable', probes: [] }, technical: '' };
	const probes = (probe.smtp ?? []).map((p) => smtpFacts(p, now));
	const egress = probe.smtpEgress ?? null;
	const mx = probes.filter((p) => p.role === 'mx');
	const connected = probes.filter((p) => p.connected);
	const facts = { egress, probes };
	const technical = probes.map(smtpLine).join('\n');

	if (egress && mx.length && !mx.some((p) => p.connected)) return { code: 'smtp_unreachable', facts, technical };
	if (connected.some((p) => p.cert && p.cert.daysLeft < 0)) return { code: 'cert_expired', facts, technical };
	if (mx.some((p) => p.connected && !p.startTls)) return { code: 'smtp_starttls_missing', facts, technical };
	if (connected.some((p) => (p.startTls || p.port === 465) && !p.tls)) return { code: 'smtp_tls_failed', facts, technical };
	if (connected.some((p) => p.cert && !p.cert.verified)) return { code: 'smtp_cert_invalid', facts, technical };
	if (connected.some((p) => p.cert && p.cert.daysLeft < CERT_EXPIRY_WARN_DAYS)) return { code: 'cert_expiring_soon', facts, technical };
	if (!mx.length) {
		const reason = egress === false ? 'egress_blocked' : (probe.dnsbl.mx ?? []).length ? 'no_public_mx_ip' : 'no_mx';
		return { code: 'smtp_not_checked', facts: { ...facts, reason }, technical };
	}
	return { code: 'smtp_ok', facts, technical };
}

export type PtrFact = { ip: string; role: string; ptr: string[]; forward: string[]; fcrdns: boolean; error?: string };

export function mapPtr(list: PtrFact[] | null, source: 'agent' | 'worker'): Mapped {
	if (!list) return { code: 'ptr_not_checked', facts: { reason: 'unavailable', source, addresses: [] }, technical: '' };
	const addresses = list.map((p) => ({ ip: p.ip, role: p.role, ptr: p.ptr ?? [], forward: p.forward ?? [], fcrdns: p.fcrdns, error: p.error ?? null }));
	const facts = { source, addresses };
	const technical = addresses
		.map((a) => `${a.ip} (${a.role}) → ${a.ptr.join(', ') || (a.error ?? 'no PTR')}${a.ptr.length ? ` → ${a.forward.join(', ') || 'unresolved'} ${a.fcrdns ? '✓' : '✗'}` : ''}`)
		.join('\n');
	const usable = addresses.filter((a) => !a.error);
	if (!usable.length) return { code: 'ptr_not_checked', facts: { ...facts, reason: addresses.length ? 'lookup_failed' : 'no_mx_ips' }, technical };
	if (usable.some((a) => !a.ptr.length)) return { code: 'ptr_missing', facts, technical };
	if (usable.some((a) => !a.fcrdns)) return { code: 'ptr_mismatch', facts, technical };
	return { code: 'ptr_ok', facts, technical };
}

function ptrName(ip: string): string | null {
	if (ip.includes(':')) return null;
	return `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
}

/** Limited PTR/FCrDNS over DoH, used when the agent is unreachable (IPv4 MX addresses only). */
export async function workerPtr(domain: string): Promise<PtrFact[]> {
	const mx = answersOf(await doh(domain, 'MX'), 'MX')
		.map((a) => a.data.split(/\s+/)[1]?.replace(/\.$/, '') ?? '')
		.filter((h) => h && h !== '.')
		.slice(0, 3);
	const addrs = (await Promise.all(mx.map(async (host) => (await resolveHostToIps(host)).map((ip) => ({ ip, role: `MX ${host}` }))))).flat();
	const v4 = addrs.filter((a) => ptrName(a.ip)).slice(0, 6);
	return Promise.all(
		v4.map(async ({ ip, role }) => {
			try {
				const ptr = answersOf(await doh(ptrName(ip)!, 'PTR'), 'PTR').map((a) => a.data.replace(/\.$/, ''));
				const forward = (await Promise.all(ptr.map((h) => resolveHostToIps(h)))).flat();
				return { ip, role, ptr, forward, fcrdns: forward.includes(ip) };
			} catch {
				return { ip, role, ptr: [], forward: [], fcrdns: false, error: 'lookup failed' };
			}
		}),
	);
}

export async function runFullReport(domain: string, env: AgentEnv): Promise<{ report: HealthReport; usedAgent: boolean }> {
	const checkedAt = new Date();
	const agent = probeAgent(env, domain, 'full', AGENT_FULL_TIMEOUT_MS);
	const jobs: HealthJob[] = healthJobs(domain, { dkimSelectors: DKIM_DISCOVERY_SELECTORS }).filter((j) => j.id !== 'blacklist');
	jobs.push(
		{
			id: 'blacklist',
			run: async () => {
				const p = await agent;
				return p ? agentBlacklistCheck(p) : workerBlacklistCheck(domain);
			},
		},
		{ id: 'smtp', run: async () => toCheck('smtp', mapSmtp(await agent, Date.now())) },
		{
			id: 'ptr',
			run: async () => {
				const p = await agent;
				return p?.ptr ? toCheck('ptr', mapPtr(p.ptr, 'agent')) : toCheck('ptr', mapPtr(await workerPtr(domain), 'worker'));
			},
		},
	);
	const { checks } = await runJobs(jobs, FULL_DEADLINE_MS);
	const done = new Set(checks.map((c) => c.id));
	const all: HealthCheck[] = [...checks, ...jobs.filter((j) => !done.has(j.id)).map((j) => errorCheck(j.id))];
	return { report: buildReport(domain, all, checkedAt), usedAgent: (await agent) !== null };
}
