/** Authenticated client for `mx agent` POST /api/v1/probe (see cli/internal/checks/probe.go). */

export type AgentEnv = {
	AGENT_URL?: string;
	AGENT_HMAC_SECRET?: string;
	/** Cloudflare Access service token (when the agent sits behind a Tunnel + Access app). */
	AGENT_CLIENT_ID?: string;
	AGENT_CLIENT_SECRET?: string;
	/** Bearer token, only used when the agent runs without an HMAC secret. */
	AGENT_TOKEN?: string;
};

export type AgentAddr = { ip: string; role: string };

export type AgentProbe = {
	domain: string;
	mode: 'quick' | 'full';
	resolver: string;
	dnsbl: {
		dqs: boolean;
		checked: AgentAddr[] | null;
		skipped: AgentAddr[] | null;
		mx: Array<{ host: string; ips: string[] }> | null;
		listCount: number;
		hits: Array<{ list: string; zone: string; ip: string; role: string; answers: string[]; rcode: number | null; error?: string }> | null;
	};
	ptr?: Array<{ ip: string; role: string; ptr: string[]; forward: string[]; fcrdns: boolean; error?: string }> | null;
	smtp?: AgentSmtp[] | null;
	smtpEgress?: boolean;
	elapsedMs: number;
};

export type AgentSmtp = {
	host: string;
	port: number;
	mode: 'starttls' | 'implicit';
	role: 'mx' | 'submission';
	connected: boolean;
	bannerCode: number;
	banner: string;
	startTls: boolean;
	tls: boolean;
	tlsVersion?: string;
	cert?: {
		subject: string;
		issuer: string;
		dnsNames: string[];
		notBefore: string;
		notAfter: string;
		verified: boolean;
		verifyError?: string;
		hostnameMatch: boolean;
	};
	error?: string;
	elapsedMs: number;
};

export const PROBE_PATH = '/api/v1/probe';

export function agentConfigured(env: AgentEnv): boolean {
	return Boolean(env.AGENT_URL?.trim() && (env.AGENT_HMAC_SECRET?.trim() || env.AGENT_TOKEN?.trim()));
}

const enc = new TextEncoder();

function hex(buf: ArrayBuffer): string {
	return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Must match agent.SignProbe: HMAC-SHA256(secret, "<ts>\n<METHOD>\n<path>\n<sha256(body)>"). */
export async function signProbe(secret: string, ts: string, method: string, path: string, body: string): Promise<string> {
	const bodyHash = hex(await crypto.subtle.digest('SHA-256', enc.encode(body)));
	const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	return hex(await crypto.subtle.sign('HMAC', key, enc.encode(`${ts}\n${method}\n${path}\n${bodyHash}`)));
}

export async function agentHeaders(env: AgentEnv, body: string, now = Date.now()): Promise<Record<string, string>> {
	const h: Record<string, string> = { 'content-type': 'application/json' };
	if (env.AGENT_CLIENT_ID && env.AGENT_CLIENT_SECRET) {
		h['cf-access-client-id'] = env.AGENT_CLIENT_ID;
		h['cf-access-client-secret'] = env.AGENT_CLIENT_SECRET;
	}
	if (env.AGENT_HMAC_SECRET) {
		const ts = String(Math.floor(now / 1000));
		h['x-mx-timestamp'] = ts;
		h['x-mx-signature'] = await signProbe(env.AGENT_HMAC_SECRET, ts, 'POST', PROBE_PATH, body);
	} else if (env.AGENT_TOKEN) {
		h.authorization = `Bearer ${env.AGENT_TOKEN}`;
	}
	return h;
}

/** Returns null when the agent is unconfigured, unreachable, slow, or answers with an error. Never throws. */
export async function probeAgent(env: AgentEnv, domain: string, mode: 'quick' | 'full', timeoutMs: number): Promise<AgentProbe | null> {
	if (!agentConfigured(env)) return null;
	const started = Date.now();
	let status = 0;
	try {
		const url = new URL(PROBE_PATH, env.AGENT_URL);
		const body = JSON.stringify({ domain, mode });
		const res = await fetch(url, {
			method: 'POST',
			headers: await agentHeaders(env, body),
			body,
			redirect: 'manual',
			signal: AbortSignal.timeout(timeoutMs),
		});
		status = res.status;
		if (!res.ok) return null;
		const data = (await res.json()) as AgentProbe;
		if (data?.domain !== domain || !data.dnsbl) return null;
		return data;
	} catch {
		return null;
	} finally {
		console.log(JSON.stringify({ event: 'agent_probe', mode, status, ok: status === 200, ms: Date.now() - started }));
	}
}
