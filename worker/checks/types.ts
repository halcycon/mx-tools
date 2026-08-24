/** Shared result shapes — mirrored in Go CLI (`cli/internal/checks/types.go`). */

export type Severity = 'ok' | 'info' | 'warn' | 'fail' | 'error' | 'unsupported';

export type CheckRow = {
	status: Severity;
	name: string;
	value: string;
	info?: string;
};

export type CheckResult = {
	tool: string;
	title: string;
	query: string;
	ok: boolean;
	summary: string;
	rows: CheckRow[];
	related?: Array<{ tool: string; label: string; query: string }>;
	meta?: Record<string, string | number | boolean>;
	elapsedMs: number;
};

export type ParsedQuery = {
	tool: string;
	target: string;
	/** Optional DKIM selector or TCP port */
	extra?: string;
};

export type ToolDef = {
	id: string;
	label: string;
	description: string;
	/** Where this tool can run */
	platforms: Array<'worker' | 'cli'>;
	example: string;
};

export const TOOLS: ToolDef[] = [
	{ id: 'auto', label: 'Domain health', description: 'Live health report: MX + SPF + DMARC + blacklist + SOA', platforms: ['worker', 'cli'], example: 'example.com' },
	{ id: 'full', label: 'Email health report', description: 'Full live report: mail auth, DNS, blacklist, web, RDAP', platforms: ['worker', 'cli'], example: 'full:example.com' },
	{ id: 'a', label: 'A', description: 'DNS A (IPv4) records', platforms: ['worker', 'cli'], example: 'a:example.com' },
	{ id: 'aaaa', label: 'AAAA', description: 'DNS AAAA (IPv6) records', platforms: ['worker', 'cli'], example: 'aaaa:example.com' },
	{ id: 'cname', label: 'CNAME', description: 'DNS CNAME records', platforms: ['worker', 'cli'], example: 'cname:www.example.com' },
	{ id: 'mx', label: 'MX', description: 'Mail exchanger records', platforms: ['worker', 'cli'], example: 'mx:example.com' },
	{ id: 'ns', label: 'NS', description: 'Name server records', platforms: ['worker', 'cli'], example: 'ns:example.com' },
	{ id: 'ptr', label: 'PTR', description: 'Reverse DNS (PTR)', platforms: ['worker', 'cli'], example: 'ptr:1.2.3.4' },
	{ id: 'soa', label: 'SOA', description: 'Start of Authority', platforms: ['worker', 'cli'], example: 'soa:example.com' },
	{ id: 'txt', label: 'TXT', description: 'TXT records', platforms: ['worker', 'cli'], example: 'txt:example.com' },
	{ id: 'spf', label: 'SPF', description: 'Sender Policy Framework', platforms: ['worker', 'cli'], example: 'spf:example.com' },
	{ id: 'dmarc', label: 'DMARC', description: 'DMARC policy', platforms: ['worker', 'cli'], example: 'dmarc:example.com' },
	{ id: 'dkim', label: 'DKIM', description: 'DKIM key (selector:domain)', platforms: ['worker', 'cli'], example: 'dkim:default:example.com' },
	{ id: 'bimi', label: 'BIMI', description: 'Brand Indicators for Message Identification', platforms: ['worker', 'cli'], example: 'bimi:example.com' },
	{ id: 'mta-sts', label: 'MTA-STS', description: 'MTA-STS policy', platforms: ['worker', 'cli'], example: 'mta-sts:example.com' },
	{ id: 'tlsrpt', label: 'TLSRPT', description: 'TLS reporting', platforms: ['worker', 'cli'], example: 'tlsrpt:example.com' },
	{ id: 'blacklist', label: 'Blacklist', description: 'DNSBL / RBL reputation', platforms: ['worker', 'cli'], example: 'blacklist:1.2.3.4' },
	{ id: 'dns', label: 'DNS health', description: 'Authoritative DNS sanity checks', platforms: ['worker', 'cli'], example: 'dns:example.com' },
	{ id: 'whois', label: 'WHOIS/RDAP', description: 'Domain registration (RDAP)', platforms: ['worker', 'cli'], example: 'whois:example.com' },
	{ id: 'arin', label: 'ARIN/RDAP', description: 'IP network registration', platforms: ['worker', 'cli'], example: 'arin:1.2.3.4' },
	{ id: 'asn', label: 'ASN', description: 'Autonomous system for IP', platforms: ['worker', 'cli'], example: 'asn:1.2.3.4' },
	{ id: 'http', label: 'HTTP', description: 'HTTP connectivity', platforms: ['worker', 'cli'], example: 'http:example.com' },
	{ id: 'https', label: 'HTTPS', description: 'HTTPS connectivity', platforms: ['worker', 'cli'], example: 'https:example.com' },
	{ id: 'tcp', label: 'TCP', description: 'TCP connect (host:port)', platforms: ['worker', 'cli'], example: 'tcp:example.com:443' },
	{ id: 'smtp', label: 'SMTP', description: 'SMTP banner (port 25; CLI preferred)', platforms: ['cli'], example: 'smtp:example.com' },
	{ id: 'ping', label: 'Ping', description: 'ICMP echo (CLI only)', platforms: ['cli'], example: 'ping:example.com' },
	{ id: 'trace', label: 'Traceroute', description: 'ICMP traceroute (CLI only)', platforms: ['cli'], example: 'trace:example.com' },
];

export function parseQuery(raw: string): ParsedQuery {
	const input = raw.trim();
	if (!input) throw new Error('Empty query');

	const colon = input.indexOf(':');
	if (colon > 0 && colon < 16) {
		const tool = input.slice(0, colon).toLowerCase().trim();
		const rest = input.slice(colon + 1).trim();
		if (TOOLS.some((t) => t.id === tool) || tool === 'blocklist') {
			const id = tool === 'blocklist' ? 'blacklist' : tool;
			if (id === 'dkim') {
				const parts = rest.split(':');
				if (parts.length >= 2) {
					return { tool: id, extra: parts[0], target: parts.slice(1).join(':') };
				}
			}
			if (id === 'tcp') {
				const lastColon = rest.lastIndexOf(':');
				if (lastColon > 0) {
					return {
						tool: id,
						target: rest.slice(0, lastColon),
						extra: rest.slice(lastColon + 1),
					};
				}
			}
			return { tool: id, target: rest };
		}
	}
	return { tool: 'auto', target: input };
}
