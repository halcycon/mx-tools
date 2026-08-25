/** Copy for the landing page + Tools guide (kept in sync with Worker TOOLS ids). */

export type GuideGroupId = 'reports' | 'mail' | 'reputation' | 'dns' | 'web' | 'registration' | 'cli';

export type GuideTool = {
	id: string;
	label: string;
	blurb: string;
	example: string;
	group: GuideGroupId;
	/** Shown in the web UI tool list */
	web: boolean;
};

export const GUIDE_GROUPS: Array<{ id: GuideGroupId; title: string; blurb: string }> = [
	{
		id: 'reports',
		title: 'Health reports',
		blurb: 'Multi-check live reports. Domain health is the quick default; Email health adds the deeper suite.',
	},
	{
		id: 'mail',
		title: 'Mail & delivery',
		blurb: 'Authentication records, submission probes, and pasted header analysis.',
	},
	{
		id: 'reputation',
		title: 'Reputation',
		blurb: 'DNSBL checks against mail-relevant IPs (MX first; Cloudflare website proxies are skipped when MX exists).',
	},
	{
		id: 'dns',
		title: 'DNS',
		blurb: 'Record lookups and nameserver sanity.',
	},
	{
		id: 'web',
		title: 'Web & connectivity',
		blurb: 'HTTP(S) and TCP. Outbound port 25 is blocked on Workers; 587/465 work for SMTP.',
	},
	{
		id: 'registration',
		title: 'Registration',
		blurb: 'RDAP / ASN metadata for domains and IPs.',
	},
	{
		id: 'cli',
		title: 'CLI only',
		blurb: 'ICMP needs the local `mx` binary (Workers cannot send ping/traceroute).',
	},
];

export const DOMAIN_HEALTH_CHECKS = ['MX', 'SPF', 'DMARC', 'Blacklist', 'SOA'] as const;

export const EMAIL_HEALTH_EXTRA = [
	'SPF flatten',
	'DKIM (default)',
	'TXT',
	'NS',
	'BIMI',
	'MTA-STS',
	'TLSRPT',
	'DNS health',
	'HTTPS',
	'WHOIS',
	'ASN',
	'ARIN',
] as const;

export const GUIDE_TOOLS: GuideTool[] = [
	{
		id: 'auto',
		label: 'Domain health',
		blurb: 'Fast live report: MX, SPF, DMARC, blacklist, and SOA. Use this for a quick “is mail auth basically OK?” pass.',
		example: 'example.com',
		group: 'reports',
		web: true,
	},
	{
		id: 'full',
		label: 'Email health report',
		blurb: 'Everything in Domain health, plus SPF flatten, DKIM, BIMI, MTA-STS, TLSRPT, DNS health, HTTPS, and RDAP/ASN. Slower, more complete.',
		example: 'full:example.com',
		group: 'reports',
		web: true,
	},
	{
		id: 'mx',
		label: 'MX',
		blurb: 'Mail exchanger hosts and their A/AAAA addresses.',
		example: 'mx:example.com',
		group: 'mail',
		web: true,
	},
	{
		id: 'spf',
		label: 'SPF',
		blurb: 'Sender Policy Framework TXT record and all-mechanism stance.',
		example: 'spf:example.com',
		group: 'mail',
		web: true,
	},
	{
		id: 'spf-flat',
		label: 'SPF flatten',
		blurb: 'Expand include/a/mx into ip4/ip6 and count RFC 7208 DNS lookups (limit 10). Does not publish DNS.',
		example: 'spf-flat:example.com',
		group: 'mail',
		web: true,
	},
	{
		id: 'dmarc',
		label: 'DMARC',
		blurb: 'DMARC policy at _dmarc (p=, pct=, rua).',
		example: 'dmarc:example.com',
		group: 'mail',
		web: true,
	},
	{
		id: 'dkim',
		label: 'DKIM',
		blurb: 'DKIM public key for a selector. Syntax: dkim:selector:domain.',
		example: 'dkim:default:example.com',
		group: 'mail',
		web: true,
	},
	{
		id: 'bimi',
		label: 'BIMI',
		blurb: 'Brand Indicators for Message Identification TXT.',
		example: 'bimi:example.com',
		group: 'mail',
		web: true,
	},
	{
		id: 'mta-sts',
		label: 'MTA-STS',
		blurb: 'SMTP MTA Strict Transport Security policy DNS + HTTPS policy fetch.',
		example: 'mta-sts:example.com',
		group: 'mail',
		web: true,
	},
	{
		id: 'tlsrpt',
		label: 'TLSRPT',
		blurb: 'TLS reporting TXT for SMTP TLS failure reports.',
		example: 'tlsrpt:example.com',
		group: 'mail',
		web: true,
	},
	{
		id: 'smtp',
		label: 'SMTP',
		blurb: 'Banner probe on 587 (STARTTLS) and 465 (SMTPS). Port 25 is CLI-only (Workers block it). Prefer an MSA host such as smtp.example.com.',
		example: 'smtp:smtp.gmail.com',
		group: 'mail',
		web: true,
	},
	{
		id: 'headers',
		label: 'Header analyzer',
		blurb: 'Paste RFC 5322 headers. Parses hops, Authentication-Results, and spam scores in the browser (not a mailbox login).',
		example: 'headers',
		group: 'mail',
		web: true,
	},
	{
		id: 'blacklist',
		label: 'Blacklist',
		blurb:
			'Multi-DNSBL check (MX IPs preferred). On the Worker, Spamhaus often returns open-resolver query errors — connect Settings → Probe agent (`mx agent`) for local DNS, or use a DQS key on a private instance.',
		example: 'blacklist:1.2.3.4',
		group: 'reputation',
		web: true,
	},
	{
		id: 'a',
		label: 'A',
		blurb: 'IPv4 address records.',
		example: 'a:example.com',
		group: 'dns',
		web: true,
	},
	{
		id: 'aaaa',
		label: 'AAAA',
		blurb: 'IPv6 address records.',
		example: 'aaaa:example.com',
		group: 'dns',
		web: true,
	},
	{
		id: 'cname',
		label: 'CNAME',
		blurb: 'Canonical name alias records.',
		example: 'cname:www.example.com',
		group: 'dns',
		web: true,
	},
	{
		id: 'ns',
		label: 'NS',
		blurb: 'Authoritative nameservers.',
		example: 'ns:example.com',
		group: 'dns',
		web: true,
	},
	{
		id: 'ptr',
		label: 'PTR',
		blurb: 'Reverse DNS for an IP.',
		example: 'ptr:1.2.3.4',
		group: 'dns',
		web: true,
	},
	{
		id: 'soa',
		label: 'SOA',
		blurb: 'Start of Authority (serial, refresh, primary NS).',
		example: 'soa:example.com',
		group: 'dns',
		web: true,
	},
	{
		id: 'txt',
		label: 'TXT',
		blurb: 'All TXT records at the name.',
		example: 'txt:example.com',
		group: 'dns',
		web: true,
	},
	{
		id: 'dns',
		label: 'DNS health',
		blurb: 'Nameserver count and basic authoritative sanity.',
		example: 'dns:example.com',
		group: 'dns',
		web: true,
	},
	{
		id: 'http',
		label: 'HTTP',
		blurb: 'HTTP connectivity and status.',
		example: 'http:example.com',
		group: 'web',
		web: true,
	},
	{
		id: 'https',
		label: 'HTTPS',
		blurb: 'HTTPS connectivity and status.',
		example: 'https:example.com',
		group: 'web',
		web: true,
	},
	{
		id: 'tcp',
		label: 'TCP',
		blurb: 'Raw TCP connect. Syntax: tcp:host:port. Port 25 is blocked on Workers.',
		example: 'tcp:example.com:443',
		group: 'web',
		web: true,
	},
	{
		id: 'whois',
		label: 'WHOIS/RDAP',
		blurb: 'Domain registration via RDAP.',
		example: 'whois:example.com',
		group: 'registration',
		web: true,
	},
	{
		id: 'arin',
		label: 'ARIN/RDAP',
		blurb: 'IP network registration (RDAP).',
		example: 'arin:1.2.3.4',
		group: 'registration',
		web: true,
	},
	{
		id: 'asn',
		label: 'ASN',
		blurb: 'Autonomous system for an IP (Team Cymru style).',
		example: 'asn:1.2.3.4',
		group: 'registration',
		web: true,
	},
	{
		id: 'ping',
		label: 'Ping',
		blurb: 'ICMP echo. Use the CLI: mx ping:host.',
		example: 'ping:example.com',
		group: 'cli',
		web: false,
	},
	{
		id: 'trace',
		label: 'Traceroute',
		blurb: 'ICMP traceroute. Use the CLI: mx trace:host.',
		example: 'trace:example.com',
		group: 'cli',
		web: false,
	},
];

export function guideTool(id: string): GuideTool | undefined {
	return GUIDE_TOOLS.find((t) => t.id === id);
}
