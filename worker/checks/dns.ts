/** DNS-over-HTTPS helpers (Cloudflare 1.1.1.1). */

export type DnsRecordType = 'A' | 'AAAA' | 'CNAME' | 'MX' | 'NS' | 'PTR' | 'SOA' | 'TXT' | 'CAA';

export type DnsAnswer = {
	name: string;
	type: number;
	TTL: number;
	data: string;
};

export type DohResponse = {
	Status: number;
	Answer?: DnsAnswer[];
	Authority?: DnsAnswer[];
	Question?: Array<{ name: string; type: number }>;
};

const TYPE_NUM: Record<DnsRecordType, number> = {
	A: 1,
	AAAA: 28,
	CNAME: 5,
	MX: 15,
	NS: 2,
	PTR: 12,
	SOA: 6,
	TXT: 16,
	CAA: 257,
};

// Simple in-memory DoH cache to reduce duplicated lookups within/between requests.
const DOH_CACHE_TTL_MS = 30_000;
const DOH_CACHE_MAX = 256;
const DOH_CACHE = new Map<string, { ts: number; resp: DohResponse }>();

export async function doh(name: string, type: DnsRecordType): Promise<DohResponse> {
	const normalizedName = name.replace(/\.$/, '').toLowerCase();
	const key = `${type}|${normalizedName}`;
	const hit = DOH_CACHE.get(key);
	if (hit && Date.now() - hit.ts < DOH_CACHE_TTL_MS) return hit.resp;

	const url = new URL('https://cloudflare-dns.com/dns-query');
	url.searchParams.set('name', normalizedName);
	url.searchParams.set('type', type);
	const res = await fetch(url.toString(), {
		headers: { Accept: 'application/dns-json' },
	});
	if (!res.ok) throw new Error(`DoH ${res.status} for ${name}/${type}`);

	const resp = (await res.json()) as DohResponse;
	DOH_CACHE.set(key, { ts: Date.now(), resp });
	if (DOH_CACHE.size > DOH_CACHE_MAX) {
		// Cheap eviction: clear to avoid O(n) oldest tracking.
		DOH_CACHE.clear();
	}
	return resp;
}

export function answersOf(resp: DohResponse, type?: DnsRecordType): DnsAnswer[] {
	const list = resp.Answer ?? [];
	if (!type) return list;
	const n = TYPE_NUM[type];
	return list.filter((a) => a.type === n);
}

export function stripTxt(data: string): string {
	// Cloudflare returns quoted TXT chunks: "v=spf1" " ~all"
	return data
		.replace(/"\s*"/g, '')
		.replace(/^"|"$/g, '')
		.trim();
}

export function reverseIp(ip: string): string | null {
	if (ip.includes(':')) {
		// IPv6 nibble form for DNSBL
		const expanded = expandIpv6(ip);
		if (!expanded) return null;
		return expanded.replace(/:/g, '').split('').reverse().join('.');
	}
	const parts = ip.split('.');
	if (parts.length !== 4 || parts.some((p) => !/^\d+$/.test(p))) return null;
	return parts.reverse().join('.');
}

function expandIpv6(ip: string): string | null {
	try {
		const halves = ip.split('::');
		let groups: string[] = [];
		if (halves.length === 1) {
			groups = ip.split(':');
		} else if (halves.length === 2) {
			const left = halves[0] ? halves[0].split(':') : [];
			const right = halves[1] ? halves[1].split(':') : [];
			const fill = 8 - left.length - right.length;
			groups = [...left, ...Array(fill).fill('0'), ...right];
		} else return null;
		if (groups.length !== 8) return null;
		return groups.map((g) => g.padStart(4, '0')).join(':');
	} catch {
		return null;
	}
}

export function isIp(s: string): boolean {
	return isIpv4(s) || s.includes(':');
}

export function isIpv4(s: string): boolean {
	const p = s.split('.');
	return p.length === 4 && p.every((x) => /^\d+$/.test(x) && Number(x) >= 0 && Number(x) <= 255);
}

export async function resolveHostToIps(host: string): Promise<string[]> {
	if (isIp(host)) return [host];
	const [a, aaaa] = await Promise.all([doh(host, 'A'), doh(host, 'AAAA')]);
	return [
		...answersOf(a, 'A').map((x) => x.data),
		...answersOf(aaaa, 'AAAA').map((x) => x.data),
	];
}
