/** Published Cloudflare proxy/anycast ranges: https://www.cloudflare.com/ips-v4/ */

const CLOUDFLARE_V4 = [
	'173.245.48.0/20',
	'103.21.244.0/22',
	'103.22.200.0/22',
	'103.31.4.0/22',
	'141.101.64.0/18',
	'108.162.192.0/18',
	'190.93.240.0/20',
	'188.114.96.0/20',
	'197.234.240.0/22',
	'198.41.128.0/17',
	'162.158.0.0/15',
	'104.16.0.0/13',
	'104.24.0.0/14',
	'172.64.0.0/13',
	'131.0.72.0/22',
] as const;

function ipv4ToInt(ip: string): number | null {
	const p = ip.split('.');
	if (p.length !== 4) return null;
	let n = 0;
	for (const part of p) {
		if (!/^\d+$/.test(part)) return null;
		const v = Number(part);
		if (v < 0 || v > 255) return null;
		n = (n << 8) + v;
	}
	return n >>> 0;
}

export function ipv4InCidr(ip: string, cidr: string): boolean {
	const [net, bitsStr] = cidr.split('/');
	const bits = Number(bitsStr);
	const ipN = ipv4ToInt(ip);
	const netN = ipv4ToInt(net);
	if (ipN === null || netN === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
	const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
	return (ipN & mask) === (netN & mask);
}

export function isCloudflareIPv4(ip: string): boolean {
	return CLOUDFLARE_V4.some((c) => ipv4InCidr(ip, c));
}

export type BlacklistAddr = {
	ip: string;
	role: string;
	cloudflare: boolean;
};

export function selectBlacklistIps(web: string[], mx: Array<{ host: string; ips: string[] }>): {
	check: BlacklistAddr[];
	skipped: BlacklistAddr[];
} {
	const seen = new Set<string>();
	const check: BlacklistAddr[] = [];
	const skipped: BlacklistAddr[] = [];
	const add = (list: BlacklistAddr[], ip: string, role: string) => {
		if (!ip || ip.includes(':') || seen.has(ip)) return;
		seen.add(ip);
		list.push({ ip, role, cloudflare: isCloudflareIPv4(ip) });
	};

	for (const m of mx) {
		for (const ip of m.ips) add(check, ip, `MX ${m.host}`);
	}
	const haveMail = check.length > 0;
	for (const ip of web) {
		const cf = isCloudflareIPv4(ip);
		if (haveMail && cf) add(skipped, ip, 'website A');
		else add(check, ip, 'website A');
	}
	return { check: check.slice(0, 5), skipped };
}
