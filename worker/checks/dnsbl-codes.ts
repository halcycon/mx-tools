import type { Severity } from './types';

/** DNSBL answers in 127.255.255.0/24 are query errors, not listings. */
export type DnsblKind = 'clean' | 'listed' | 'whitelist' | 'query_error';

export type DnsblInterpretation = {
	kind: DnsblKind;
	status: Severity;
	label: string;
	detail: string;
};

const SPAMHAUS_LISTED: Record<string, string> = {
	'127.0.0.2': 'SBL — spam source / snowshoe',
	'127.0.0.3': 'CSS — snowshoe / exploited',
	'127.0.0.4': 'XBL/CBL — exploited/compromised host',
	'127.0.0.5': 'XBL — reserved listing code',
	'127.0.0.6': 'XBL — reserved listing code',
	'127.0.0.7': 'XBL — reserved listing code',
	'127.0.0.9': 'SBL DROP / hijacked',
	'127.0.0.10': 'PBL — ISP dynamic/end-user',
	'127.0.0.11': 'PBL — ISP dynamic/end-user',
	'127.0.0.30': 'BCL — botnet controller',
};

const CBL_LISTED: Record<string, string> = {
	'127.0.0.2': 'CBL — exploited host',
	'127.0.0.4': 'CBL/XBL — exploited host',
};

const SORBS_LISTED: Record<string, string> = {
	'127.0.0.2': 'HTTP',
	'127.0.0.3': 'SOCKS',
	'127.0.0.4': 'MISC',
	'127.0.0.5': 'SMTP',
	'127.0.0.6': 'WEB',
	'127.0.0.7': 'BLOCK',
	'127.0.0.8': 'ZOMBIE',
	'127.0.0.9': 'DUL (dynamic)',
	'127.0.0.10': 'BADCONF',
	'127.0.0.11': 'NOSERVER',
};

const QUERY_ERRORS: Record<string, string> = {
	'127.255.255.252': 'Malformed DNSBL zone name.',
	'127.255.255.254':
		'Blocked as an anonymous/open-resolver query. Public resolvers (including Cloudflare 1.1.1.1) cannot use Spamhaus public mirrors. Add a Spamhaus DQS key on a private instance, or this is not a listing.',
	'127.255.255.255': 'Excessive queries — rate limited. Not a listing.',
};

const LISTING_NOT_ERROR =
	'This is a listing return code (127.0.0.0/24), not a query error. Query errors are only 127.255.255.0/24.';

export function isQueryErrorCode(ip: string): boolean {
	return ip.startsWith('127.255.255.');
}

function listingMap(zone: string): Record<string, string> | null {
	const z = zone.toLowerCase();
	if (z.includes('spamhaus')) return SPAMHAUS_LISTED;
	if (z.includes('abuseat') || z.includes('cbl.')) return CBL_LISTED;
	if (z.includes('sorbs')) return SORBS_LISTED;
	return null;
}

function describeListed(zone: string, answers: string[]): { labels: string[]; detail: string } {
	const map = listingMap(zone);
	const labels = answers.map((a) => {
		const meaning = map?.[a];
		return meaning ? `${a} (${meaning})` : a;
	});
	const primary = map?.[answers[0] ?? ''] ?? '';
	const detail = primary
		? `${primary}. ${LISTING_NOT_ERROR}`
		: `Present on this DNSBL. ${LISTING_NOT_ERROR}`;
	return { labels, detail };
}

export function interpretDnsblCodes(zone: string, answers: string[], whitelist = false): DnsblInterpretation {
	if (!answers.length) {
		return { kind: 'clean', status: 'ok', label: 'OK', detail: 'Not listed' };
	}

	const error = answers.find((a) => QUERY_ERRORS[a] || isQueryErrorCode(a));
	if (error) {
		const detail =
			QUERY_ERRORS[error] ??
			`DNSBL returned error code ${error} (127.255.255.0/24). This is not a reputation listing.`;
		return {
			kind: 'query_error',
			status: 'warn',
			label: `Query error ${error}`,
			detail: zone.includes('spamhaus')
				? `${detail} For private deploys, set SPAMHAUS_DQS_KEY (or paste it in Settings) and queries go to {key}.zen.dq.spamhaus.net.`
				: detail,
		};
	}

	if (whitelist) {
		return {
			kind: 'whitelist',
			status: 'ok',
			label: `Listed (good) ${answers.join(', ')}`,
			detail: 'Present on a DNS whitelist.',
		};
	}

	const { labels, detail } = describeListed(zone, answers);
	return {
		kind: 'listed',
		status: 'fail',
		label: `LISTED ${labels.join(', ')}`,
		detail,
	};
}

/** Public zen.spamhaus.org rejects DoH/public resolvers. DQS uses a keyed zone. */
export function spamhausZone(dqsKey?: string): { zone: string; name: string; url: string } {
	const key = dqsKey?.trim();
	if (key) {
		return {
			zone: `${key}.zen.dq.spamhaus.net`,
			name: 'Spamhaus ZEN (DQS)',
			url: 'https://www.spamhaus.org/lookup/',
		};
	}
	return {
		zone: 'zen.spamhaus.org',
		name: 'Spamhaus ZEN',
		url: 'https://www.spamhaus.org/lookup/',
	};
}
