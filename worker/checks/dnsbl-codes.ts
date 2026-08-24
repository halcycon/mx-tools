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
	'127.0.0.4': 'XBL/CBL — exploited host',
	'127.0.0.9': 'SBL DROP / hijacked',
	'127.0.0.10': 'PBL — ISP dynamic/end-user',
	'127.0.0.11': 'PBL — ISP dynamic/end-user',
};

const QUERY_ERRORS: Record<string, string> = {
	'127.255.255.252': 'Malformed DNSBL zone name.',
	'127.255.255.254':
		'Blocked as an anonymous/open-resolver query. Public resolvers (including Cloudflare 1.1.1.1) cannot use Spamhaus public mirrors. Add a Spamhaus DQS key on a private instance, or this is not a listing.',
	'127.255.255.255': 'Excessive queries — rate limited. Not a listing.',
};

export function isQueryErrorCode(ip: string): boolean {
	return ip.startsWith('127.255.255.');
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

	const labels = answers.map((a) => {
		if (zone.includes('spamhaus') && SPAMHAUS_LISTED[a]) return `${a} (${SPAMHAUS_LISTED[a]})`;
		return a;
	});

	return {
		kind: 'listed',
		status: 'fail',
		label: `LISTED ${labels.join(', ')}`,
		detail: zone.includes('spamhaus') ? 'Spamhaus dataset hit — see return code meaning above.' : 'Present on this DNSBL.',
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
