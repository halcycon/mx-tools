import { answersOf, doh, stripTxt } from './dns';
import type { CheckResult, CheckRow, Severity } from './types';

type Term = { raw: string; qual: string; mech: string; arg: string };

const LOOKUP_MECHS = new Set(['include', 'a', 'mx', 'ptr', 'exists', 'redirect']);

export function parseSpfTerms(record: string): Term[] {
	const body = record.replace(/^v=spf1\s+/i, '').trim();
	if (!body) return [];
	return body.split(/\s+/).filter(Boolean).map((raw) => {
		let rest = raw;
		let qual = '+';
		if (rest.startsWith('+') || rest.startsWith('-') || rest.startsWith('~') || rest.startsWith('?')) {
			qual = rest[0];
			rest = rest.slice(1);
		}
		const colon = rest.indexOf(':');
		let mech = rest;
		let arg = '';
		if (rest.toLowerCase().startsWith('redirect=')) {
			mech = 'redirect';
			arg = rest.slice('redirect='.length);
		} else if (rest.toLowerCase().startsWith('exp=')) {
			mech = 'exp';
			arg = rest.slice('exp='.length);
		} else if (colon >= 0) {
			mech = rest.slice(0, colon).toLowerCase();
			arg = rest.slice(colon + 1);
		} else {
			mech = rest.toLowerCase();
		}
		return { raw, qual, mech, arg };
	});
}

async function spfRecord(domain: string): Promise<string | null> {
	const resp = await doh(domain, 'TXT');
	const recs = answersOf(resp, 'TXT').map((a) => stripTxt(a.data)).filter((v) => v.toLowerCase().startsWith('v=spf1'));
	return recs[0] ?? null;
}

async function hostIps(host: string): Promise<string[]> {
	const [a, aaaa] = await Promise.all([doh(host, 'A'), doh(host, 'AAAA')]);
	return [
		...answersOf(a, 'A').map((x) => `ip4:${x.data}`),
		...answersOf(aaaa, 'AAAA').map((x) => `ip6:${x.data}`),
	];
}

type FlattenState = {
	lookups: number;
	ips: string[];
	kept: string[];
	notes: CheckRow[];
	seen: Set<string>;
};

async function flattenDomain(domain: string, state: FlattenState, depth: number): Promise<string | null> {
	const key = domain.replace(/\.$/, '').toLowerCase();
	if (state.seen.has(key)) {
		state.notes.push({ status: 'warn', name: 'Loop', value: `Already visited ${key}` });
		return null;
	}
	if (depth > 10) {
		state.notes.push({ status: 'fail', name: 'Depth', value: `Too much nesting at ${key}` });
		return null;
	}
	state.seen.add(key);
	const rec = await spfRecord(key);
	if (!rec) {
		state.notes.push({ status: 'fail', name: 'Missing', value: `No SPF at ${key}` });
		return null;
	}
	state.notes.push({ status: 'info', name: key, value: rec });

	let allQual = '?all';
	for (const term of parseSpfTerms(rec)) {
		if (term.mech === 'all') {
			allQual = `${term.qual === '+' ? '+' : term.qual}all`;
			continue;
		}
		if (term.mech === 'exp') continue;
		if (LOOKUP_MECHS.has(term.mech) || term.mech === 'redirect') state.lookups += 1;

		if (term.mech === 'ip4' || term.mech === 'ip6') {
			state.ips.push(`${term.qual === '+' ? '' : term.qual}${term.mech}:${term.arg}`);
			continue;
		}
		if (term.mech === 'include') {
			await flattenDomain(term.arg, state, depth + 1);
			continue;
		}
		if (term.mech === 'redirect') {
			const nested = await flattenDomain(term.arg, state, depth + 1);
			if (nested) allQual = nested;
			continue;
		}
		const q = term.qual === '+' ? '' : term.qual;
		if (term.mech === 'a') {
			let host = term.arg || key;
			let cidr = '';
			const slash = host.lastIndexOf('/');
			if (slash > 0 && /^\d+$/.test(host.slice(slash + 1))) {
				cidr = host.slice(slash);
				host = host.slice(0, slash);
			}
			for (const ip of await hostIps(host)) {
				state.ips.push(`${q}${cidr ? `${ip}${cidr}` : ip}`);
			}
			continue;
		}
		if (term.mech === 'mx') {
			const host = term.arg || key;
			const mx = answersOf(await doh(host, 'MX'), 'MX');
			for (const recMx of mx) {
				const mxHost = recMx.data.split(/\s+/).pop()?.replace(/\.$/, '') ?? '';
				if (!mxHost || mxHost === '.') continue;
				state.lookups += 1;
				for (const ip of await hostIps(mxHost)) {
					state.ips.push(`${q}${ip}`);
				}
			}
			continue;
		}
		if (term.mech === 'ptr' || term.mech === 'exists' || term.raw.includes('%{')) {
			state.kept.push(term.raw);
			state.notes.push({
				status: 'warn',
				name: 'Cannot flatten',
				value: term.raw,
				info: 'ptr/exists/macros still need DNS at evaluation time',
			});
			continue;
		}
		state.kept.push(term.raw);
	}
	return allQual;
}

function uniq(list: string[]): string[] {
	return [...new Set(list)];
}

export async function runSpfFlat(target: string): Promise<CheckResult> {
	const start = Date.now();
	const domain = target.replace(/\.$/, '');
	const state: FlattenState = { lookups: 0, ips: [], kept: [], notes: [], seen: new Set() };
	const allQual = (await flattenDomain(domain, state, 0)) ?? '?all';
	const ips = uniq(state.ips);
	const kept = uniq(state.kept);
	const flat = ['v=spf1', ...ips, ...kept, allQual].join(' ');
	const rows: CheckRow[] = [
		{
			status: (state.lookups > 10 ? 'fail' : state.lookups > 7 ? 'warn' : 'ok') as Severity,
			name: 'DNS lookups (orig.)',
			value: String(state.lookups),
			info: 'RFC 7208 limit is 10 mechanisms that cause DNS lookups',
		},
		{
			status: ips.length ? 'ok' : 'warn',
			name: 'Flattened IPs',
			value: String(ips.length),
		},
		{
			status: flat.length > 450 ? 'warn' : 'ok',
			name: 'Record length',
			value: `${flat.length} chars`,
			info: flat.length > 255 ? 'Split into multiple TXT strings (max 255 each) when publishing' : undefined,
		},
		{ status: 'ok', name: 'Flattened SPF', value: flat },
	];
	rows.push(...state.notes);
	return {
		tool: 'spf-flat',
		title: 'SPF Flattening',
		query: domain,
		ok: state.lookups <= 10 && Boolean(ips.length || kept.length),
		summary: state.lookups > 10 ? `Over lookup budget (${state.lookups}/10)` : `Flattened ${ips.length} CIDR/IP term(s), ${state.lookups} orig. lookups`,
		rows,
		related: [
			{ tool: 'spf', label: 'Original SPF', query: `spf:${domain}` },
		],
		elapsedMs: Date.now() - start,
	};
}
