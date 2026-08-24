import type { CheckResult, CheckRow, Severity } from './types';

export type HeaderField = { name: string; value: string };

const MAX_RAW = 256 * 1024;

export function unfoldHeaders(raw: string): HeaderField[] {
	const normalized = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
	const headerBlock = normalized.split(/\n\s*\n/)[0] ?? normalized;
	const fields: HeaderField[] = [];
	for (const line of headerBlock.split('\n')) {
		if (/^[ \t]/.test(line) && fields.length) {
			fields[fields.length - 1].value += ` ${line.trim()}`;
			continue;
		}
		const i = line.indexOf(':');
		if (i <= 0) continue;
		fields.push({ name: line.slice(0, i).trim(), value: line.slice(i + 1).trim() });
	}
	return fields;
}

function all(fields: HeaderField[], name: string): string[] {
	const n = name.toLowerCase();
	return fields.filter((f) => f.name.toLowerCase() === n).map((f) => f.value);
}

function first(fields: HeaderField[], name: string): string | undefined {
	return all(fields, name)[0];
}

function emailsIn(value: string): string[] {
	const out: string[] = [];
	const angle = [...value.matchAll(/<([^>]+@[^>]+)>/g)];
	if (angle.length) {
		for (const m of angle) out.push(m[1].toLowerCase());
		return out;
	}
	const bare = value.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
	if (bare) out.push(bare[0].toLowerCase());
	return out;
}

function domainOf(addr: string): string {
	const at = addr.lastIndexOf('@');
	return at >= 0 ? addr.slice(at + 1) : addr;
}

function parseDate(value: string): Date | null {
	const trimmed = value.replace(/\s+\([^)]+\)\s*$/, '').trim();
	const t = Date.parse(trimmed);
	if (!Number.isNaN(t)) return new Date(t);
	const t2 = Date.parse(value);
	return Number.isNaN(t2) ? null : new Date(t2);
}

export type Hop = {
	index: number;
	from: string;
	by: string;
	with: string;
	id: string;
	for: string;
	when: string;
	ip: string;
	delayMs: number | null;
};

function parseReceived(value: string): Omit<Hop, 'index' | 'delayMs'> {
	const datePart = value.includes(';') ? value.slice(value.lastIndexOf(';') + 1).trim() : '';
	const body = value.includes(';') ? value.slice(0, value.lastIndexOf(';')) : value;
	const from = /\bfrom\s+(\S+)/i.exec(body)?.[1] ?? '';
	const by = /\bby\s+(\S+)/i.exec(body)?.[1] ?? '';
	const withTok = /\bwith\s+(\S+)/i.exec(body)?.[1] ?? '';
	const id = /\bid\s+(\S+)/i.exec(body)?.[1] ?? '';
	const forAddr = /\bfor\s+<?([^\s>;]+)>?/i.exec(body)?.[1] ?? '';
	const ip =
		/\[([0-9a-fA-F:.]+)\]/.exec(body)?.[1] ??
		/\b(\d{1,3}(?:\.\d{1,3}){3})\b/.exec(body)?.[1] ??
		'';
	const whenDate = parseDate(datePart);
	return {
		from,
		by,
		with: withTok,
		id,
		for: forAddr,
		when: whenDate ? whenDate.toISOString() : datePart,
		ip,
	};
}

function formatDelay(ms: number): string {
	const abs = Math.abs(ms);
	if (abs < 1000) return `${ms}ms`;
	const s = abs / 1000;
	if (s < 60) return `${ms < 0 ? '-' : ''}${s.toFixed(1)}s`;
	const m = Math.floor(s / 60);
	const rem = Math.round(s % 60);
	return `${ms < 0 ? '-' : ''}${m}m ${rem}s`;
}

function delayStatus(ms: number | null): Severity {
	if (ms === null) return 'info';
	if (ms < 0) return 'warn';
	if (ms > 10 * 60 * 1000) return 'fail';
	if (ms > 60 * 1000) return 'warn';
	return 'ok';
}

type AuthHit = { method: string; result: string; detail: string };

function parseAuthResults(values: string[]): AuthHit[] {
	const hits: AuthHit[] = [];
	for (const value of values) {
		const chunks = value.split(';').map((s) => s.trim()).filter(Boolean);
		for (const chunk of chunks.slice(1)) {
			const m = /^(spf|dkim|dmarc|arc|compauth)\s*=\s*(\S+)/i.exec(chunk);
			if (!m) continue;
			hits.push({
				method: m[1].toLowerCase(),
				result: m[2].toLowerCase().replace(/;$/, ''),
				detail: chunk,
			});
		}
	}
	return hits;
}

function authTone(result: string): Severity {
	if (result === 'pass' || result === 'none') return result === 'pass' ? 'ok' : 'info';
	if (result === 'neutral' || result === 'softfail' || result === 'temperror' || result === 'policy') return 'warn';
	if (result === 'fail' || result === 'permerror' || result === 'hardfail') return 'fail';
	return 'info';
}

function parseSpam(fields: HeaderField[]): CheckRow[] {
	const rows: CheckRow[] = [];
	const status = first(fields, 'X-Spam-Status');
	if (status) {
		const yes = /^\s*yes\b/i.test(status);
		const score = /score\s*=\s*([-\d.]+)/i.exec(status)?.[1];
		rows.push({
			status: yes ? 'fail' : 'ok',
			name: 'X-Spam-Status',
			value: yes ? 'YES (flagged)' : 'No',
			info: score ? `score=${score}` : status.slice(0, 180),
		});
	}
	const scoreHdr = first(fields, 'X-Spam-Score');
	if (scoreHdr) {
		const n = Number(scoreHdr);
		rows.push({
			status: n >= 5 ? 'fail' : n >= 2 ? 'warn' : 'ok',
			name: 'X-Spam-Score',
			value: scoreHdr,
		});
	}
	const forefront = first(fields, 'X-Forefront-Antispam-Report') || first(fields, 'X-MS-Exchange-Organization-SCL');
	if (forefront) {
		const scl = /(?:SCL[:\s]|:)(\d+)/i.exec(forefront)?.[1] ?? forefront;
		const n = Number(scl);
		rows.push({
			status: n >= 6 ? 'fail' : n >= 5 ? 'warn' : 'info',
			name: 'Microsoft SCL',
			value: String(scl),
			info: forefront.slice(0, 200),
		});
	}
	const spamassassin = first(fields, 'X-Spam-Flag');
	if (spamassassin) {
		rows.push({
			status: /^yes$/i.test(spamassassin.trim()) ? 'fail' : 'ok',
			name: 'X-Spam-Flag',
			value: spamassassin,
		});
	}
	return rows;
}

function dkimMeta(value: string): string {
	const d = /(?:^|;)\s*d=([^;]+)/i.exec(value)?.[1]?.trim();
	const s = /(?:^|;)\s*s=([^;]+)/i.exec(value)?.[1]?.trim();
	const a = /(?:^|;)\s*a=([^;]+)/i.exec(value)?.[1]?.trim();
	return [d && `d=${d}`, s && `s=${s}`, a && `a=${a}`].filter(Boolean).join(' ');
}

export function analyzeHeaders(raw: string): CheckResult[] {
	const start = Date.now();
	if (!raw.trim()) {
		return [
			{
				tool: 'headers',
				title: 'Email headers',
				query: 'headers',
				ok: false,
				summary: 'Paste a header block first',
				rows: [],
				elapsedMs: 0,
			},
		];
	}
	if (raw.length > MAX_RAW) {
		return [
			{
				tool: 'headers',
				title: 'Email headers',
				query: 'headers',
				ok: false,
				summary: `Header too large (${raw.length} bytes; max ${MAX_RAW})`,
				rows: [],
				elapsedMs: 0,
			},
		];
	}

	const fields = unfoldHeaders(raw);
	if (!fields.length) {
		return [
			{
				tool: 'headers',
				title: 'Email headers',
				query: 'headers',
				ok: false,
				summary: 'No RFC 5322 header fields found',
				rows: [],
				elapsedMs: Date.now() - start,
			},
		];
	}

	const from = first(fields, 'From') ?? '';
	const to = first(fields, 'To') ?? '';
	const subject = first(fields, 'Subject') ?? '(no subject)';
	const date = first(fields, 'Date') ?? '';
	const mid = first(fields, 'Message-ID') ?? first(fields, 'Message-Id') ?? '';
	const returnPath = first(fields, 'Return-Path') ?? '';
	const fromAddr = emailsIn(from)[0];
	const rpAddr = emailsIn(returnPath)[0];

	const summaryRows: CheckRow[] = [
		{ status: 'info', name: 'Subject', value: subject },
		{ status: 'info', name: 'From', value: from || '—' },
		{ status: 'info', name: 'To', value: to || '—' },
		{ status: date ? 'ok' : 'warn', name: 'Date', value: date || 'Missing' },
		{ status: mid ? 'ok' : 'warn', name: 'Message-ID', value: mid || 'Missing' },
		{ status: 'info', name: 'Return-Path', value: returnPath || '—' },
	];
	if (fromAddr && rpAddr && domainOf(fromAddr) !== domainOf(rpAddr)) {
		summaryRows.push({
			status: 'warn',
			name: 'Envelope vs From',
			value: `${rpAddr} vs ${fromAddr}`,
			info: 'Return-Path domain differs from From (can be forwarding, or spoofing)',
		});
	}

	const received = all(fields, 'Received');
	const hops: Hop[] = received.map((v, i) => ({ index: received.length - i, ...parseReceived(v), delayMs: null }));
	// hops[] is newest-first (header order). Chronological = reverse.
	const chrono = [...hops].reverse();
	for (let i = 1; i < chrono.length; i++) {
		const prev = parseDate(chrono[i - 1].when) ?? (/\d{4}/.test(chrono[i - 1].when) ? new Date(chrono[i - 1].when) : null);
		const cur = parseDate(chrono[i].when) ?? (/\d{4}/.test(chrono[i].when) ? new Date(chrono[i].when) : null);
		if (prev && cur && !Number.isNaN(prev.getTime()) && !Number.isNaN(cur.getTime())) {
			chrono[i].delayMs = cur.getTime() - prev.getTime();
		}
	}
	const delayByIndex = new Map(chrono.map((h) => [h.index, h.delayMs]));
	for (const h of hops) h.delayMs = delayByIndex.get(h.index) ?? null;

	const hopRows: CheckRow[] = hops.map((h) => ({
		status: delayStatus(h.delayMs),
		name: `Hop ${h.index}`,
		value: [h.from && `from ${h.from}`, h.by && `by ${h.by}`, h.with && `with ${h.with}`].filter(Boolean).join('  ') || h.when,
		info: [
			h.delayMs !== null ? `delay ${formatDelay(h.delayMs)}` : null,
			h.ip && `ip ${h.ip}`,
			h.when,
			h.for && `for ${h.for}`,
		]
			.filter(Boolean)
			.join(' · '),
	}));

	const authHits = parseAuthResults(all(fields, 'Authentication-Results'));
	const receivedSpf = first(fields, 'Received-SPF');
	const authRows: CheckRow[] = [];
	if (receivedSpf) {
		const tok = receivedSpf.trim().split(/\s+/)[0].toLowerCase();
		authRows.push({ status: authTone(tok), name: 'Received-SPF', value: tok, info: receivedSpf.slice(0, 200) });
	}
	for (const hit of authHits) {
		authRows.push({
			status: authTone(hit.result),
			name: hit.method.toUpperCase(),
			value: hit.result,
			info: hit.detail.slice(0, 220),
		});
	}
	for (const sig of all(fields, 'DKIM-Signature')) {
		authRows.push({ status: 'info', name: 'DKIM-Signature', value: dkimMeta(sig) || 'present', info: sig.slice(0, 160) });
	}
	if (!authRows.length) {
		authRows.push({ status: 'warn', name: 'Auth', value: 'No Authentication-Results or Received-SPF' });
	}

	const spamRows = parseSpam(fields);
	const elapsed = Date.now() - start;
	const fromDomain = fromAddr ? domainOf(fromAddr) : '';
	const related: CheckResult['related'] = [];
	if (fromDomain) {
		related.push({ tool: 'spf', label: `SPF ${fromDomain}`, query: `spf:${fromDomain}` });
		related.push({ tool: 'dmarc', label: `DMARC ${fromDomain}`, query: `dmarc:${fromDomain}` });
		related.push({ tool: 'mx', label: `MX ${fromDomain}`, query: `mx:${fromDomain}` });
	}
	const hopIp = hops.find((h) => h.ip && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(h.ip))?.ip;
	if (hopIp) related.push({ tool: 'blacklist', label: `Blacklist ${hopIp}`, query: `blacklist:${hopIp}` });

	const failAuth = authRows.some((r) => r.status === 'fail');
	const results: CheckResult[] = [
		{
			tool: 'headers',
			title: 'Email headers',
			query: subject,
			ok: Boolean(from && received.length),
			summary: `${received.length} hop(s) · ${subject}`,
			rows: summaryRows,
			related,
			elapsedMs: elapsed,
		},
		{
			tool: 'headers-hops',
			title: 'Delivery path',
			query: `${received.length} Received`,
			ok: received.length > 0,
			summary: received.length ? `${received.length} hop(s), newest first` : 'No Received headers',
			rows: hopRows.length ? hopRows : [{ status: 'warn', name: 'Received', value: 'None' }],
			elapsedMs: elapsed,
		},
		{
			tool: 'headers-auth',
			title: 'Authentication results',
			query: fromDomain || 'headers',
			ok: !failAuth,
			summary: authHits.length
				? authHits.map((h) => `${h.method}=${h.result}`).join(' · ')
				: receivedSpf
					? `Received-SPF ${receivedSpf.split(/\s+/)[0]}`
					: 'No auth headers',
			rows: authRows,
			related,
			elapsedMs: elapsed,
		},
	];
	if (spamRows.length) {
		results.push({
			tool: 'headers-spam',
			title: 'Anti-spam headers',
			query: 'headers',
			ok: !spamRows.some((r) => r.status === 'fail'),
			summary: spamRows.map((r) => `${r.name} ${r.value}`).join(' · '),
			rows: spamRows,
			elapsedMs: elapsed,
		});
	}
	return results;
}

export const HEADER_MAX_BYTES = MAX_RAW;
