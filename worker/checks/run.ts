import { answersOf, doh, isIp, resolveHostToIps, reverseIp, stripTxt } from './dns';
import { interpretDnsblCodes, spamhausZone } from './dnsbl-codes';
import { DNSBLS } from './dnsbls';
import type { CheckResult, CheckRow, LookupOptions, ParsedQuery, Severity } from './types';

function timed(): { start: number; done: () => number } {
	const start = Date.now();
	return { start, done: () => Date.now() - start };
}

function base(tool: string, title: string, query: string, rows: CheckRow[], summary: string, elapsedMs: number, ok = true): CheckResult {
	return { tool, title, query, ok, summary, rows, elapsedMs };
}

export async function runA(target: string): Promise<CheckResult> {
	const t = timed();
	const resp = await doh(target, 'A');
	const ans = answersOf(resp, 'A');
	const rows: CheckRow[] = ans.map((a) => ({
		status: 'ok' as Severity,
		name: a.name,
		value: a.data,
		info: `TTL ${a.TTL}`,
	}));
	return base('a', 'A Record', target, rows, rows.length ? `${rows.length} A record(s)` : 'No A records', t.done(), rows.length > 0);
}

export async function runAaaa(target: string): Promise<CheckResult> {
	const t = timed();
	const resp = await doh(target, 'AAAA');
	const ans = answersOf(resp, 'AAAA');
	const rows: CheckRow[] = ans.map((a) => ({
		status: 'ok',
		name: a.name,
		value: a.data,
		info: `TTL ${a.TTL}`,
	}));
	return base('aaaa', 'AAAA Record', target, rows, rows.length ? `${rows.length} AAAA record(s)` : 'No AAAA records', t.done(), rows.length > 0);
}

export async function runCname(target: string): Promise<CheckResult> {
	const t = timed();
	const resp = await doh(target, 'CNAME');
	const ans = answersOf(resp, 'CNAME');
	const rows: CheckRow[] = ans.map((a) => ({
		status: 'ok',
		name: a.name,
		value: a.data,
		info: `TTL ${a.TTL}`,
	}));
	return base('cname', 'CNAME Record', target, rows, rows.length ? ans[0].data : 'No CNAME', t.done(), rows.length > 0);
}

export async function runMx(target: string): Promise<CheckResult> {
	const t = timed();
	const resp = await doh(target, 'MX');
	const ans = answersOf(resp, 'MX');
	const parsed = ans
		.map((a) => {
			const [pref, host] = a.data.split(/\s+/);
			return { pref: Number(pref), host: host?.replace(/\.$/, '') ?? '', ttl: a.TTL };
		})
		.sort((a, b) => a.pref - b.pref);

	const rows: CheckRow[] = [];
	for (const m of parsed) {
		if (!m.host || m.host === '.') {
			rows.push({
				status: 'info',
				name: `Preference ${m.pref}`,
				value: '(null MX)',
				info: 'Explicitly no mail service',
			});
			continue;
		}
		const ips = await resolveHostToIps(m.host);
		rows.push({
			status: ips.length ? 'ok' : 'warn',
			name: `Preference ${m.pref}`,
			value: m.host,
			info: ips.length ? `IP: ${ips.join(', ')}` : 'No A/AAAA for MX host',
		});
	}
	return {
		...base('mx', 'MX Lookup', target, rows, rows.length ? `${rows.length} mail server(s)` : 'No MX records', t.done(), rows.length > 0),
		related: rows
			.filter((r) => r.value !== '(null MX)')
			.slice(0, 3)
			.flatMap((r) => [
				{ tool: 'smtp', label: `SMTP ${r.value}`, query: `smtp:${r.value}` },
				{ tool: 'blacklist', label: `Blacklist ${r.value}`, query: `blacklist:${r.value}` },
			]),
	};
}

export async function runNs(target: string): Promise<CheckResult> {
	const t = timed();
	const resp = await doh(target, 'NS');
	const ans = answersOf(resp, 'NS');
	const rows: CheckRow[] = ans.map((a) => ({
		status: 'ok',
		name: 'NS',
		value: a.data.replace(/\.$/, ''),
		info: `TTL ${a.TTL}`,
	}));
	return base('ns', 'NS Records', target, rows, rows.length ? `${rows.length} nameserver(s)` : 'No NS', t.done(), rows.length > 0);
}

export async function runPtr(target: string): Promise<CheckResult> {
	const t = timed();
	let name = target;
	if (isIp(target) && !target.includes(':')) {
		name = `${target.split('.').reverse().join('.')}.in-addr.arpa`;
	} else if (target.includes(':')) {
		const rev = reverseIp(target);
		if (!rev) return base('ptr', 'PTR Lookup', target, [], 'Invalid IPv6', t.done(), false);
		name = `${rev}.ip6.arpa`;
	}
	const resp = await doh(name, 'PTR');
	const ans = answersOf(resp, 'PTR');
	const rows: CheckRow[] = ans.map((a) => ({
		status: 'ok',
		name: target,
		value: a.data.replace(/\.$/, ''),
		info: `TTL ${a.TTL}`,
	}));
	return base('ptr', 'PTR Lookup', target, rows, rows.length ? rows[0].value : 'No PTR', t.done(), rows.length > 0);
}

export async function runSoa(target: string): Promise<CheckResult> {
	const t = timed();
	const resp = await doh(target, 'SOA');
	const ans = answersOf(resp, 'SOA');
	if (!ans.length) return base('soa', 'SOA Record', target, [], 'No SOA', t.done(), false);
	const parts = ans[0].data.split(/\s+/);
	const labels = ['Primary NS', 'Admin mailbox', 'Serial', 'Refresh', 'Retry', 'Expire', 'Minimum TTL'];
	const rows: CheckRow[] = parts.map((p, i) => ({
		status: 'ok',
		name: labels[i] ?? `Field ${i}`,
		value: p.replace(/\.$/, ''),
	}));
	return base('soa', 'SOA Record', target, rows, `Serial ${parts[2] ?? '?'}`, t.done());
}

export async function runTxt(target: string): Promise<CheckResult> {
	const t = timed();
	const resp = await doh(target, 'TXT');
	const ans = answersOf(resp, 'TXT');
	const rows: CheckRow[] = ans.map((a) => ({
		status: 'ok',
		name: a.name,
		value: stripTxt(a.data),
		info: `TTL ${a.TTL}`,
	}));
	return base('txt', 'TXT Records', target, rows, rows.length ? `${rows.length} TXT record(s)` : 'No TXT', t.done(), rows.length > 0);
}

export async function runSpf(target: string): Promise<CheckResult> {
	const t = timed();
	const resp = await doh(target, 'TXT');
	const spf = answersOf(resp, 'TXT').map((a) => stripTxt(a.data)).filter((v) => v.toLowerCase().startsWith('v=spf1'));
	const rows: CheckRow[] = spf.map((v) => {
		let status: Severity = 'ok';
		if (/\+all\b/i.test(v)) status = 'fail';
		else if (/~all\b/i.test(v)) status = 'warn';
		else if (/-all\b/i.test(v)) status = 'ok';
		else status = 'info';
		return { status, name: 'SPF', value: v };
	});
	if (spf.length > 1) {
		rows.push({ status: 'fail', name: 'Policy', value: 'Multiple SPF records (invalid)' });
	}
	if (!spf.length) rows.push({ status: 'fail', name: 'SPF', value: 'Not found' });
	return base('spf', 'SPF Record', target, rows, spf[0] ?? 'Missing SPF', t.done(), spf.length === 1);
}

export async function runDmarc(target: string): Promise<CheckResult> {
	const t = timed();
	const name = `_dmarc.${target.replace(/\.$/, '')}`;
	const resp = await doh(name, 'TXT');
	const records = answersOf(resp, 'TXT').map((a) => stripTxt(a.data)).filter((v) => /v=DMARC1/i.test(v));
	const rows: CheckRow[] = [];
	if (!records.length) {
		rows.push({ status: 'fail', name: 'DMARC', value: 'Not found' });
		return base('dmarc', 'DMARC Record', target, rows, 'Missing DMARC', t.done(), false);
	}
	const rec = records[0];
	rows.push({ status: 'ok', name: 'Record', value: rec });
	const policy = /;\s*p=([^;\s]+)/i.exec(rec)?.[1] ?? '?';
	const status: Severity = policy.toLowerCase() === 'none' ? 'warn' : policy.toLowerCase() === 'reject' ? 'ok' : 'info';
	rows.push({ status, name: 'Policy (p)', value: policy });
	const pct = /;\s*pct=([^;\s]+)/i.exec(rec)?.[1];
	if (pct) rows.push({ status: 'info', name: 'Percent', value: pct });
	const rua = /;\s*rua=([^;\s]+)/i.exec(rec)?.[1];
	if (rua) rows.push({ status: 'info', name: 'RUA', value: rua });
	return base('dmarc', 'DMARC Record', target, rows, `p=${policy}`, t.done());
}

export async function runDkim(target: string, selector = 'default'): Promise<CheckResult> {
	const t = timed();
	const name = `${selector}._domainkey.${target.replace(/\.$/, '')}`;
	const resp = await doh(name, 'TXT');
	const records = answersOf(resp, 'TXT').map((a) => stripTxt(a.data));
	const rows: CheckRow[] = records.length
		? records.map((v) => ({ status: 'ok' as Severity, name: `${selector}._domainkey`, value: v }))
		: [{ status: 'fail', name: selector, value: 'No DKIM key found' }];
	return base('dkim', 'DKIM Record', `${selector}:${target}`, rows, records.length ? 'Found' : 'Missing', t.done(), records.length > 0);
}

export async function runBimi(target: string): Promise<CheckResult> {
	const t = timed();
	const name = `default._bimi.${target.replace(/\.$/, '')}`;
	const resp = await doh(name, 'TXT');
	const records = answersOf(resp, 'TXT').map((a) => stripTxt(a.data)).filter((v) => /v=BIMI1/i.test(v));
	const rows: CheckRow[] = records.length
		? records.map((v) => ({ status: 'ok' as Severity, name: 'BIMI', value: v }))
		: [{ status: 'info', name: 'BIMI', value: 'Not found (optional)' }];
	return base('bimi', 'BIMI Record', target, rows, records[0] ?? 'No BIMI', t.done(), records.length > 0);
}

export async function runTlsrpt(target: string): Promise<CheckResult> {
	const t = timed();
	const name = `_smtp._tls.${target.replace(/\.$/, '')}`;
	const resp = await doh(name, 'TXT');
	const records = answersOf(resp, 'TXT').map((a) => stripTxt(a.data)).filter((v) => /v=TLSRPTv1/i.test(v));
	const rows: CheckRow[] = records.length
		? records.map((v) => ({ status: 'ok' as Severity, name: 'TLSRPT', value: v }))
		: [{ status: 'info', name: 'TLSRPT', value: 'Not found' }];
	return base('tlsrpt', 'TLSRPT Record', target, rows, records[0] ?? 'No TLSRPT', t.done(), records.length > 0);
}

export async function runMtaSts(target: string): Promise<CheckResult> {
	const t = timed();
	const domain = target.replace(/\.$/, '');
	const dnsName = `_mta-sts.${domain}`;
	const resp = await doh(dnsName, 'TXT');
	const records = answersOf(resp, 'TXT').map((a) => stripTxt(a.data)).filter((v) => /v=STSv1/i.test(v));
	const rows: CheckRow[] = [];
	if (!records.length) {
		rows.push({ status: 'info', name: 'DNS', value: 'No MTA-STS TXT' });
	} else {
		rows.push({ status: 'ok', name: 'DNS', value: records[0] });
	}
	try {
		const policyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
		const res = await fetch(policyUrl, { redirect: 'follow' });
		const text = await res.text();
		rows.push({
			status: res.ok ? 'ok' : 'warn',
			name: 'Policy URL',
			value: policyUrl,
			info: `HTTP ${res.status}`,
		});
		if (res.ok) {
			for (const line of text.split(/\r?\n/).filter(Boolean).slice(0, 12)) {
				rows.push({ status: 'info', name: 'Policy', value: line });
			}
		}
	} catch (e) {
		rows.push({ status: 'warn', name: 'Policy fetch', value: e instanceof Error ? e.message : String(e) });
	}
	return base('mta-sts', 'MTA-STS', target, rows, records[0] ?? 'No MTA-STS', t.done(), records.length > 0);
}

export async function runBlacklist(target: string, opts: LookupOptions = {}): Promise<CheckResult> {
	const t = timed();
	const ips = await resolveHostToIps(target);
	if (!ips.length) {
		return base('blacklist', 'Blacklist Check', target, [{ status: 'error', name: 'Resolve', value: 'No IPs' }], 'Cannot resolve', t.done(), false);
	}

	const lists = DNSBLS.map((bl) => (bl.zone.includes('spamhaus') ? { ...bl, ...spamhausZone(opts.spamhausDqsKey) } : bl));

	const rows: CheckRow[] = [];
	let listed = 0;
	let queryErrors = 0;
	// Prefer IPv4 for classic DNSBLs
	const checkIps = ips.filter((ip) => !ip.includes(':')).length ? ips.filter((ip) => !ip.includes(':')) : ips;

	for (const ip of checkIps.slice(0, 3)) {
		const rev = reverseIp(ip);
		if (!rev) continue;
		const chunkSize = 8;
		for (let i = 0; i < lists.length; i += chunkSize) {
			const chunk = lists.slice(i, i + chunkSize);
			const results = await Promise.all(
				chunk.map(async (bl) => {
					const q = `${rev}.${bl.zone}`;
					try {
						const resp = await doh(q, 'A');
						return { bl, ip, answers: answersOf(resp, 'A').map((a) => a.data) };
					} catch {
						return { bl, ip, answers: [] as string[] };
					}
				}),
			);
			for (const r of results) {
				const isWl = r.bl.zone.includes('dnswl');
				const interp = interpretDnsblCodes(r.bl.zone, r.answers, isWl);
				if (interp.kind === 'listed') listed++;
				if (interp.kind === 'query_error') queryErrors++;
				rows.push({
					status: interp.status,
					name: `${r.bl.name} (${ip})`,
					value: interp.label,
					info: interp.detail + (r.bl.url ? ` ${r.bl.url}` : ''),
				});
			}
		}
	}

	const summary = listed
		? `Listed on ${listed} list(s)`
		: queryErrors
			? `No listings; ${queryErrors} list(s) returned query errors (e.g. Spamhaus anonymous/open-resolver)`
			: `Clean on ${lists.length} lists`;
	return {
		...base('blacklist', 'Blacklist Check', target, rows, summary, t.done(), listed === 0),
		meta: {
			listed,
			queryErrors,
			spamhausDqs: Boolean(opts.spamhausDqsKey?.trim()),
		},
	};
}

export async function runDnsHealth(target: string): Promise<CheckResult> {
	const t = timed();
	const ns = answersOf(await doh(target, 'NS'), 'NS').map((a) => a.data.replace(/\.$/, ''));
	const rows: CheckRow[] = [];
	if (ns.length < 2) rows.push({ status: 'warn', name: 'NS count', value: String(ns.length), info: 'Prefer ≥ 2 nameservers' });
	else rows.push({ status: 'ok', name: 'NS count', value: String(ns.length) });

	for (const server of ns) {
		const ips = await resolveHostToIps(server);
		rows.push({
			status: ips.length ? 'ok' : 'fail',
			name: server,
			value: ips.join(', ') || 'unresolved',
		});
	}
	const soa = answersOf(await doh(target, 'SOA'), 'SOA');
	if (soa.length) rows.push({ status: 'ok', name: 'SOA', value: soa[0].data.split(/\s+/)[2] ?? soa[0].data });
	return base('dns', 'DNS Health', target, rows, `${ns.length} NS`, t.done(), ns.length >= 2);
}

async function rdapFetch(url: string): Promise<unknown> {
	const res = await fetch(url, { headers: { Accept: 'application/rdap+json, application/json' } });
	if (!res.ok) throw new Error(`RDAP ${res.status}`);
	return res.json();
}

export async function runWhois(target: string): Promise<CheckResult> {
	const t = timed();
	const domain = target.replace(/\.$/, '').toLowerCase();
	try {
		const bootstrap = (await rdapFetch('https://rdap.org/domain/' + encodeURIComponent(domain))) as Record<string, unknown>;
		const rows: CheckRow[] = [];
		if (typeof bootstrap.ldhName === 'string') rows.push({ status: 'ok', name: 'Domain', value: bootstrap.ldhName });
		if (typeof bootstrap.handle === 'string') rows.push({ status: 'info', name: 'Handle', value: bootstrap.handle });
		const status = bootstrap.status;
		if (Array.isArray(status)) rows.push({ status: 'info', name: 'Status', value: status.join(', ') });
		const events = bootstrap.events as Array<{ eventAction?: string; eventDate?: string }> | undefined;
		for (const ev of events ?? []) {
			if (ev.eventAction && ev.eventDate) {
				rows.push({ status: 'info', name: ev.eventAction, value: ev.eventDate });
			}
		}
		const entities = bootstrap.entities as Array<{ roles?: string[]; vcardArray?: unknown[] }> | undefined;
		for (const ent of entities ?? []) {
			const role = (ent.roles ?? []).join(', ') || 'entity';
			const fn = extractVcardFn(ent.vcardArray);
			if (fn) rows.push({ status: 'info', name: role, value: fn });
		}
		const nameservers = bootstrap.nameservers as Array<{ ldhName?: string }> | undefined;
		for (const ns of nameservers ?? []) {
			if (ns.ldhName) rows.push({ status: 'ok', name: 'NS', value: ns.ldhName });
		}
		return base('whois', 'Domain RDAP', target, rows, rows[0]?.value ?? domain, t.done(), rows.length > 0);
	} catch (e) {
		return base('whois', 'Domain RDAP', target, [{ status: 'error', name: 'RDAP', value: e instanceof Error ? e.message : String(e) }], 'Failed', t.done(), false);
	}
}

function extractVcardFn(vcardArray: unknown[] | undefined): string | null {
	if (!Array.isArray(vcardArray) || vcardArray.length < 2) return null;
	const props = vcardArray[1];
	if (!Array.isArray(props)) return null;
	for (const p of props) {
		if (Array.isArray(p) && p[0] === 'fn') return String(p[3]);
	}
	return null;
}

export async function runArin(target: string): Promise<CheckResult> {
	const t = timed();
	const ip = isIp(target) ? target : (await resolveHostToIps(target))[0];
	if (!ip) return base('arin', 'IP RDAP', target, [{ status: 'error', name: 'IP', value: 'Unresolved' }], 'Failed', t.done(), false);
	try {
		const data = (await rdapFetch('https://rdap.org/ip/' + encodeURIComponent(ip))) as Record<string, unknown>;
		const rows: CheckRow[] = [];
		if (typeof data.name === 'string') rows.push({ status: 'ok', name: 'Name', value: data.name });
		if (typeof data.handle === 'string') rows.push({ status: 'info', name: 'Handle', value: data.handle });
		if (typeof data.startAddress === 'string') rows.push({ status: 'info', name: 'Start', value: data.startAddress });
		if (typeof data.endAddress === 'string') rows.push({ status: 'info', name: 'End', value: data.endAddress });
		if (typeof data.ipVersion === 'string' || typeof data.ipVersion === 'number') {
			rows.push({ status: 'info', name: 'Version', value: String(data.ipVersion) });
		}
		const country = data.country;
		if (typeof country === 'string') rows.push({ status: 'info', name: 'Country', value: country });
		return base('arin', 'IP RDAP', target, rows, String(data.name ?? ip), t.done(), rows.length > 0);
	} catch (e) {
		return base('arin', 'IP RDAP', target, [{ status: 'error', name: 'RDAP', value: e instanceof Error ? e.message : String(e) }], 'Failed', t.done(), false);
	}
}

export async function runAsn(target: string): Promise<CheckResult> {
	const t = timed();
	const ip = isIp(target) ? target : (await resolveHostToIps(target))[0];
	if (!ip) return base('asn', 'ASN Lookup', target, [{ status: 'error', name: 'IP', value: 'Unresolved' }], 'Failed', t.done(), false);
	try {
		// Team Cymru DNS: dig +origin.asn.cymru.com TXT
		const rev = reverseIp(ip);
		if (!rev || ip.includes(':')) {
			// Fall back to RDAP remarks
			const arin = await runArin(ip);
			return { ...arin, tool: 'asn', title: 'ASN Lookup', elapsedMs: t.done() };
		}
		const resp = await doh(`${rev}.origin.asn.cymru.com`, 'TXT');
		const txts = answersOf(resp, 'TXT').map((a) => stripTxt(a.data));
		const rows: CheckRow[] = txts.map((v) => {
			const [asn, prefix, cc, registry, allocated] = v.split('|').map((s) => s.trim());
			return {
				status: 'ok' as Severity,
				name: `AS${asn}`,
				value: `${prefix} ${cc} ${registry}`,
				info: allocated ? `allocated ${allocated}` : undefined,
			};
		});
		if (!rows.length) rows.push({ status: 'warn', name: 'ASN', value: 'No Cymru data' });
		return base('asn', 'ASN Lookup', target, rows, rows[0]?.name ?? 'Unknown', t.done(), rows.length > 0 && rows[0].status === 'ok');
	} catch (e) {
		return base('asn', 'ASN Lookup', target, [{ status: 'error', name: 'Lookup', value: e instanceof Error ? e.message : String(e) }], 'Failed', t.done(), false);
	}
}

export async function runHttp(target: string, secure: boolean): Promise<CheckResult> {
	const t = timed();
	const tool = secure ? 'https' : 'http';
	let url = target;
	if (!/^https?:\/\//i.test(url)) url = `${secure ? 'https' : 'http'}://${url}`;
	try {
		const started = Date.now();
		const res = await fetch(url, { redirect: 'manual', headers: { 'User-Agent': 'mx-tools/1.0' } });
		const ms = Date.now() - started;
		const rows: CheckRow[] = [
			{ status: res.ok || (res.status >= 300 && res.status < 400) ? 'ok' : 'warn', name: 'Status', value: String(res.status) },
			{ status: 'info', name: 'URL', value: url },
			{ status: 'info', name: 'Time', value: `${ms} ms` },
		];
		const loc = res.headers.get('location');
		if (loc) rows.push({ status: 'info', name: 'Location', value: loc });
		const server = res.headers.get('server');
		if (server) rows.push({ status: 'info', name: 'Server', value: server });
		return base(tool, tool.toUpperCase(), target, rows, `HTTP ${res.status}`, t.done());
	} catch (e) {
		return base(tool, tool.toUpperCase(), target, [{ status: 'fail', name: 'Error', value: e instanceof Error ? e.message : String(e) }], 'Failed', t.done(), false);
	}
}

export async function runTcp(host: string, portStr = '443'): Promise<CheckResult> {
	const t = timed();
	const port = Number(portStr);
	if (!port || port < 1 || port > 65535) {
		return base('tcp', 'TCP Check', `${host}:${portStr}`, [{ status: 'error', name: 'Port', value: 'Invalid' }], 'Bad port', t.done(), false);
	}
	if (port === 25) {
		return base(
			'tcp',
			'TCP Check',
			`${host}:${port}`,
			[{ status: 'unsupported', name: 'Port 25', value: 'Blocked on Cloudflare Workers — use the CLI' }],
			'Unsupported on Worker',
			t.done(),
			false,
		);
	}
	try {
		// cloudflare:sockets
		const { connect } = await import('cloudflare:sockets');
		const socket = connect({ hostname: host, port });
		const reader = socket.readable.getReader();
		const timeout = new Promise<never>((_, reject) => setTimeout(() => reject(new Error('timeout')), 5000));
		await Promise.race([socket.opened, timeout]);
		try {
			reader.releaseLock();
		} catch {
			/* ignore */
		}
		await socket.close();
		return base('tcp', 'TCP Check', `${host}:${port}`, [{ status: 'ok', name: 'Connect', value: `Open ${host}:${port}` }], 'Open', t.done());
	} catch (e) {
		return base('tcp', 'TCP Check', `${host}:${port}`, [{ status: 'fail', name: 'Connect', value: e instanceof Error ? e.message : String(e) }], 'Closed/failed', t.done(), false);
	}
}

export async function runSmtp(_target: string): Promise<CheckResult> {
	return {
		tool: 'smtp',
		title: 'SMTP Test',
		query: _target,
		ok: false,
		summary: 'Port 25 blocked on Cloudflare Workers — use the CLI (`mx smtp:host`)',
		rows: [{ status: 'unsupported', name: 'SMTP', value: 'Use CLI for port 25 banner checks' }],
		elapsedMs: 0,
	};
}

export async function runPing(target: string): Promise<CheckResult> {
	return {
		tool: 'ping',
		title: 'Ping',
		query: target,
		ok: false,
		summary: 'ICMP not available on Workers — use the CLI',
		rows: [{ status: 'unsupported', name: 'ICMP', value: 'Use CLI: mx ping:' + target }],
		elapsedMs: 0,
	};
}

export async function runTrace(target: string): Promise<CheckResult> {
	return {
		tool: 'trace',
		title: 'Traceroute',
		query: target,
		ok: false,
		summary: 'ICMP not available on Workers — use the CLI',
		rows: [{ status: 'unsupported', name: 'ICMP', value: 'Use CLI: mx trace:' + target }],
		elapsedMs: 0,
	};
}

type NamedJob = { name: string; run: () => Promise<CheckResult> };

function autoJobs(target: string, opts: LookupOptions = {}): NamedJob[] {
	return [
		{ name: 'mx', run: () => runMx(target) },
		{ name: 'spf', run: () => runSpf(target) },
		{ name: 'dmarc', run: () => runDmarc(target) },
		{ name: 'blacklist', run: () => runBlacklist(target, opts) },
		{ name: 'soa', run: () => runSoa(target) },
	];
}

function fullJobs(target: string, opts: LookupOptions = {}): NamedJob[] {
	return [
		...autoJobs(target, opts),
		{ name: 'dkim', run: () => runDkim(target, 'default') },
		{ name: 'txt', run: () => runTxt(target) },
		{ name: 'ns', run: () => runNs(target) },
		{ name: 'bimi', run: () => runBimi(target) },
		{ name: 'mta-sts', run: () => runMtaSts(target) },
		{ name: 'tlsrpt', run: () => runTlsrpt(target) },
		{ name: 'dns', run: () => runDnsHealth(target) },
		{ name: 'https', run: () => runHttp(target, true) },
		{ name: 'whois', run: () => runWhois(target) },
		{ name: 'asn', run: () => runAsn(target) },
		{ name: 'arin', run: () => runArin(target) },
	];
}

export function plannedChecks(tool: string, target: string): string[] {
	if (tool === 'auto') return autoJobs(target).map((j) => j.name);
	if (tool === 'full') return fullJobs(target).map((j) => j.name);
	return [tool];
}

async function* streamPool(jobs: NamedJob[], concurrency = 4): AsyncGenerator<CheckResult> {
	const slots = new Map<number, Promise<{ id: number; result: CheckResult }>>();
	let next = 0;
	let finished = 0;

	const launch = () => {
		if (next >= jobs.length) return;
		const id = next;
		const job = jobs[next++];
		slots.set(
			id,
			job.run().then((result) => ({ id, result })),
		);
	};

	while (slots.size < concurrency && next < jobs.length) launch();

	while (finished < jobs.length) {
		const { id, result } = await Promise.race(slots.values());
		slots.delete(id);
		finished += 1;
		yield result;
		launch();
	}
}

export async function runAutoFast(target: string, opts: LookupOptions = {}): Promise<CheckResult[]> {
	const out: CheckResult[] = [];
	for await (const r of streamPool(autoJobs(target, opts))) out.push(r);
	return out;
}

export async function runFull(target: string, opts: LookupOptions = {}): Promise<CheckResult[]> {
	const out: CheckResult[] = [];
	for await (const r of streamPool(fullJobs(target, opts), 4)) out.push(r);
	return out;
}

export async function* streamOne(q: ParsedQuery, opts: LookupOptions = {}): AsyncGenerator<CheckResult> {
	if (q.tool === 'auto') {
		yield* streamPool(autoJobs(q.target, opts));
		return;
	}
	if (q.tool === 'full') {
		yield* streamPool(fullJobs(q.target, opts), 4);
		return;
	}
	for (const r of await runOne(q, opts)) yield r;
}

export async function runOne(q: ParsedQuery, opts: LookupOptions = {}): Promise<CheckResult[]> {
	const { tool, target, extra } = q;
	switch (tool) {
		case 'auto':
			return runAutoFast(target, opts);
		case 'full':
			return runFull(target, opts);
		case 'a':
			return [await runA(target)];
		case 'aaaa':
			return [await runAaaa(target)];
		case 'cname':
			return [await runCname(target)];
		case 'mx':
			return [await runMx(target)];
		case 'ns':
			return [await runNs(target)];
		case 'ptr':
			return [await runPtr(target)];
		case 'soa':
			return [await runSoa(target)];
		case 'txt':
			return [await runTxt(target)];
		case 'spf':
			return [await runSpf(target)];
		case 'dmarc':
			return [await runDmarc(target)];
		case 'dkim':
			return [await runDkim(target, extra ?? 'default')];
		case 'bimi':
			return [await runBimi(target)];
		case 'mta-sts':
			return [await runMtaSts(target)];
		case 'tlsrpt':
			return [await runTlsrpt(target)];
		case 'blacklist':
			return [await runBlacklist(target, opts)];
		case 'dns':
			return [await runDnsHealth(target)];
		case 'whois':
			return [await runWhois(target)];
		case 'arin':
			return [await runArin(target)];
		case 'asn':
			return [await runAsn(target)];
		case 'http':
			return [await runHttp(target, false)];
		case 'https':
			return [await runHttp(target, true)];
		case 'tcp':
			return [await runTcp(target, extra ?? '443')];
		case 'smtp':
			return [await runSmtp(target)];
		case 'ping':
			return [await runPing(target)];
		case 'trace':
			return [await runTrace(target)];
		default:
			return [
				{
					tool,
					title: 'Unknown',
					query: target,
					ok: false,
					summary: `Unknown tool: ${tool}`,
					rows: [],
					elapsedMs: 0,
				},
			];
	}
}
