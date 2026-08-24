import { useEffect, useMemo, useState } from 'react';
import type { CheckResult, Severity } from './types';

export type CategoryId = 'problems' | 'blacklist' | 'mail' | 'web' | 'dns';

const MAIL_TOOLS = new Set(['mx', 'smtp', 'spf', 'spf-flat', 'dmarc', 'dkim', 'bimi', 'mta-sts', 'tlsrpt']);
const WEB_TOOLS = new Set(['http', 'https', 'tcp']);
const DNS_TOOLS = new Set(['a', 'aaaa', 'cname', 'ns', 'ptr', 'soa', 'txt', 'dns', 'whois', 'arin', 'asn']);

export function categoryOf(tool: string): Exclude<CategoryId, 'problems'> {
	if (tool === 'blacklist') return 'blacklist';
	if (MAIL_TOOLS.has(tool)) return 'mail';
	if (WEB_TOOLS.has(tool)) return 'web';
	if (DNS_TOOLS.has(tool)) return 'dns';
	return 'dns';
}

export function rowTone(status: Severity): 'pass' | 'warn' | 'error' | 'skip' {
	if (status === 'fail' || status === 'error') return 'error';
	if (status === 'warn') return 'warn';
	if (status === 'unsupported') return 'skip';
	return 'pass';
}

export function resultTone(result: CheckResult): 'pass' | 'warn' | 'error' | 'skip' {
	const tones = result.rows.map((r) => rowTone(r.status));
	if (tones.includes('error')) return 'error';
	if (tones.includes('warn')) return 'warn';
	if (tones.length && tones.every((t) => t === 'skip')) return 'skip';
	return 'pass';
}

export type Problem = {
	id: string;
	tool: string;
	/** Shown in the category column (list name for DNSBLs). */
	label: string;
	category: Exclude<CategoryId, 'problems'>;
	host: string;
	result: string;
	tone: 'warn' | 'error';
	info?: string;
};

/** Blacklist rows are named `List name (1.2.3.4)`. */
export function parseBlacklistRowName(name: string): { list: string; ip: string } | null {
	const m = /^(.*) \(([^)]+)\)$/.exec(name);
	if (!m) return null;
	return { list: m[1], ip: m[2] };
}

export function problemsFrom(results: CheckResult[]): Problem[] {
	const out: Problem[] = [];
	for (const res of results) {
		for (const [i, row] of res.rows.entries()) {
			const tone = rowTone(row.status);
			if (tone !== 'error' && tone !== 'warn') continue;
			const bl = res.tool === 'blacklist' ? parseBlacklistRowName(row.name) : null;
			out.push({
				id: `${res.tool}-${i}-${row.name}`,
				tool: res.tool,
				label: bl?.list ?? res.tool,
				category: categoryOf(res.tool),
				host: bl?.ip ?? res.query,
				result: row.value || res.summary,
				tone,
				info: row.info || (bl ? undefined : row.name),
			});
		}
	}
	return out;
}

type Counts = { errors: number; warnings: number; passed: number };

function emptyCounts(): Counts {
	return { errors: 0, warnings: 0, passed: 0 };
}

function addTone(c: Counts, tone: 'pass' | 'warn' | 'error' | 'skip') {
	if (tone === 'error') c.errors += 1;
	else if (tone === 'warn') c.warnings += 1;
	else if (tone === 'pass') c.passed += 1;
}

export function tally(results: CheckResult[]) {
	const overall = emptyCounts();
	const byCat: Record<Exclude<CategoryId, 'problems'>, Counts> = {
		blacklist: emptyCounts(),
		mail: emptyCounts(),
		web: emptyCounts(),
		dns: emptyCounts(),
	};
	for (const res of results) {
		const cat = categoryOf(res.tool);
		if (res.tool === 'blacklist') {
			for (const row of res.rows) {
				const tone = rowTone(row.status);
				addTone(overall, tone);
				addTone(byCat.blacklist, tone);
			}
			continue;
		}
		const tone = resultTone(res);
		addTone(overall, tone);
		addTone(byCat[cat], tone);
	}
	return { overall, byCat };
}

function worst(c: Counts): 'error' | 'warn' | 'ok' | 'idle' {
	if (c.errors) return 'error';
	if (c.warnings) return 'warn';
	if (c.passed) return 'ok';
	return 'idle';
}

type Baseline = { savedAt: string; ids: string[] };

function baselineKey(target: string) {
	return `dart-baseline:${target.replace(/\.$/, '').toLowerCase()}`;
}

function loadBaseline(target: string): Baseline | null {
	if (!target || typeof localStorage === 'undefined') return null;
	try {
		const raw = localStorage.getItem(baselineKey(target));
		return raw ? (JSON.parse(raw) as Baseline) : null;
	} catch {
		return null;
	}
}

function problemIds(problems: Problem[]) {
	return [...new Set(problems.map((p) => p.id))].sort();
}

function Card({
	id,
	label,
	icon,
	counts,
	active,
	onSelect,
}: {
	id: CategoryId;
	label: string;
	icon: string;
	counts: Counts;
	active: boolean;
	onSelect: (id: CategoryId) => void;
}) {
	return (
		<button
			type="button"
			className={`cat-card cat-${worst(counts)}${active ? ' active' : ''}`}
			onClick={() => onSelect(id)}
			aria-pressed={active}
		>
			<div className="cat-card-title">
				<span aria-hidden="true">{icon}</span>
				{label}
			</div>
			<ul>
				<li className="error">
					<span>Errors</span>
					<strong>{counts.errors}</strong>
				</li>
				<li className="warn">
					<span>Warnings</span>
					<strong>{counts.warnings}</strong>
				</li>
				<li className="ok">
					<span>Passed</span>
					<strong>{counts.passed}</strong>
				</li>
			</ul>
		</button>
	);
}

export default function HealthReport({
	query,
	target,
	results,
	expected,
	loading,
	onOpen,
}: {
	query: string;
	target: string;
	results: CheckResult[];
	expected: number;
	loading: boolean;
	onOpen: (q: string) => void;
}) {
	const { byCat } = tally(results);
	const problems = problemsFrom(results);
	const checkTones = results.map(resultTone);
	const passed = checkTones.filter((t) => t === 'pass').length;
	const warnings = checkTones.filter((t) => t === 'warn').length;
	const errors = checkTones.filter((t) => t === 'error').length;
	const done = results.length;
	const remaining = Math.max(0, expected - done);
	const total = Math.max(expected, done, 1);
	const passPct = (passed / total) * 100;
	const warnPct = (warnings / total) * 100;
	const errPct = (errors / total) * 100;
	const restPct = Math.max(0, 100 - passPct - warnPct - errPct);

	const [tab, setTab] = useState<CategoryId>('problems');
	const [baseline, setBaseline] = useState<Baseline | null>(() => loadBaseline(target));

	useEffect(() => {
		setBaseline(loadBaseline(target));
	}, [target]);

	const ids = useMemo(() => problemIds(problems), [problems]);
	const diff = useMemo(() => {
		if (!baseline || loading) return null;
		const prev = new Set(baseline.ids);
		const cur = new Set(ids);
		const added = ids.filter((id) => !prev.has(id)).length;
		const resolved = baseline.ids.filter((id) => !cur.has(id)).length;
		return { added, resolved };
	}, [baseline, ids, loading]);

	const problemCounts: Counts = {
		errors: problems.filter((p) => p.tone === 'error').length,
		warnings: problems.filter((p) => p.tone === 'warn').length,
		passed,
	};

	const filtered =
		tab === 'problems'
			? problems
			: problems.filter((p) => p.category === tab);

	const title = query.startsWith('full:') ? 'Email health report' : 'Domain health report';
	const subtitle = query.startsWith('full:')
		? 'Deep suite: Domain health plus SPF flatten, DKIM, BIMI, MTA-STS, TLSRPT, DNS, HTTPS, RDAP'
		: 'Quick suite: MX, SPF, DMARC, blacklist, SOA';

	return (
		<div className="report">
			<div className="report-head">
				<div>
					<p className="report-kicker">D.A.R.T.</p>
					<h2>
						{title} <span>{target || query}</span>
					</h2>
					<p className="report-sub">{subtitle}</p>
				</div>
				<div className="report-status" aria-live="polite">
					{loading ? (
						<>
							{remaining} test{remaining === 1 ? '' : 's'} remaining
						</>
					) : (
						<>{done} tests complete</>
					)}
					{!loading && target ? (
						<div className="baseline">
							{diff ? (
								<span>
									vs saved: {diff.added} new, {diff.resolved} resolved
								</span>
							) : (
								<span>No saved snapshot for this host</span>
							)}
							<button
								type="button"
								className="more"
								onClick={() => {
									const next: Baseline = { savedAt: new Date().toISOString(), ids };
									localStorage.setItem(baselineKey(target), JSON.stringify(next));
									setBaseline(next);
								}}
							>
								Save baseline
							</button>
						</div>
					) : null}
				</div>
			</div>

			<div
				className={`progress${loading ? ' live' : ''}`}
				role="progressbar"
				aria-valuemin={0}
				aria-valuemax={total}
				aria-valuenow={done}
				aria-label="Health check progress"
			>
				<span className="seg ok" style={{ width: `${passPct}%` }} />
				<span className="seg warn" style={{ width: `${warnPct}%` }} />
				<span className="seg fail" style={{ width: `${errPct}%` }} />
				<span className="seg rest" style={{ width: `${restPct}%` }} />
			</div>
			<div className="progress-legend">
				<span className="ok">{passed} passed</span>
				<span className="warn">{warnings} warnings</span>
				<span className="fail">{errors} errors</span>
				{loading ? <span className="muted">{remaining} remaining</span> : null}
			</div>

			<div className="cat-row">
				<Card id="problems" label="Problems" icon="⚠" counts={problemCounts} active={tab === 'problems'} onSelect={setTab} />
				<Card id="blacklist" label="Blacklist" icon="⊘" counts={byCat.blacklist} active={tab === 'blacklist'} onSelect={setTab} />
				<Card id="mail" label="Mail server" icon="✉" counts={byCat.mail} active={tab === 'mail'} onSelect={setTab} />
				<Card id="web" label="Web server" icon="◎" counts={byCat.web} active={tab === 'web'} onSelect={setTab} />
				<Card id="dns" label="DNS" icon="⬡" counts={byCat.dns} active={tab === 'dns'} onSelect={setTab} />
			</div>

			<div className="problem-panel">
				<h3>
					{tab === 'problems' ? `${filtered.length} problem${filtered.length === 1 ? '' : 's'}` : `${tab} findings`}
				</h3>
				{filtered.length === 0 ? (
					<p className="empty">{loading ? 'Scanning… findings appear as tests finish.' : 'No issues in this category.'}</p>
				) : (
					<table className="problem-table">
						<thead>
							<tr>
								<th>Status</th>
								<th>List / check</th>
								<th>Host</th>
								<th>Result</th>
								<th></th>
							</tr>
						</thead>
						<tbody>
							{filtered.map((p) => (
								<tr key={p.id} className="problem-row">
									<td>
										<span className={`badge ${p.tone === 'error' ? 'fail' : 'warn'}`}>
											{p.tone === 'error' ? 'error' : 'warn'}
										</span>
									</td>
									<td>{p.label}</td>
									<td className="host">{p.host}</td>
									<td>
										{p.result}
										{p.info ? <div className="row-info">{p.info}</div> : null}
									</td>
									<td>
										<button type="button" className="more" onClick={() => onOpen(`${p.tool}:${p.host}`)}>
											More info
										</button>
									</td>
								</tr>
							))}
						</tbody>
					</table>
				)}
			</div>
		</div>
	);
}
