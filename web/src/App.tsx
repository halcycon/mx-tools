import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import HealthReport from './HealthReport';
import Settings, { loadKeys } from './Settings';
import type { CheckResult } from './types';

type ToolDef = {
	id: string;
	label: string;
	description: string;
	example: string;
};

const EXAMPLES = ['example.com', 'full:github.com', 'spf:github.com', 'blacklist:1.1.1.1', 'dmarc:cloudflare.com'];

function ResultCard({
	result,
	onRelated,
}: {
	result: CheckResult;
	onRelated: (q: string) => void;
}) {
	return (
		<article className="card">
			<div className="card-head">
				<h3>{result.title}</h3>
				<span className="meta">
					{result.query} · {result.elapsedMs}ms
				</span>
			</div>
			<div className="summary">{result.summary}</div>
			{result.rows.length > 0 && (
				<table>
					<thead>
						<tr>
							<th>Status</th>
							<th>Name</th>
							<th>Value</th>
						</tr>
					</thead>
					<tbody>
						{result.rows.map((row, i) => (
							<tr key={`${row.name}-${i}`}>
								<td>
									<span className={`badge ${row.status}`}>{row.status}</span>
								</td>
								<td>{row.name}</td>
								<td className="value">
									{row.value}
									{row.info ? <div style={{ color: 'var(--muted)', marginTop: 4 }}>{row.info}</div> : null}
								</td>
							</tr>
						))}
					</tbody>
				</table>
			)}
			{result.related && result.related.length > 0 && (
				<div className="related">
					{result.related.slice(0, 8).map((r) => (
						<button key={r.query + r.label} type="button" onClick={() => onRelated(r.query)}>
							{r.label}
						</button>
					))}
				</div>
			)}
		</article>
	);
}

export default function App() {
	const [tools, setTools] = useState<ToolDef[]>([]);
	const [tool, setTool] = useState('auto');
	const [target, setTarget] = useState('');
	const [loading, setLoading] = useState(false);
	const [results, setResults] = useState<CheckResult[]>([]);
	const [error, setError] = useState<string | null>(null);
	const [history, setHistory] = useState<string[]>(() => {
		try {
			return JSON.parse(localStorage.getItem('mx-tools-history') || '[]');
		} catch {
			return [];
		}
	});
	const [expected, setExpected] = useState(0);
	const [report, setReport] = useState(false);
	const [activeQuery, setActiveQuery] = useState('');
	const [settingsOpen, setSettingsOpen] = useState(false);
	const [serverHasDqs, setServerHasDqs] = useState(false);
	const [detail, setDetail] = useState<{ query: string; results: CheckResult[]; loading: boolean } | null>(null);
	const [reportSnap, setReportSnap] = useState<{
		query: string;
		results: CheckResult[];
		expected: number;
	} | null>(null);

	useEffect(() => {
		void (async () => {
			try {
				const r = await fetch('/api/tools');
				const d = (await r.json()) as { tools?: ToolDef[] };
				setTools(d.tools ?? []);
			} catch {
				setTools([]);
			}
		})();
	}, []);

	useEffect(() => {
		void (async () => {
			try {
				const r = await fetch('/api/config');
				const d = (await r.json()) as { spamhausDqsConfigured?: boolean };
				setServerHasDqs(Boolean(d.spamhausDqsConfigured));
			} catch {
				setServerHasDqs(false);
			}
		})();
	}, []);

	useEffect(() => {
		localStorage.setItem('mx-tools-history', JSON.stringify(history.slice(0, 30)));
	}, [history]);

	const toolOptions = useMemo(() => {
		const list = tools.length
			? tools
			: [{ id: 'auto', label: 'Domain health', description: '', example: '' }];
		return list.filter((t) => t.id !== 'ping' && t.id !== 'trace');
	}, [tools]);

	const consumeStream = useCallback(async (q: string, onEvent: (event: string, parsed: Record<string, unknown>) => void) => {
		const key = loadKeys().spamhausDqs.trim();
		const res = await fetch(`/api/lookup?stream=1&q=${encodeURIComponent(q)}`, {
			headers: {
				Accept: 'text/event-stream',
				...(key ? { 'x-spamhaus-dqs-key': key } : {}),
			},
		});
		if (!res.ok || !res.body) {
			const text = await res.text();
			throw new Error(text || `HTTP ${res.status}`);
		}
		const reader = res.body.getReader();
		const dec = new TextDecoder();
		let buf = '';
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			buf += dec.decode(value, { stream: true });
			const chunks = buf.split('\n\n');
			buf = chunks.pop() ?? '';
			for (const chunk of chunks) {
				const lines = chunk.split('\n');
				let event = 'message';
				let data = '';
				for (const line of lines) {
					if (line.startsWith('event:')) event = line.slice(6).trim();
					if (line.startsWith('data:')) data += line.slice(5).trim();
				}
				if (!data) continue;
				onEvent(event, JSON.parse(data) as Record<string, unknown>);
			}
		}
	}, []);

	const buildQuery = useCallback(
		(override?: string) => {
			if (override) return override;
			const t = target.trim();
			if (!t) return '';
			if (tool === 'auto') return t;
			return `${tool}:${t}`;
		},
		[target, tool],
	);

	const run = useCallback(
		async (raw?: string, mode: 'main' | 'detail' = 'main') => {
			const q = buildQuery(raw);
			if (!q) return;

			if (mode === 'detail') {
				setDetail({ query: q, results: [], loading: true });
				try {
					await consumeStream(q, (event, parsed) => {
						if (event === 'result') {
							setDetail((d) =>
								d ? { ...d, results: [...d.results, parsed as unknown as CheckResult] } : d,
							);
						}
						if (event === 'error') setError(String(parsed.message ?? 'Lookup failed'));
					});
				} catch (e) {
					setError(e instanceof Error ? e.message : String(e));
				} finally {
					setDetail((d) => (d ? { ...d, loading: false } : d));
				}
				return;
			}

			setDetail(null);
			setReportSnap(null);
			setLoading(true);
			setError(null);
			setResults([]);
			const looksReport =
				tool === 'auto' ||
				tool === 'full' ||
				q.startsWith('full:') ||
				!q.includes(':');
			setReport(looksReport);
			setExpected(q.startsWith('full:') || tool === 'full' ? 16 : looksReport ? 5 : 1);
			setActiveQuery(q);
			setHistory((h) => [q, ...h.filter((x) => x !== q)].slice(0, 30));

			try {
				await consumeStream(q, (event, parsed) => {
					if (event === 'start') {
						const n = Number(parsed.expected) || 0;
						setExpected(n);
						setReport(parsed.tool === 'auto' || parsed.tool === 'full' || n > 1);
					}
					if (event === 'result') setResults((r) => [...r, parsed as unknown as CheckResult]);
					if (event === 'error') setError(String(parsed.message ?? 'Lookup failed'));
				});
			} catch (e) {
				setError(e instanceof Error ? e.message : String(e));
			} finally {
				setLoading(false);
			}
		},
		[buildQuery, consumeStream, tool],
	);

	const openDetail = useCallback(
		(q: string) => {
			setReportSnap({
				query: activeQuery,
				results,
				expected,
			});
			void run(q, 'detail');
		},
		[activeQuery, expected, results, run],
	);

	const onSubmit = (e: FormEvent) => {
		e.preventDefault();
		void run();
	};

	const runHealth = () => {
		const raw = target.trim();
		if (!raw) return;
		const host = raw.includes(':') ? raw.slice(raw.indexOf(':') + 1) : raw;
		setTool('full');
		setTarget(host);
		void run(`full:${host}`);
	};

	const applyExample = (ex: string) => {
		const colon = ex.indexOf(':');
		if (colon > 0) {
			setTool(ex.slice(0, colon));
			setTarget(ex.slice(colon + 1));
		} else {
			setTool('auto');
			setTarget(ex);
		}
		void run(ex);
	};

	return (
		<div className="app">
			<div className="brand">
				<h1>
					mx<span>-tools</span>
				</h1>
				<button type="button" className="settings-btn" onClick={() => setSettingsOpen(true)}>
					Settings
				</button>
			</div>
			<p className="tagline">
				D.A.R.T. (Domain Authentication & Reputation Toolkit) for DNS, mail auth, blacklists, and network
				lookups — same checks in the web UI and CLI.
			</p>

			<form className="search" onSubmit={onSubmit}>
				<select value={tool} onChange={(e) => setTool(e.target.value)} aria-label="Tool">
					{toolOptions.map((t) => (
						<option key={t.id} value={t.id}>
							{t.label}
						</option>
					))}
				</select>
				<input
					value={target}
					onChange={(e) => setTarget(e.target.value)}
					placeholder="domain, IP, or command:target"
					spellCheck={false}
					autoCapitalize="off"
					autoCorrect="off"
				/>
				<button type="submit" disabled={loading || !target.trim()}>
					{loading ? 'Running…' : 'Lookup'}
				</button>
				<button type="button" className="health-btn" disabled={loading || !target.trim()} onClick={runHealth}>
					Email health report
				</button>
			</form>

			<div className="hints">
				{EXAMPLES.map((ex) => (
					<button key={ex} type="button" onClick={() => applyExample(ex)}>
						{ex}
					</button>
				))}
			</div>

			<div className="layout">
				<aside className="panel history">
					<h2>History</h2>
					{history.length === 0 ? (
						<p className="empty" style={{ padding: '0.5rem' }}>
							No lookups yet
						</p>
					) : (
						<ul>
							{history.map((h) => (
								<li key={h}>
									<button
										type="button"
										className={h === activeQuery ? 'active' : ''}
										onClick={() => {
											const c = h.indexOf(':');
											if (c > 0 && c < 16) {
												setTool(h.slice(0, c));
												setTarget(h.slice(c + 1));
											} else {
												setTool('auto');
												setTarget(h);
											}
											void run(h);
										}}
									>
										{h}
									</button>
								</li>
							))}
						</ul>
					)}
				</aside>

				<section className="panel results">
					{error && <p className="empty" style={{ color: 'var(--fail)' }}>{error}</p>}
					{detail ? (
						<>
							<button
								type="button"
								className="back-btn"
								onClick={() => {
									if (reportSnap) {
										setActiveQuery(reportSnap.query);
										setResults(reportSnap.results);
										setExpected(reportSnap.expected);
										setReport(true);
									}
									setDetail(null);
									setError(null);
								}}
							>
								← Back to health report
							</button>
							<p className="detail-query">
								<code>{detail.query}</code>
								{detail.loading ? ' — running…' : null}
							</p>
							{detail.results.map((r, i) => (
								<ResultCard key={`${r.tool}-${i}`} result={r} onRelated={(q) => void run(q, 'detail')} />
							))}
						</>
					) : !error && results.length === 0 && !loading ? (
						<p className="empty">
							Enter a domain and run <strong>Email health report</strong>, or try <code>full:example.com</code>
						</p>
					) : (report || expected > 1) && (loading || results.length > 0) ? (
						<HealthReport
							query={activeQuery}
							target={activeQuery.includes(':') ? activeQuery.slice(activeQuery.indexOf(':') + 1) : activeQuery}
							results={results}
							expected={expected || results.length}
							loading={loading}
							onOpen={openDetail}
						/>
					) : (
						results.map((r, i) => <ResultCard key={`${r.tool}-${i}`} result={r} onRelated={(q) => void run(q)} />)
					)}
				</section>
			</div>

			<p className="footer">
				CLI: <code>mx example.com</code> · <code>mx blacklist:1.2.3.4</code> · SMTP/ping/traceroute work best in
				the TUI (Workers block ICMP and port 25).
			</p>
			<Settings open={settingsOpen} onClose={() => setSettingsOpen(false)} serverHasDqs={serverHasDqs} />
		</div>
	);
}
