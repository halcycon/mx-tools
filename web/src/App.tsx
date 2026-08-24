import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';

export type Severity = 'ok' | 'info' | 'warn' | 'fail' | 'error' | 'unsupported';

export type CheckRow = {
	status: Severity;
	name: string;
	value: string;
	info?: string;
};

export type CheckResult = {
	tool: string;
	title: string;
	query: string;
	ok: boolean;
	summary: string;
	rows: CheckRow[];
	related?: Array<{ tool: string; label: string; query: string }>;
	elapsedMs: number;
};

type ToolDef = {
	id: string;
	label: string;
	description: string;
	example: string;
};

const EXAMPLES = ['example.com', 'mx:gmail.com', 'spf:github.com', 'blacklist:1.1.1.1', 'dmarc:cloudflare.com'];

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
	const [activeQuery, setActiveQuery] = useState('');

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
		localStorage.setItem('mx-tools-history', JSON.stringify(history.slice(0, 30)));
	}, [history]);

	const toolOptions = useMemo(() => {
		const list = tools.length
			? tools
			: [{ id: 'auto', label: 'Domain health', description: '', example: '' }];
		return list.filter((t) => t.id !== 'ping' && t.id !== 'trace');
	}, [tools]);

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
		async (raw?: string) => {
			const q = buildQuery(raw);
			if (!q) return;
			setLoading(true);
			setError(null);
			setResults([]);
			setActiveQuery(q);
			setHistory((h) => [q, ...h.filter((x) => x !== q)].slice(0, 30));

			try {
				const res = await fetch(`/api/lookup?stream=1&q=${encodeURIComponent(q)}`, {
					headers: { Accept: 'text/event-stream' },
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
						const parsed = JSON.parse(data);
						if (event === 'result') setResults((r) => [...r, parsed as CheckResult]);
						if (event === 'error') setError(parsed.message ?? 'Lookup failed');
					}
				}
			} catch (e) {
				setError(e instanceof Error ? e.message : String(e));
			} finally {
				setLoading(false);
			}
		},
		[buildQuery],
	);

	const onSubmit = (e: FormEvent) => {
		e.preventDefault();
		void run();
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
			</div>
			<p className="tagline">
				Private SuperTool for DNS, mail auth, blacklists, and network lookups — same checks in the web UI and
				CLI.
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
					{!error && results.length === 0 && !loading && (
						<p className="empty">Enter a domain or try <code>mx:example.com</code></p>
					)}
					{loading && results.length === 0 && <p className="empty">Running checks…</p>}
					{results.map((r, i) => (
						<ResultCard key={`${r.tool}-${i}`} result={r} onRelated={(q) => void run(q)} />
					))}
				</section>
			</div>

			<p className="footer">
				CLI: <code>mx example.com</code> · <code>mx blacklist:1.2.3.4</code> · SMTP/ping/traceroute work best in
				the TUI (Workers block ICMP and port 25).
			</p>
		</div>
	);
}
