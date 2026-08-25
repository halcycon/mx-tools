import { useEffect, useState } from 'react';

const STORAGE = 'mx-tools-keys';

export type ClientKeys = {
	spamhausDqs: string;
	agentUrl: string;
	agentToken: string;
};

export function loadKeys(): ClientKeys {
	try {
		const raw = localStorage.getItem(STORAGE);
		if (!raw) return { spamhausDqs: '', agentUrl: '', agentToken: '' };
		const parsed = JSON.parse(raw) as Partial<ClientKeys>;
		return {
			spamhausDqs: parsed.spamhausDqs ?? '',
			agentUrl: parsed.agentUrl ?? '',
			agentToken: parsed.agentToken ?? '',
		};
	} catch {
		return { spamhausDqs: '', agentUrl: '', agentToken: '' };
	}
}

export function saveKeys(keys: ClientKeys) {
	localStorage.setItem(STORAGE, JSON.stringify(keys));
}

/** Normalize agent base URL (no trailing slash). Empty = use Worker `/api`. */
export function agentBase(keys = loadKeys()): string {
	return keys.agentUrl.trim().replace(/\/$/, '');
}

export function agentHeaders(keys = loadKeys()): Record<string, string> {
	const h: Record<string, string> = {};
	const token = keys.agentToken.trim();
	if (token) {
		h.Authorization = `Bearer ${token}`;
		h['x-agent-token'] = token;
	}
	const dqs = keys.spamhausDqs.trim();
	if (dqs) h['x-spamhaus-dqs-key'] = dqs;
	return h;
}

export async function probeAgent(
	url: string,
	token: string,
): Promise<{ ok: boolean; message: string; agent?: boolean; spamhausDqsConfigured?: boolean }> {
	const base = url.trim().replace(/\/$/, '');
	if (!base) return { ok: false, message: 'Enter an agent URL' };
	try {
		const health = await fetch(`${base}/api/health`, { method: 'GET' });
		if (!health.ok) return { ok: false, message: `Health HTTP ${health.status}` };
		const cfgRes = await fetch(`${base}/api/config`, {
			headers: token.trim()
				? { Authorization: `Bearer ${token.trim()}`, 'x-agent-token': token.trim() }
				: {},
		});
		if (cfgRes.status === 401) return { ok: false, message: 'Unauthorized — check token' };
		if (!cfgRes.ok) return { ok: false, message: `Config HTTP ${cfgRes.status}` };
		const cfg = (await cfgRes.json()) as { agent?: boolean; spamhausDqsConfigured?: boolean };
		return {
			ok: true,
			message: cfg.agent ? 'Connected to local agent' : 'Reachable (not an mx agent?)',
			agent: Boolean(cfg.agent),
			spamhausDqsConfigured: Boolean(cfg.spamhausDqsConfigured),
		};
	} catch (e) {
		return {
			ok: false,
			message: e instanceof Error ? e.message : String(e),
		};
	}
}

export default function Settings({
	open,
	onClose,
	serverHasDqs,
	onSaved,
}: {
	open: boolean;
	onClose: () => void;
	serverHasDqs: boolean;
	onSaved?: () => void;
}) {
	const [spamhausDqs, setSpamhausDqs] = useState('');
	const [agentUrl, setAgentUrl] = useState('');
	const [agentToken, setAgentToken] = useState('');
	const [probeMsg, setProbeMsg] = useState<string | null>(null);
	const [probing, setProbing] = useState(false);

	useEffect(() => {
		if (open) {
			const k = loadKeys();
			setSpamhausDqs(k.spamhausDqs);
			setAgentUrl(k.agentUrl);
			setAgentToken(k.agentToken);
			setProbeMsg(null);
		}
	}, [open]);

	if (!open) return null;

	const persist = (next: ClientKeys) => {
		saveKeys(next);
		onSaved?.();
	};

	return (
		<div className="modal-backdrop" onClick={onClose} role="presentation">
			<div
				className="modal settings-modal"
				role="dialog"
				aria-labelledby="settings-title"
				onClick={(e) => e.stopPropagation()}
			>
				<h2 id="settings-title">Settings</h2>

				<section className="settings-block">
					<h3>Probe agent</h3>
					<p>
						Run <code>mx agent</code> on this machine (or a mail host). Lookups then use local DNS/SMTP —
						Spamhaus open-resolver blocks usually go away. Token stays in this browser; DQS keys stay on the
						agent via <code>SPAMHAUS_DQS_KEY</code>.
					</p>
					<label>
						Agent URL
						<input
							type="url"
							autoComplete="off"
							spellCheck={false}
							value={agentUrl}
							onChange={(e) => setAgentUrl(e.target.value)}
							placeholder="http://127.0.0.1:8788"
						/>
					</label>
					<label>
						Agent token
						<input
							type="password"
							autoComplete="off"
							spellCheck={false}
							value={agentToken}
							onChange={(e) => setAgentToken(e.target.value)}
							placeholder="Bearer token from mx agent"
						/>
					</label>
					<p className="hint">
						Default bind is loopback only. From an <code>https://</code> hosted UI, browsers may block{' '}
						<code>http://127.0.0.1</code> (mixed content) — use local <code>npm run start</code>, or SSH{' '}
						<code>-L 8788:127.0.0.1:8788</code>.
					</p>
					<div className="modal-actions" style={{ marginTop: '0.5rem' }}>
						<button
							type="button"
							className="ghost"
							disabled={probing || !agentUrl.trim()}
							onClick={() => {
								setProbing(true);
								void probeAgent(agentUrl, agentToken).then((r) => {
									setProbeMsg(r.ok ? `✓ ${r.message}` : `✗ ${r.message}`);
									setProbing(false);
								});
							}}
						>
							{probing ? 'Testing…' : 'Test connection'}
						</button>
					</div>
					{probeMsg ? <p className="hint">{probeMsg}</p> : null}
				</section>

				<section className="settings-block">
					<h3>Spamhaus DQS (optional)</h3>
					<p>
						Only needed for the <em>Worker</em> path, or as an override header. Prefer setting{' '}
						<code>SPAMHAUS_DQS_KEY</code> on the agent process instead of pasting here.
					</p>
					<label>
						DQS key (this browser → Worker)
						<input
							type="password"
							autoComplete="off"
							spellCheck={false}
							value={spamhausDqs}
							onChange={(e) => setSpamhausDqs(e.target.value)}
							placeholder={serverHasDqs ? 'Optional override — Worker already has a secret' : 'For private Worker deploys'}
						/>
					</label>
					<p className="hint">
						Worker secret: {serverHasDqs ? 'configured' : 'not set'}.
					</p>
				</section>

				<div className="modal-actions">
					<button
						type="button"
						className="ghost"
						onClick={() => {
							setSpamhausDqs('');
							setAgentUrl('');
							setAgentToken('');
							persist({ spamhausDqs: '', agentUrl: '', agentToken: '' });
							onClose();
						}}
					>
						Clear all
					</button>
					<button
						type="button"
						onClick={() => {
							persist({
								spamhausDqs: spamhausDqs.trim(),
								agentUrl: agentUrl.trim().replace(/\/$/, ''),
								agentToken: agentToken.trim(),
							});
							onClose();
						}}
					>
						Save
					</button>
				</div>
			</div>
		</div>
	);
}
