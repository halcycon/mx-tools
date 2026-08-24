import { useEffect, useState } from 'react';

const STORAGE = 'mx-tools-keys';

export type ClientKeys = {
	spamhausDqs: string;
};

export function loadKeys(): ClientKeys {
	try {
		const raw = localStorage.getItem(STORAGE);
		if (!raw) return { spamhausDqs: '' };
		const parsed = JSON.parse(raw) as Partial<ClientKeys>;
		return { spamhausDqs: parsed.spamhausDqs ?? '' };
	} catch {
		return { spamhausDqs: '' };
	}
}

export function saveKeys(keys: ClientKeys) {
	localStorage.setItem(STORAGE, JSON.stringify(keys));
}

export default function Settings({
	open,
	onClose,
	serverHasDqs,
}: {
	open: boolean;
	onClose: () => void;
	serverHasDqs: boolean;
}) {
	const [spamhausDqs, setSpamhausDqs] = useState('');

	useEffect(() => {
		if (open) setSpamhausDqs(loadKeys().spamhausDqs);
	}, [open]);

	if (!open) return null;

	return (
		<div className="modal-backdrop" onClick={onClose} role="presentation">
			<div
				className="modal"
				role="dialog"
				aria-labelledby="settings-title"
				onClick={(e) => e.stopPropagation()}
			>
				<h2 id="settings-title">Private keys</h2>
				<p>
					Stored only in this browser. Sent as a request header to <em>this</em> Worker. Do not paste keys into
					a public deployment.
				</p>
				<label>
					Spamhaus DQS key
					<input
						type="password"
						autoComplete="off"
						spellCheck={false}
						value={spamhausDqs}
						onChange={(e) => setSpamhausDqs(e.target.value)}
						placeholder={serverHasDqs ? 'Optional override — Worker already has a secret' : 'For private instances'}
					/>
				</label>
				<p className="hint">
					Queries then use <code>{'{key}'}.zen.dq.spamhaus.net</code>. Server secret:{' '}
					{serverHasDqs ? 'configured' : 'not set'}. CLI: <code>SPAMHAUS_DQS_KEY</code>.
				</p>
				<div className="modal-actions">
					<button
						type="button"
						className="ghost"
						onClick={() => {
							setSpamhausDqs('');
							saveKeys({ spamhausDqs: '' });
							onClose();
						}}
					>
						Clear
					</button>
					<button
						type="button"
						onClick={() => {
							saveKeys({ spamhausDqs: spamhausDqs.trim() });
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
