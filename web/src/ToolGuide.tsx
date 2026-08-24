import {
	DOMAIN_HEALTH_CHECKS,
	EMAIL_HEALTH_EXTRA,
	GUIDE_GROUPS,
	GUIDE_TOOLS,
	guideTool,
	type GuideTool,
} from './tools-guide';

type Props = {
	mode: 'landing' | 'guide';
	onClose?: () => void;
	onPickTool: (toolId: string) => void;
	onRunExample: (example: string) => void;
};

function ReportCard({
	title,
	kicker,
	checks,
	extra,
	example,
	primary,
	onRun,
	onSelect,
}: {
	title: string;
	kicker: string;
	checks: readonly string[];
	extra?: readonly string[];
	example: string;
	primary?: boolean;
	onRun: () => void;
	onSelect: () => void;
}) {
	return (
		<article className={`guide-card${primary ? ' primary' : ''}`}>
			<p className="guide-kicker">{kicker}</p>
			<h3>{title}</h3>
			<ul className="guide-checks">
				{checks.map((c) => (
					<li key={c}>{c}</li>
				))}
			</ul>
			{extra ? (
				<>
					<p className="guide-plus">Plus</p>
					<ul className="guide-checks muted">
						{extra.map((c) => (
							<li key={c}>{c}</li>
						))}
					</ul>
				</>
			) : null}
			<div className="guide-card-actions">
				<button type="button" className={primary ? undefined : 'health-btn'} onClick={onRun}>
					Try {example}
				</button>
				<button type="button" className="linkish" onClick={onSelect}>
					Select in dropdown
				</button>
			</div>
		</article>
	);
}

function ToolRow({ tool, onPick, onRun }: { tool: GuideTool; onPick: () => void; onRun: () => void }) {
	return (
		<li className="guide-tool">
			<div>
				<button type="button" className="guide-tool-name" onClick={onPick} title={`Select ${tool.label}`}>
					{tool.label}
					<code>{tool.id === 'auto' ? '(bare domain)' : tool.id}</code>
				</button>
				<p>{tool.blurb}</p>
			</div>
			<button type="button" className="more" onClick={onRun} title={`Run ${tool.example}`}>
				{tool.example}
			</button>
		</li>
	);
}

export default function ToolGuide({ mode, onClose, onPickTool, onRunExample }: Props) {
	const domain = guideTool('auto')!;
	const email = guideTool('full')!;

	return (
		<div className={`tool-guide${mode === 'guide' ? ' overlay' : ''}`}>
			{mode === 'guide' ? (
				<div className="tool-guide-head">
					<div>
						<p className="guide-kicker">D.A.R.T.</p>
						<h2>Tools guide</h2>
					</div>
					{onClose ? (
						<button type="button" className="settings-btn" onClick={onClose}>
							Close
						</button>
					) : null}
				</div>
			) : (
				<div className="landing-hero">
					<p className="guide-kicker">Welcome</p>
					<h2>Domain Authentication & Reputation Toolkit</h2>
					<p>
						Pick a tool, enter a host, and results stream in live. Start with a health report, or jump to a
						single check such as SPF or blacklist.
					</p>
				</div>
			)}

			<section className="guide-compare" aria-label="Health report comparison">
				<ReportCard
					title="Domain health"
					kicker="Quick · 5 checks"
					checks={DOMAIN_HEALTH_CHECKS}
					example={domain.example}
					primary
					onRun={() => onRunExample(domain.example)}
					onSelect={() => onPickTool('auto')}
				/>
				<ReportCard
					title="Email health report"
					kicker="Deep · Domain health +"
					checks={DOMAIN_HEALTH_CHECKS}
					extra={EMAIL_HEALTH_EXTRA}
					example={email.example}
					onRun={() => onRunExample(email.example)}
					onSelect={() => onPickTool('full')}
				/>
			</section>

			<p className="guide-note">
				<strong>Domain health</strong> answers “is mail auth basically OK?” · <strong>Email health</strong> adds
				flatten, DKIM, BIMI, MTA-STS, DNS, HTTPS, and registration lookups. Same live progress UI either way.
			</p>

			{GUIDE_GROUPS.map((group) => {
				const tools = GUIDE_TOOLS.filter((t) => t.group === group.id);
				if (!tools.length) return null;
				return (
					<section key={group.id} className="guide-section">
						<h3>{group.title}</h3>
						<p className="guide-section-blurb">{group.blurb}</p>
						<ul className="guide-tool-list">
							{tools.map((tool) => (
								<ToolRow
									key={tool.id}
									tool={tool}
									onPick={() => onPickTool(tool.id)}
									onRun={() => onRunExample(tool.example)}
								/>
							))}
						</ul>
					</section>
				);
			})}
		</div>
	);
}
