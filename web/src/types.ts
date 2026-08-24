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
