import snapshot from './wording.json';
import type { HealthCheck, HealthStatus } from '../health/codes';

/** Same shape as cuckoo-site data/healthcheck.yaml (synced by scripts/sync-wording.mjs). */
export type Wording = {
	statuses: Partial<Record<HealthStatus, { label?: string }>>;
	summary: { attention_one?: string; attention_many?: string; all_good?: string; partial?: string };
	checks: Record<string, Partial<Record<HealthStatus | 'title', string>>>;
	/** `why` and `fix` are optional extras used by the full-report email. */
	codes: Record<string, { title?: string; text?: string; label?: string; why?: string; fix?: string }>;
};

export const WORDING = snapshot as unknown as Wording;

export type Described = { title: string; text: string; label: string; why?: string; fix?: string };

export function describe(check: HealthCheck, w: Wording = WORDING): Described {
	const code = w.codes[check.code];
	const fallback = w.checks[check.id];
	return {
		title: code?.title ?? fallback?.title ?? check.id.toUpperCase(),
		text: code?.text ?? fallback?.[check.status] ?? '',
		label: code?.label ?? w.statuses[check.status]?.label ?? check.status,
		why: code?.why,
		fix: code?.fix,
	};
}

export function summaryLine(attention: number, w: Wording = WORDING): string {
	if (attention === 0) return w.summary.all_good ?? '';
	if (attention === 1) return w.summary.attention_one ?? '1';
	return (w.summary.attention_many ?? '{count}').replace('{count}', String(attention));
}
