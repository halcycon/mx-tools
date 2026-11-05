import { DAY, type ReportEnv } from '../report/config';
import { sendEmail } from '../report/mailer';
import { esc, type RenderedEmail } from '../report/templates';
import type { UsageRow } from './store';

import { ZONE, previousLondonDay } from './time';
export { previousLondonDay } from './time';

const PAGE_SIZE = 100;
const RETENTION_DAYS = 7;
const timeFormatter = new Intl.DateTimeFormat('en-GB', { timeZone: ZONE, dateStyle: 'short', timeStyle: 'long' });

type Totals = { checks: number; domains: number };
export function renderUsageDigest(day: string, rows: UsageRow[], totals: Totals, part: number, parts: number, domains: { domain: string; checks: number }[]): RenderedEmail {
	const subject = `Website health-check usage: ${day}${parts > 1 ? ` (${part}/${parts})` : ''}`;
	const intro = `${totals.checks} checks across ${totals.domains} domains. Previous calendar day in ${ZONE}. Referrer and UTM are browser-supplied and may be missing. Data retained in D1 for ${RETENTION_DAYS} days; this email is a separate copy.`;
	const columns = ['Time (UK)', 'Domain', 'Visitor IP', 'Page', 'Referrer', 'UTM', 'Outcome', 'Cached'];
	const values = rows.map(row => [timeFormatter.format(row.requested_at), row.domain, row.client_ip ?? 'Unknown', row.page_url ?? 'Unknown', row.referrer ?? 'Unknown', Object.entries(JSON.parse(row.utm_json) as Record<string, string>).map(([k, v]) => `${k}=${v}`).join('; ') || 'None', row.outcome, row.cached ? 'Yes' : 'No']);
	const domainText = domains.map(d => `${d.domain}: ${d.checks}`).join('\n');
	return {
		subject,
		text: `${subject}\n\n${intro}\n\nDomains on this page:\n${domainText || 'None'}\n\n${values.map(v => columns.map((c, i) => `${c}: ${v[i]}`).join('\n')).join('\n\n') || 'No checks recorded.'}`,
		html: `<!doctype html><html lang="en"><body><h1>${esc(subject)}</h1><p>${esc(intro)}</p><h2>Domains on this page</h2><ul>${domains.map(d => `<li>${esc(d.domain)}: ${d.checks}</li>`).join('') || '<li>None</li>'}</ul><table border="1" cellpadding="6"><thead><tr>${columns.map(c => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${values.map(v => `<tr>${v.map(s => `<td>${esc(s)}</td>`).join('')}</tr>`).join('')}</tbody></table>${rows.length ? '' : '<p>No checks recorded.</p>'}</body></html>`,
	};
}

type Digest = { day: string; start_at: number; end_at: number; next_offset: number };

/** Called by the existing 15-minute cron; first delivery is at UK midnight, retries follow. */
export async function handleUsageCron(env: ReportEnv, now = Date.now()): Promise<void> {
	const to = env.LEAD_NOTIFY_TO?.trim();
	const window = previousLondonDay(now);
	// Keep data for seven days even if sending is broken. Delivery metadata has no visitor data.
	await env.DB.batch([
		env.DB.prepare('DELETE FROM health_usage WHERE requested_at < ?').bind(now - RETENTION_DAYS * DAY),
		env.DB.prepare('DELETE FROM health_usage_digests WHERE end_at < ?').bind(now - RETENTION_DAYS * DAY),
	]);
	if (!to) return;
	await env.DB.prepare('INSERT OR IGNORE INTO health_usage_digests(day,start_at,end_at) VALUES(?,?,?)').bind(window.day, window.start, window.end).run();
	const pending = await env.DB.prepare('SELECT day,start_at,end_at,next_offset FROM health_usage_digests WHERE sent_at IS NULL AND end_at<=? ORDER BY day').bind(window.end).all<Digest>();
	for (const digest of pending.results) {
		const token = crypto.randomUUID();
		const claimed = await env.DB.prepare(`UPDATE health_usage_digests SET lease_token=?,lease_until=?
			WHERE day=? AND sent_at IS NULL AND lease_until<=? RETURNING day,start_at,end_at,next_offset`)
			.bind(token, now + 10 * 60_000, digest.day, now).first<Digest>();
		if (!claimed) continue;
		try {
			const totals = await env.DB.prepare('SELECT COUNT(*) AS checks,COUNT(DISTINCT domain) AS domains FROM health_usage WHERE requested_at>=? AND requested_at<?')
				.bind(digest.start_at, digest.end_at).first<Totals>();
			const count = totals?.checks ?? 0;
			const parts = Math.max(1, Math.ceil(count / PAGE_SIZE));
			let offset = claimed.next_offset;
			// Bound each invocation; subsequent ticks resume large summaries.
			for (let sent = 0; sent < 10; sent++) {
				const rows = await env.DB.prepare('SELECT * FROM health_usage WHERE requested_at>=? AND requested_at<? ORDER BY requested_at,id LIMIT ? OFFSET ?')
					.bind(digest.start_at, digest.end_at, PAGE_SIZE, offset).all<UsageRow>();
				const counts = new Map<string, number>();
				for (const row of rows.results) counts.set(row.domain, (counts.get(row.domain) ?? 0) + 1);
				const domains = [...counts].sort(([a], [b]) => a.localeCompare(b)).map(([domain, checks]) => ({ domain, checks }));
				await sendEmail(env, { to, ...renderUsageDigest(digest.day, rows.results, totals ?? { checks: 0, domains: 0 }, Math.floor(offset / PAGE_SIZE) + 1, parts, domains) });
				offset += rows.results.length;
				const done = offset >= count;
				await env.DB.prepare('UPDATE health_usage_digests SET next_offset=?,sent_at=?,lease_until=? WHERE day=? AND lease_token=?')
					.bind(offset, done ? now : null, now + 10 * 60_000, digest.day, token).run();
				if (done) break;
			}
		} finally {
			await env.DB.prepare('UPDATE health_usage_digests SET lease_until=0 WHERE day=? AND lease_token=?').bind(digest.day, token).run();
		}
	}
}
