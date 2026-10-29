import type { AgentEnv } from '../agent/client';
import { readLimits, type ReportEnv, type ReportJob } from './config';
import { metric, release } from './handler';
import { deliveryDecision } from './limits';
import { notifyAdmin, sendEmail } from './mailer';
import { runFullReport } from './full';
import { bumpAttempts, cachedResult, cleanup, deferredRequests, getRequest, markFailed, markSent, markStep, storeResult } from './store';
import { renderAdminNotice, renderApology, renderLead, renderReport } from './templates';

/** 1 delivery + 3 retries (matches `max_retries: 3` on the consumer). */
export const MAX_ATTEMPTS = 4;

export type QueueEnv = ReportEnv & AgentEnv;

export type FullRunner = typeof runFullReport;

export async function processReport(env: QueueEnv, id: string, now = Date.now(), run: FullRunner = runFullReport): Promise<'sent' | 'skipped'> {
	const row = await getRequest(env.DB, id);
	if (!row || row.status !== 'queued') return 'skipped';
	await bumpAttempts(env.DB, id);

	const limits = readLimits(env);
	let usedCache = true;
	let result = await cachedResult(env.DB, row.domain, now, limits);
	if (!result) {
		usedCache = false;
		result = await run(row.domain, env);
		if (result.usedAgent) await storeResult(env.DB, row.domain, result.report, true, now);
	}

	if (!row.report_sent_at) {
		await sendEmail(env, { to: row.email, ...renderReport({ name: row.name, report: result.report, bookingUrl: env.BOOKING_URL }) });
		await markStep(env.DB, id, 'report_sent_at', Date.now());
		metric('report_sent', { cached: usedCache, agent: result.usedAgent, overall: result.report.overall });
	}
	if (!row.lead_sent_at && env.LEAD_NOTIFY_TO) {
		await sendEmail(env, {
			to: env.LEAD_NOTIFY_TO,
			replyTo: row.email,
			...renderLead({
				name: row.name,
				email: row.email,
				organisation: row.organisation,
				domain: row.domain,
				wantsCall: row.wants_call === 1,
				report: result.report,
				usedCache,
				usedAgent: result.usedAgent,
			}),
		});
		await markStep(env.DB, id, 'lead_sent_at', Date.now());
		metric('lead_sent', { wantsCall: row.wants_call === 1 });
	}
	await markSent(env.DB, id, result.report, { usedCache, usedAgent: result.usedAgent }, Date.now());
	return 'sent';
}

export async function failReport(env: QueueEnv, id: string, now = Date.now()): Promise<void> {
	const row = await getRequest(env.DB, id);
	if (!row) return;
	await markFailed(env.DB, id, now);
	if (!row.report_sent_at) {
		try {
			await sendEmail(env, { to: row.email, ...renderApology({ name: row.name, domain: row.domain }) });
		} catch {
			metric('apology_failed');
		}
	}
	await notifyAdmin(env, {
		...renderAdminNotice(`Full report failed: ${row.domain}`, [
			`Request ${row.id} failed after ${row.attempts} attempt(s).`,
			`Requester: ${row.name} <${row.email}>${row.organisation ? `, ${row.organisation}` : ''}. Discovery call: ${row.wants_call === 1 ? 'yes' : 'no'}.`,
			row.report_sent_at ? 'The report itself was sent; the lead notification step failed.' : 'They have been sent a short apology.',
		]),
		replyTo: row.email,
	});
	metric('failed');
}

export async function handleReportQueue(batch: MessageBatch<ReportJob>, env: QueueEnv): Promise<void> {
	for (const msg of batch.messages) {
		try {
			await processReport(env, msg.body.id);
			msg.ack();
		} catch (e) {
			const code = (e as { code?: string }).code ?? (e instanceof Error ? e.name : 'unknown');
			if (msg.attempts >= MAX_ATTEMPTS) {
				await failReport(env, msg.body.id);
				msg.ack();
			} else {
				metric('retry', { attempt: msg.attempts, code });
				msg.retry({ delaySeconds: 30 * 2 ** (msg.attempts - 1) });
			}
		}
	}
}

/** Cron: retention cleanup, then release deferred requests whose limits have freed up. */
export async function handleReportCron(env: QueueEnv, now = Date.now()): Promise<void> {
	const limits = readLimits(env);
	const removed = await cleanup(env.DB, now, limits);
	let released = 0;
	for (const row of await deferredRequests(env.DB)) {
		if ((await deliveryDecision(env.DB, row.email_hash, row.domain, now, limits)) !== 'ok') continue;
		if ((await release(env, row, now)) === 'queued') released++;
	}
	metric('cron', { ...removed, released });
}
