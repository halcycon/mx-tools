import type { ReportEnv } from './config';
import type { RenderedEmail } from './templates';

export type Outgoing = RenderedEmail & { to: string; replyTo?: string };

export async function sendEmail(env: ReportEnv, msg: Outgoing): Promise<void> {
	if (!env.REPORT_FROM) throw new Error('REPORT_FROM is not configured');
	await env.EMAIL.send({
		from: { email: env.REPORT_FROM, name: env.REPORT_FROM_NAME || 'The Cuckoo Camp' },
		to: msg.to,
		replyTo: msg.replyTo ?? env.REPLY_TO ?? undefined,
		subject: msg.subject,
		html: msg.html,
		text: msg.text,
	});
}

/** Admin mail is best effort and never blocks the requester's flow. */
export async function notifyAdmin(env: ReportEnv, msg: RenderedEmail & { replyTo?: string }): Promise<boolean> {
	if (!env.LEAD_NOTIFY_TO) return false;
	try {
		await sendEmail(env, { ...msg, to: env.LEAD_NOTIFY_TO });
		return true;
	} catch (e) {
		console.log(JSON.stringify({ event: 'report_admin_email_failed', code: (e as { code?: string }).code ?? 'unknown' }));
		return false;
	}
}
