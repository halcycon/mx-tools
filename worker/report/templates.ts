import type { HealthCheck, HealthReport, HealthStatus } from '../health/codes';
import { describe, summaryLine, WORDING, type Wording } from './wording';

export type RenderedEmail = { subject: string; html: string; text: string };

export const NO_MAILBOX_LINE = 'This report covers public DNS and mail-server checks only. We never accessed your mailbox.';

export function esc(s: string): string {
	return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const COLORS: Record<HealthStatus, string> = { fail: '#b42318', warn: '#b54708', pass: '#067647', info: '#475467' };

function layout(title: string, body: string): string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${esc(title)}</title></head>
<body style="margin:0;padding:0;background:#f5f5f4;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1c1917;line-height:1.5">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:640px;background:#ffffff;border-radius:8px;padding:28px">
<tr><td>${body}</td></tr></table>
<p style="font-size:12px;color:#78716c;margin:16px 0 0">The Cuckoo Camp · thecuckoocamp.co.uk</p>
</td></tr></table></body></html>`;
}

function button(href: string, label: string): string {
	return `<p style="margin:24px 0"><a href="${esc(href)}" style="display:inline-block;background:#1c1917;color:#ffffff;text-decoration:none;padding:12px 20px;border-radius:6px;font-weight:600">${esc(label)}</a></p>`;
}

export function renderConfirmation(p: { name: string; domain: string; confirmUrl: string; ttlHours: number }): RenderedEmail {
	const subject = `Confirm your email health report for ${p.domain}`;
	const html = layout(
		subject,
		`<p>Hi ${esc(p.name)},</p>
<p>Someone (hopefully you) asked for a full email health report for <strong>${esc(p.domain)}</strong> to be sent to this address.</p>
<p>Click the button to confirm and we'll run the checks and email you the results.</p>
${button(p.confirmUrl, 'Confirm and send my report')}
<p style="font-size:14px;color:#57534e">This link works once and expires in ${p.ttlHours} hours. If you didn't ask for this, ignore this email and nothing will be sent.</p>`,
	);
	const text = `Hi ${p.name},

Someone (hopefully you) asked for a full email health report for ${p.domain} to be sent to this address.

Confirm and send my report:
${p.confirmUrl}

This link works once and expires in ${p.ttlHours} hours. If you didn't ask for this, ignore this email and nothing will be sent.
`;
	return { subject, html, text };
}

const SECTION_ORDER: Array<{ statuses: HealthStatus[]; heading: string }> = [
	{ statuses: ['fail', 'warn'], heading: 'What needs attention' },
	{ statuses: ['pass'], heading: "What's working well" },
	{ statuses: ['info'], heading: 'Not checked or optional' },
];

const rank: Record<HealthStatus, number> = { fail: 0, warn: 1, pass: 2, info: 3 };

export function renderReport(p: { name: string; report: HealthReport; bookingUrl?: string; wording?: Wording }): RenderedEmail {
	const w = p.wording ?? WORDING;
	const { report } = p;
	const subject = `Your email health report for ${report.domain}`;
	const attention = report.score.fail + report.score.warn;
	const summary = summaryLine(attention, w);
	const sorted = [...report.checks].sort((a, b) => rank[a.status] - rank[b.status]);

	const htmlSections: string[] = [];
	const textSections: string[] = [];
	for (const section of SECTION_ORDER) {
		const items = sorted.filter((c) => section.statuses.includes(c.status));
		if (!items.length) continue;
		htmlSections.push(`<h2 style="font-size:18px;margin:28px 0 8px">${esc(section.heading)}</h2>`);
		textSections.push(`\n${section.heading.toUpperCase()}\n${'-'.repeat(section.heading.length)}`);
		for (const c of items) {
			const d = describe(c, w);
			htmlSections.push(`<div style="border-left:4px solid ${COLORS[c.status]};padding:4px 0 4px 12px;margin:12px 0">
<p style="margin:0;font-weight:600">${esc(d.title)} <span style="font-weight:500;font-size:13px;color:${COLORS[c.status]}">· ${esc(d.label)}</span></p>
${d.text ? `<p style="margin:4px 0">${esc(d.text)}</p>` : ''}
${d.why ? `<p style="margin:4px 0"><strong>Why it matters:</strong> ${esc(d.why)}</p>` : ''}
${d.fix ? `<p style="margin:4px 0"><strong>What to do:</strong> ${esc(d.fix)}</p>` : ''}
</div>`);
			textSections.push(
				[`* ${d.title} [${d.label}]`, d.text && `  ${d.text}`, d.why && `  Why it matters: ${d.why}`, d.fix && `  What to do: ${d.fix}`]
					.filter(Boolean)
					.join('\n'),
			);
		}
	}

	const tech = sorted.filter((c) => c.technical);
	const techHtml = tech
		.map(
			(c) => `<p style="margin:12px 0 4px;font-weight:600;font-size:13px">${esc(c.id)} · ${esc(c.code)}</p>
<pre style="margin:0;padding:8px;background:#f5f5f4;border-radius:4px;font-size:12px;white-space:pre-wrap;word-break:break-all">${esc(c.technical)}</pre>`,
		)
		.join('\n');
	const techText = tech.map((c) => `[${c.id} · ${c.code}]\n${c.technical}`).join('\n\n');

	const html = layout(
		subject,
		`<p>Hi ${esc(p.name)},</p>
<p>Here is your full email health report for <strong>${esc(report.domain)}</strong>, checked ${esc(report.checkedAt.replace('T', ' ').replace('Z', ' UTC'))}.</p>
<p style="font-size:18px;font-weight:600;margin:16px 0">${esc(summary)}</p>
${htmlSections.join('\n')}
${p.bookingUrl ? button(p.bookingUrl, 'Book your free 20-minute call') : ''}
<h2 style="font-size:18px;margin:28px 0 8px">Technical details</h2>
<p style="font-size:14px;color:#57534e">For whoever looks after your domain or email.</p>
${techHtml}
<p style="font-size:13px;color:#57534e;margin-top:28px">${esc(NO_MAILBOX_LINE)}</p>`,
	);
	const text = `Hi ${p.name},

Here is your full email health report for ${report.domain}, checked ${report.checkedAt}.

${summary}
${textSections.join('\n\n')}
${p.bookingUrl ? `\nBook your free 20-minute call: ${p.bookingUrl}\n` : ''}
TECHNICAL DETAILS
-----------------
${techText}

${NO_MAILBOX_LINE}
`;
	return { subject, html, text };
}

export type LeadInfo = {
	name: string;
	email: string;
	organisation: string | null;
	domain: string;
	wantsCall: boolean;
	report: HealthReport;
	usedCache: boolean;
	usedAgent: boolean;
};

export function topIssues(report: HealthReport, wording: Wording = WORDING, max = 5): Array<{ check: HealthCheck; title: string }> {
	return report.checks
		.filter((c) => c.status === 'fail' || c.status === 'warn')
		.sort((a, b) => rank[a.status] - rank[b.status])
		.slice(0, max)
		.map((check) => ({ check, title: describe(check, wording).title }));
}

export function renderLead(p: LeadInfo): RenderedEmail {
	const subject = `${p.wantsCall ? 'Call request' : 'New report lead'}: ${p.domain} (${p.report.overall})`;
	const s = p.report.score;
	const issues = topIssues(p.report);
	const rows: Array<[string, string]> = [
		['Name', p.name],
		['Email', p.email],
		['Organisation', p.organisation ?? '—'],
		['Domain', p.domain],
		['Discovery call', p.wantsCall ? 'Yes, asked for a call' : 'No'],
		['Overall', `${p.report.overall} (pass ${s.pass} · warn ${s.warn} · fail ${s.fail})`],
		['Source', `${p.usedAgent ? 'VPS agent' : 'Worker only (agent unavailable)'}${p.usedCache ? ', cached result' : ''}`],
	];
	const html = layout(
		subject,
		`<h2 style="font-size:18px;margin:0 0 12px">${esc(subject)}</h2>
<table role="presentation" cellpadding="4" style="font-size:14px">${rows.map(([k, v]) => `<tr><td style="color:#57534e">${esc(k)}</td><td>${esc(v)}</td></tr>`).join('')}</table>
<h3 style="font-size:16px;margin:20px 0 8px">Top issues</h3>
${issues.length ? `<ul>${issues.map((i) => `<li><strong>${esc(i.check.status)}</strong> ${esc(i.title)} <code>${esc(i.check.code)}</code></li>`).join('')}</ul>` : '<p>None.</p>'}
<p style="font-size:13px;color:#57534e">Replying to this email writes to ${esc(p.name)} &lt;${esc(p.email)}&gt;.</p>`,
	);
	const text = `${subject}

${rows.map(([k, v]) => `${k}: ${v}`).join('\n')}

Top issues:
${issues.length ? issues.map((i) => `- [${i.check.status}] ${i.title} (${i.check.code})`).join('\n') : '- none'}
`;
	return { subject, html, text };
}

export function renderApology(p: { name: string; domain: string }): RenderedEmail {
	const subject = `Your email health report for ${p.domain}`;
	const body = `We're sorry, we couldn't finish your email health report for ${p.domain} this time. Adam has been told and will get it to you, or be in touch, soon.`;
	return {
		subject,
		html: layout(subject, `<p>Hi ${esc(p.name)},</p><p>${esc(body)}</p><p style="font-size:13px;color:#57534e">${esc(NO_MAILBOX_LINE)}</p>`),
		text: `Hi ${p.name},\n\n${body}\n\n${NO_MAILBOX_LINE}\n`,
	};
}

export function renderAdminNotice(subject: string, lines: string[]): RenderedEmail {
	return {
		subject,
		html: layout(subject, `<h2 style="font-size:18px">${esc(subject)}</h2>${lines.map((l) => `<p>${esc(l)}</p>`).join('')}`),
		text: `${subject}\n\n${lines.join('\n')}\n`,
	};
}
