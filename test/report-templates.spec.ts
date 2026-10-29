import { describe, expect, it } from 'vitest';
import { buildReport, toCheck } from '../worker/health/codes';
import { NO_MAILBOX_LINE, renderApology, renderConfirmation, renderLead, renderReport } from '../worker/report/templates';
import { describe as describeCheck, WORDING } from '../worker/report/wording';

const report = buildReport(
	'example.org',
	[
		toCheck('dmarc', { code: 'dmarc_policy_none', facts: {}, technical: 'v=DMARC1; p=none' }),
		toCheck('spf', { code: 'spf_pass_hardfail', facts: {}, technical: 'v=spf1 -all' }),
		toCheck('mx', { code: 'mx_missing', facts: {}, technical: '' }),
		toCheck('bimi', { code: 'bimi_missing', facts: {}, technical: '' }),
		toCheck('smtp', { code: 'cert_expiring_soon', facts: {}, technical: 'mx.example.org:25 <script>alert(1)</script>' }),
	],
	new Date('2026-11-03T08:00:00Z'),
);

describe('report email', () => {
	const email = renderReport({ name: 'Ann <Treasurer>', report, bookingUrl: 'https://www.thecuckoocamp.co.uk/contact/' });

	it('uses the website wording for each code', () => {
		expect(WORDING.codes.dmarc_policy_none?.text).toBeTruthy();
		expect(email.html).toContain(WORDING.codes.dmarc_policy_none!.text!.replace(/'/g, '&#39;'));
		expect(email.text).toContain(WORDING.codes.dmarc_policy_none!.text!);
		expect(email.text).toContain(WORDING.codes.mx_missing!.text!);
	});

	it('orders sections: issues, then good, then not checked', () => {
		const t = email.text;
		expect(t.indexOf('WHAT NEEDS ATTENTION')).toBeLessThan(t.indexOf("WHAT'S WORKING WELL"));
		expect(t.indexOf("WHAT'S WORKING WELL")).toBeLessThan(t.indexOf('NOT CHECKED OR OPTIONAL'));
		expect(t.indexOf(describeCheck(report.checks.find((c) => c.id === 'mx')!).title)).toBeLessThan(t.indexOf('WHAT\'S WORKING WELL'));
	});

	it('has the summary, call button, technical details and mailbox line', () => {
		expect(email.subject).toBe('Your email health report for example.org');
		expect(email.text).toContain('3 things need attention');
		expect(email.html).toContain('Book your free 20-minute call');
		expect(email.html).toContain('https://www.thecuckoocamp.co.uk/contact/');
		expect(email.text).toContain('TECHNICAL DETAILS');
		expect(email.text).toContain('v=DMARC1; p=none');
		expect(email.html).toContain(NO_MAILBOX_LINE);
		expect(email.text).toContain(NO_MAILBOX_LINE);
	});

	it('escapes user-controlled and DNS-controlled text in HTML', () => {
		expect(email.html).toContain('Ann &lt;Treasurer&gt;');
		expect(email.html).not.toContain('<script>');
		expect(email.html).toContain('&lt;script&gt;');
	});

	it('falls back to the check id when the website has no wording for a code', () => {
		const d = describeCheck(report.checks.find((c) => c.id === 'smtp')!, { statuses: {}, summary: {}, checks: {}, codes: {} });
		expect(d.title).toBe('SMTP');
		expect(d.label).toBe('warn');
	});

	it('uses why/fix extras when the wording provides them', () => {
		const w = { ...WORDING, codes: { ...WORDING.codes, mx_missing: { title: 'Mail', text: 't', why: 'Because.', fix: 'Add MX.' } } };
		const e = renderReport({ name: 'A', report, wording: w });
		expect(e.text).toContain('Why it matters: Because.');
		expect(e.text).toContain('What to do: Add MX.');
	});
});

describe('confirmation, lead and apology emails', () => {
	it('confirmation carries the single-use link and expiry', () => {
		const e = renderConfirmation({ name: 'Ann', domain: 'example.org', confirmUrl: 'https://dart.example/api/v1/report-confirm?token=abc', ttlHours: 24 });
		expect(e.html).toContain('Confirm and send my report');
		expect(e.html).toContain('href="https://dart.example/api/v1/report-confirm?token=abc"');
		expect(e.text).toContain('https://dart.example/api/v1/report-confirm?token=abc');
		expect(e.text).toContain('24 hours');
	});

	it('lead has contact details, counts, top issues and the call flag', () => {
		const e = renderLead({ name: 'Ann', email: 'ann@example.org', organisation: 'Small Charity', domain: 'example.org', wantsCall: true, report, usedCache: false, usedAgent: true });
		expect(e.subject).toBe('Call request: example.org (fail)');
		for (const s of ['ann@example.org', 'Small Charity', 'Yes, asked for a call', 'pass 1 · warn 2 · fail 1', 'mx_missing', 'dmarc_policy_none', 'VPS agent']) {
			expect(e.text).toContain(s);
		}
	});

	it('apology is short and mentions the mailbox line', () => {
		const e = renderApology({ name: 'Ann', domain: 'example.org' });
		expect(e.text).toContain("couldn't finish");
		expect(e.text).toContain(NO_MAILBOX_LINE);
	});
});
