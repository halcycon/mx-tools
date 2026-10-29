import { getDomain } from 'tldts-icann';
import { normalizeDomain } from '../health/domain';

/** Small, cheap list of the most common throwaway-inbox providers. Not exhaustive by design. */
const DISPOSABLE = new Set([
	'10minutemail.com',
	'dispostable.com',
	'emailondeck.com',
	'getnada.com',
	'guerrillamail.com',
	'guerrillamailblock.com',
	'maildrop.cc',
	'mailinator.com',
	'mailnesia.com',
	'mintemail.com',
	'mohmal.com',
	'sharklasers.com',
	'temp-mail.org',
	'tempmail.com',
	'tempmailo.com',
	'throwawaymail.com',
	'trashmail.com',
	'yopmail.com',
]);

const EMAIL = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

export function normalizeEmail(input: unknown): string | null {
	if (typeof input !== 'string') return null;
	const email = input.trim().toLowerCase();
	if (email.length > 254 || !EMAIL.test(email)) return null;
	const [local, host] = [email.slice(0, email.lastIndexOf('@')), email.slice(email.lastIndexOf('@') + 1)];
	if (local.length > 64 || local.startsWith('.') || local.endsWith('.') || local.includes('..')) return null;
	const registrable = getDomain(host);
	if (!registrable || normalizeDomain(host) === null || DISPOSABLE.has(registrable)) return null;
	return email;
}

function cleanText(input: unknown, max: number): string | null {
	if (typeof input !== 'string') return null;
	const s = input.replace(/[\u0000-\u001f\u007f<>]/g, ' ').replace(/\s+/g, ' ').trim();
	return s && s.length <= max ? s : null;
}

export type ReportRequestInput = {
	name: string;
	email: string;
	organisation: string | null;
	domain: string;
	wantsCall: boolean;
	turnstileToken: unknown;
};

export type ValidationError = 'invalid_name' | 'invalid_email' | 'invalid_domain' | 'invalid_organisation' | 'consent_required';

export function validateReportRequest(body: unknown): { ok: true; value: ReportRequestInput } | { ok: false; error: ValidationError } {
	const b = (body && typeof body === 'object' ? body : {}) as Record<string, unknown>;
	if (b.consent !== true) return { ok: false, error: 'consent_required' };
	const name = cleanText(b.name, 100);
	if (!name) return { ok: false, error: 'invalid_name' };
	const email = normalizeEmail(b.email);
	if (!email) return { ok: false, error: 'invalid_email' };
	const domain = normalizeDomain(b.domain);
	if (!domain) return { ok: false, error: 'invalid_domain' };
	let organisation: string | null = null;
	if (b.organisation !== undefined && b.organisation !== null && b.organisation !== '') {
		organisation = cleanText(b.organisation, 120);
		if (!organisation) return { ok: false, error: 'invalid_organisation' };
	}
	return { ok: true, value: { name, email, organisation, domain, wantsCall: b.wantsCall === true, turnstileToken: b.turnstileToken } };
}
