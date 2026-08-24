import { describe, it, expect } from 'vitest';
import { parseSmtpReply } from '../worker/checks/smtp';
import { parseQuery } from '../worker/checks/types';

describe('SMTP reply parser', () => {
	it('handles a single-line 220', () => {
		const p = parseSmtpReply('220 smtp.example.com ESMTP\r\nleftover');
		expect(p).toEqual({ code: 220, text: 'smtp.example.com ESMTP', rest: 'leftover' });
	});

	it('handles a multiline 250 EHLO', () => {
		const raw = '250-smtp.example.com\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n';
		const p = parseSmtpReply(raw);
		expect(p?.code).toBe(250);
		expect(p?.text).toContain('STARTTLS');
		expect(p?.text).toContain('AUTH PLAIN LOGIN');
	});

	it('returns null until the final line arrives', () => {
		expect(parseSmtpReply('250-smtp.example.com\r\n250-STARTTLS\r\n')).toBeNull();
	});
});

describe('parseQuery smtp ports', () => {
	it('splits smtp:host:587', () => {
		expect(parseQuery('smtp:smtp.gmail.com:587')).toEqual({
			tool: 'smtp',
			target: 'smtp.gmail.com',
			extra: '587',
		});
	});
});
