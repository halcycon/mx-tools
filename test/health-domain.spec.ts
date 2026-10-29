import { describe, expect, it } from 'vitest';
import { normalizeDomain } from '../worker/health/domain';

describe('health-check domain validator', () => {
	it.each([
		['example.org', 'example.org'],
		['  Example.ORG  ', 'example.org'],
		['example.org.', 'example.org'],
		['https://www.thecuckoocamp.co.uk/about?x=1#top', 'thecuckoocamp.co.uk'],
		['http://example.org:8080/', 'example.org'],
		['www.example.org', 'example.org'],
		['mail.dept.example.ac.uk', 'example.ac.uk'],
		['treasurer@charity.org.uk', 'charity.org.uk'],
		['mailto:someone@example.com', 'example.com'],
		['bücher.de', 'xn--bcher-kva.de'],
	])('normalises %j → %s', (input, expected) => {
		expect(normalizeDomain(input)).toBe(expected);
	});

	it.each([
		'',
		'   ',
		'example',
		'localhost',
		'printer.local',
		'nas.lan',
		'app.internal',
		'foo.test',
		'1.2.3.4',
		'http://10.0.0.1/',
		'0x7f.1',
		'[::1]',
		'2001:db8::1',
		'co.uk',
		'com',
		'exa mple.com',
		'-bad-.com',
		'under_score.com',
		'a'.repeat(64) + '.com',
		'1.1.1.1.in-addr.arpa',
	])('rejects %j', (input) => {
		expect(normalizeDomain(input)).toBeNull();
	});

	it('rejects non-strings', () => {
		expect(normalizeDomain(undefined)).toBeNull();
		expect(normalizeDomain(42)).toBeNull();
		expect(normalizeDomain({ domain: 'example.org' })).toBeNull();
	});
});
