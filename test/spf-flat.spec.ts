import { describe, it, expect } from 'vitest';
import { parseQuery } from '../worker/checks/types';
import { parseSpfTerms } from '../worker/checks/spf-flat';

describe('SPF flatten parser', () => {
	it('parses mechanisms and modifiers', () => {
		const terms = parseSpfTerms('v=spf1 include:_spf.google.com ip4:1.2.3.4/24 a mx ~all');
		expect(terms.map((t) => t.mech)).toEqual(['include', 'ip4', 'a', 'mx', 'all']);
		expect(terms[0].arg).toBe('_spf.google.com');
		expect(terms[1].arg).toBe('1.2.3.4/24');
		expect(terms[4].qual).toBe('~');
	});

	it('parses redirect=', () => {
		const terms = parseSpfTerms('v=spf1 redirect=_spf.example.com');
		expect(terms[0]).toMatchObject({ mech: 'redirect', arg: '_spf.example.com' });
	});
});

describe('parseQuery aliases', () => {
	it('accepts spf-flat and flatten', () => {
		expect(parseQuery('spf-flat:example.com')).toEqual({ tool: 'spf-flat', target: 'example.com' });
		expect(parseQuery('flatten:example.com')).toEqual({ tool: 'spf-flat', target: 'example.com' });
	});
});
