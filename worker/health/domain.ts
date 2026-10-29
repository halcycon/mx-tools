import { getDomain } from 'tldts-icann';
import { isIpv4 } from '../checks/dns';

/** Special-use / internal suffixes (RFC 6761, RFC 6762, RFC 8375, ICANN `.internal`) plus common private-network names. */
const INTERNAL_SUFFIXES = new Set([
	'arpa',
	'corp',
	'example',
	'home',
	'internal',
	'intranet',
	'invalid',
	'lan',
	'local',
	'localdomain',
	'localhost',
	'onion',
	'private',
	'test',
]);

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Normalise user input (URL, email address, hostname) to a lowercase registrable
 * domain, e.g. `https://www.Example.co.uk/about` → `example.co.uk`.
 * Returns null for IPs, internal names, public suffixes, and malformed input.
 */
export function normalizeDomain(input: unknown): string | null {
	if (typeof input !== 'string') return null;
	let s = input.trim().toLowerCase();
	if (!s || s.length > 512) return null;

	s = s.replace(/^mailto:/, '').replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
	s = s.split(/[/?#]/, 1)[0];
	if (s.includes('@')) s = s.slice(s.lastIndexOf('@') + 1);
	if (s.startsWith('[') || (s.match(/:/g)?.length ?? 0) > 1) return null;
	s = s.replace(/:\d*$/, '').replace(/\.+$/, '');
	if (!s || /\s/.test(s)) return null;

	let host: string;
	try {
		host = new URL(`http://${s}`).hostname;
	} catch {
		return null;
	}
	if (host.startsWith('[') || isIpv4(host)) return null;
	if (host.length > 253) return null;

	const labels = host.split('.');
	if (labels.length < 2 || !labels.every((l) => LABEL.test(l))) return null;
	const tld = labels[labels.length - 1];
	if (/^\d+$/.test(tld) || INTERNAL_SUFFIXES.has(tld)) return null;

	return getDomain(host);
}
