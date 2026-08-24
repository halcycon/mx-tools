/** Common public DNSBLs. */

export type Dnsbl = {
	zone: string;
	name: string;
	url?: string;
};

export const DNSBLS: Dnsbl[] = [
	{ zone: 'zen.spamhaus.org', name: 'Spamhaus ZEN', url: 'https://www.spamhaus.org/lookup/' },
	{ zone: 'bl.spamcop.net', name: 'SpamCop', url: 'https://www.spamcop.net/bl.shtml' },
	{ zone: 'b.barracudacentral.org', name: 'Barracuda', url: 'https://barracudacentral.org/lookups' },
	{ zone: 'dnsbl.sorbs.net', name: 'SORBS', url: 'http://www.sorbs.net/' },
	{ zone: 'spam.dnsbl.sorbs.net', name: 'SORBS Spam' },
	{ zone: 'psbl.surriel.com', name: 'PSBL', url: 'https://psbl.org/' },
	{ zone: 'dnsbl.dronebl.org', name: 'DroneBL', url: 'https://dronebl.org/' },
	{ zone: 'rbl.interserver.net', name: 'InterServer' },
	{ zone: 'dnsbl-1.uceprotect.net', name: 'UCEPROTECT L1' },
	{ zone: 'cbl.abuseat.org', name: 'CBL Abuseat', url: 'https://www.abuseat.org/' },
	{ zone: 'dyna.spamrats.com', name: 'SpamRats Dyna' },
	{ zone: 'noptr.spamrats.com', name: 'SpamRats NoPTR' },
	{ zone: 'spam.spamrats.com', name: 'SpamRats Spam' },
	{ zone: 'z.mailspike.net', name: 'Mailspike Z' },
	{ zone: 'bl.mailspike.net', name: 'Mailspike BL' },
	{ zone: 'db.wpbl.info', name: 'WPBL' },
	{ zone: 'dnsbl.spfbl.net', name: 'SPFBL' },
	{ zone: 'all.s5h.net', name: 'S5H' },
	{ zone: 'bhnc.njabl.org', name: 'NJABL' },
	{ zone: 'combined.abuse.ro', name: 'Abuse.ro' },
	{ zone: 'bl.blocklist.de', name: 'Blocklist.de', url: 'https://www.blocklist.de/' },
	{ zone: 'list.dnswl.org', name: 'DNSWL (whitelist)' },
];
