import { describe, expect, it } from 'vitest';
import { isCloudflareIPv4, selectBlacklistIps } from '../worker/checks/cloudflare-ips';

describe('Cloudflare proxy detection', () => {
	it('recognizes Cloudflare anycast A records', () => {
		expect(isCloudflareIPv4('104.21.64.109')).toBe(true);
		expect(isCloudflareIPv4('1.1.1.1')).toBe(false);
		expect(isCloudflareIPv4('8.8.8.8')).toBe(false);
	});

	it('skips Cloudflare website A when MX IPs exist', () => {
		const { check, skipped } = selectBlacklistIps(
			['104.21.64.109'],
			[{ host: 'mail.example.com', ips: ['203.0.113.10'] }],
		);
		expect(check.map((a) => a.ip)).toEqual(['203.0.113.10']);
		expect(skipped.map((a) => a.ip)).toEqual(['104.21.64.109']);
	});

	it('checks website A when there is no MX', () => {
		const { check, skipped } = selectBlacklistIps(['104.21.64.109'], []);
		expect(check.map((a) => a.ip)).toEqual(['104.21.64.109']);
		expect(skipped).toHaveLength(0);
	});
});
