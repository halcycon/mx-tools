/** Tunable limits — every value can be overridden with a Worker var of the same name. */
export const LIMIT_DEFAULTS = {
	REPORT_DOMAIN_PER_HOUR: 1,
	REPORT_DOMAIN_PER_DAY: 3,
	REPORT_EMAIL_CONFIRMED_PER_DAY: 3,
	REPORT_EMAIL_PENDING_PER_DAY: 5,
	REPORT_IP_PER_HOUR: 5,
	REPORT_IP_PER_DAY: 10,
	CONFIRM_EMAIL_COOLDOWN_MINUTES: 10,
	DAILY_REPORT_CAP: 200,
	TOKEN_TTL_HOURS: 24,
	RESULT_CACHE_HOURS: 24,
	RETENTION_DAYS: 90,
} as const;

export type Limits = { -readonly [K in keyof typeof LIMIT_DEFAULTS]: number };
export type LimitEnv = Partial<Record<keyof typeof LIMIT_DEFAULTS, string>>;

export function readLimits(env: LimitEnv): Limits {
	const out = { ...LIMIT_DEFAULTS } as Limits;
	for (const key of Object.keys(LIMIT_DEFAULTS) as Array<keyof Limits>) {
		const raw = env[key];
		if (raw === undefined || raw === '') continue;
		const n = Number(raw);
		if (Number.isFinite(n) && n >= 0) out[key] = n;
	}
	return out;
}

export type ReportEnv = LimitEnv & {
	DB: D1Database;
	REPORT_QUEUE: Queue<ReportJob>;
	EMAIL: SendEmail;
	/** e.g. reports@thecuckoocamp.co.uk (must be on an Email Sending domain). */
	REPORT_FROM?: string;
	REPORT_FROM_NAME?: string;
	REPLY_TO?: string;
	LEAD_NOTIFY_TO?: string;
	SITE_URL?: string;
	BOOKING_URL?: string;
};

export type ReportJob = { id: string };

export const HOUR = 3_600_000;
export const DAY = 24 * HOUR;
export const MINUTE = 60_000;
