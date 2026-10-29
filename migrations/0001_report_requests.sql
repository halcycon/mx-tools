-- Gated full email health reports (POST /api/v1/report-request → confirm → queue → email).
-- Personal data (name, email, organisation) is deleted after RETENTION_DAYS; ip_hash after 24h.

CREATE TABLE report_requests (
	id TEXT PRIMARY KEY,
	token_hash TEXT UNIQUE,               -- sha256 of the confirmation token; NULL once used
	status TEXT NOT NULL,                 -- pending | queued | deferred | sent | failed
	defer_reason TEXT,                    -- domain | email | cap
	name TEXT NOT NULL,
	email TEXT NOT NULL,
	email_hash TEXT NOT NULL,
	organisation TEXT,
	domain TEXT NOT NULL,
	wants_call INTEGER NOT NULL DEFAULT 0,
	ip_hash TEXT,
	created_at INTEGER NOT NULL,          -- unix ms
	expires_at INTEGER NOT NULL,
	confirmed_at INTEGER,
	queued_at INTEGER,                    -- released to the queue (counts against delivery limits)
	completed_at INTEGER,
	report_sent_at INTEGER,
	lead_sent_at INTEGER,
	attempts INTEGER NOT NULL DEFAULT 0,
	overall TEXT,
	score_pass INTEGER,
	score_warn INTEGER,
	score_fail INTEGER,
	used_cache INTEGER,
	used_agent INTEGER
);

CREATE INDEX idx_rr_email_created ON report_requests (email_hash, created_at);
CREATE INDEX idx_rr_email_queued ON report_requests (email_hash, queued_at);
CREATE INDEX idx_rr_ip_created ON report_requests (ip_hash, created_at);
CREATE INDEX idx_rr_domain_queued ON report_requests (domain, queued_at);
CREATE INDEX idx_rr_queued ON report_requests (queued_at);
CREATE INDEX idx_rr_status ON report_requests (status, expires_at);

-- Completed full reports per domain, reused for RESULT_CACHE_HOURS. No personal data.
CREATE TABLE report_results (
	domain TEXT PRIMARY KEY,
	report_json TEXT NOT NULL,
	used_agent INTEGER NOT NULL,
	created_at INTEGER NOT NULL
);

-- One-per-day admin notices (e.g. daily cap reached).
CREATE TABLE notices (
	kind TEXT NOT NULL,
	day TEXT NOT NULL,
	PRIMARY KEY (kind, day)
);
