-- Website health-check usage only; never populated by the main diagnostic UI.
CREATE TABLE health_usage (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    requested_at INTEGER NOT NULL,
    client_ip TEXT,
    page_url TEXT,
    referrer TEXT,
    utm_json TEXT NOT NULL,
    outcome TEXT NOT NULL DEFAULT 'started',
    cached INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_health_usage_time ON health_usage(requested_at, id);

-- Progress survives retries; a lease prevents overlapping scheduled handlers.
CREATE TABLE health_usage_digests (
    day TEXT PRIMARY KEY,
    start_at INTEGER NOT NULL,
    end_at INTEGER NOT NULL,
    next_offset INTEGER NOT NULL DEFAULT 0,
    lease_token TEXT,
    lease_until INTEGER NOT NULL DEFAULT 0,
    sent_at INTEGER
);
