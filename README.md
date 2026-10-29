# mx-tools

Private integrated diagnostic tool: DNS, mail authentication, blacklists, RDAP, and connectivity checks — with a reactive web UI (Cloudflare Worker) and a Charm Bracelet Bubble Tea CLI/TUI.

## Features

| Command | Description | Web (Worker) | CLI |
|---------|-------------|--------------|-----|
| _(bare input)_ | Domain health report (live progress): MX + SPF + DMARC + blacklist + SOA | ✓ | ✓ |
| `full` | Email health report (live progress): mail auth, DNS, blacklist, HTTPS, RDAP | ✓ | ✓ |
| `a` `aaaa` `cname` `mx` `ns` `ptr` `soa` `txt` | DNS lookups | ✓ | ✓ |
| `spf` `spf-flat` `dmarc` `dkim` `bimi` `mta-sts` `tlsrpt` | Email auth / SPF flattening / reporting | ✓ | ✓ |
| `headers` | Parse pasted RFC 5322 headers (hops, auth, spam scores) | ✓ | ✓ |
| `blacklist` | Multi-DNSBL reputation | ✓ | ✓ |
| `dns` | Nameserver health | ✓ | ✓ |
| `whois` `arin` `asn` | RDAP / Cymru ASN | ✓ | ✓ |
| `http` `https` `tcp` | Connectivity | ✓* | ✓ |
| `smtp` | SMTP banner: **587** STARTTLS + **465** SMTPS on the Worker; CLI also probes **25** (MX) | ✓ | ✓ |
| `ping` `trace` | ICMP | ✗ | ✓ |

\* Outbound **port 25** is blocked on Cloudflare Workers ([TCP sockets](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/)). Submission **587** (STARTTLS) and **465** (implicit TLS) are allowed. The Worker never authenticates. Use the CLI for inbound port 25. Submission usually lives on an MSA host (`smtp.example.com`), not the MX.

`spf-flat:` (alias `flatten:`) expands `include` / `a` / `mx` into `ip4`/`ip6` and counts RFC 7208 DNS lookups. It does **not** publish DNS for you — copy the flattened record if you choose to use it, and re-run after ESP IP changes.

Health reports can **Save baseline** in this browser (problem IDs for that host). Re-run later to see new vs resolved findings. That is local change detection, not a hosted monitor.

These commercial extras are out of scope here: inbox placement (needs seed mailboxes), recipient complaint / FBL feeds, ESP delivery telemetry, and SMTP round-trip latency from Workers.

Header analyzer: paste a header dump in the web UI (**Header analyzer** tool). Parsing runs in the browser. CLI: `mx --once headers message.eml` or `mx --json headers < headers.txt`. Optional API: `POST /api/headers` with `{ "raw": "..." }`.

## Web (Cloudflare Worker + SPA)

```bash
npm install
npm run dev          # Vite UI :5173 + Worker API :8787
# or
npm start            # build SPA + wrangler dev (single origin)
npm run deploy       # build + wrangler deploy
```

Open the UI, pick a tool (or leave **Domain health**), enter a host, and results stream in via SSE.

### Cloudflare deployment (Worker + static assets)

This project deploys the React app as **static assets served from the same Worker** (no Pages split). It keeps configuration simple and makes local dev match production.

1. Create a Cloudflare account (Workers enabled).
2. Install Wrangler:
   - `npm i -g wrangler` (or use `npx wrangler`)
3. Authenticate:
   - `npx wrangler login`
4. Deploy:
   - `npm install`
   - `npm run deploy`

After deploy, Cloudflare will print the Worker URL.

### Cloudflare Git-linked Worker settings

If you connect this repository directly to **Cloudflare Workers Builds** and want redeploys on every push:

- **Product**: Workers
- **Repository**: `halcycon/mx-tools`
- **Production branch**: `main`
- **Root directory**: repository root (`/`) or leave blank
- **Build command**: `npm run build` (Cloudflare already runs `npm ci` before this)
- **Deploy command**: `npx wrangler deploy`
- **Non-production branch deploy command**: leave default, or `npx wrangler versions upload`

Why these settings work:

- `vite build` outputs the SPA into `dist/`
- `wrangler.jsonc` points `assets.directory` at `./dist`
- the Worker entrypoint is `worker/index.ts`
- `/api/*` requests hit the Worker first, while everything else is served as static SPA assets

This is already the recommended layout for the repo, so **do not split this into Pages + Worker** unless you specifically want separate frontend/backend projects. A single Worker keeps deploys, routing, and local dev simpler.

### Optional Cloudflare dashboard settings

- **Preview URLs**: enabled in `wrangler.jsonc`
- **Observability**: enabled in `wrangler.jsonc`
- **Custom domain**: add after the first successful deploy

## Public health-check API (`POST /api/v1/health-check`)

Stable JSON endpoint used by the free “email health check” on [thecuckoocamp.co.uk](https://www.thecuckoocamp.co.uk). It runs the `full:` email checks (minus WHOIS/ASN/ARIN) and returns **facts and stable codes only**. All plain-English wording lives on the website.

```bash
curl -s https://dart.thecuckoocamp.co.uk/api/v1/health-check \
  -H 'content-type: application/json' \
  -H 'origin: https://www.thecuckoocamp.co.uk' \
  -d '{"domain":"example.org","turnstileToken":"<token from the Turnstile widget>"}'
```

Response `200`:

```json
{
  "domain": "example.org",
  "checkedAt": "2026-11-03T08:00:00Z",
  "score": { "pass": 6, "warn": 2, "fail": 1 },
  "overall": "fail",
  "checks": [
    {
      "id": "dmarc",
      "status": "fail",
      "code": "dmarc_policy_none",
      "facts": { "record": "v=DMARC1; p=none", "policy": "none", "subdomainPolicy": null, "pct": 100, "rua": null, "ruf": null },
      "technical": "v=DMARC1; p=none"
    }
  ]
}
```

`checks[]` is always ordered `spf, dmarc, dkim, mx, mta-sts, tlsrpt, blacklist, bimi, dns, https`. `score` counts `pass`/`warn`/`fail` only. `info` results are neutral. `overall` is `fail` if any check fails, otherwise `warn` if any warns, otherwise `pass`.

| Status | Body |
|--------|------|
| 400 | `{ "error": "invalid_domain" }`: not a public registrable domain, or the body is not JSON |
| 403 | `{ "error": "turnstile_failed" }`: missing, invalid, or reused Turnstile token (fails closed if `TURNSTILE_SECRET` is unset) |
| 429 | `{ "error": "rate_limited" }` (+ `Retry-After: 60`) |
| 502 | `{ "error": "upstream_timeout", "partial": <same shape> }`: the ~15 s deadline passed; `partial.checks` holds only the checks that finished |

**Input.** The endpoint accepts URLs, email addresses, or hostnames and reduces them to the lowercase registrable domain via the Public Suffix List (`https://www.Charity.org.uk/about` → `charity.org.uk`, `treasurer@charity.org.uk` → `charity.org.uk`). It rejects IPs, bare public suffixes (`co.uk`), and internal or special-use names (`.local`, `.lan`, `.internal`, `.test`, …). The normalised domain is echoed back in `domain`.

**Behaviour.**
- All checks run in parallel, with per-fetch timeouts and a 15 s overall deadline.
- DKIM tries the selectors `default, google, selector1, selector2, k1, s1, mail`.
- HTTPS tries the apex first, then `www.` if the apex can't be reached.
- The blacklist check skips lists that never answer through public DoH (NJABL, WPBL, SpamRats). It treats DNSBL query errors, SERVFAIL, timeouts, and answers outside `127.0.0.0/8` as **inconclusive**, never as listed. Without a DQS key Spamhaus (and CBL, which Spamhaus now serves) always refuse DoH, so expect `blacklist_inconclusive` with `facts.listed: []`. The public endpoint never uses browser-supplied keys.

**Caching and logs.**
- Complete results are cached per domain for 10 minutes: Cache API, plus an in-isolate fallback because the Cache API is inactive on `workers.dev`. Partial results are never cached.
- Logs carry the domain, outcome, and counts only. Client IPs are only used as a hashed rate-limit key.

**CORS.** Allowed origins are `https://www.thecuckoocamp.co.uk` and `https://thecuckoocamp.co.uk`. Set `HEALTH_CHECK_ALLOW_DEV_ORIGINS="true"` (in `.dev.vars` or `wrangler.jsonc` `vars`) to also allow `http://localhost:1313` for Hugo dev. Other API routes keep `*`.

**Rate limit.** The `HEALTH_CHECK_RATE_LIMITER` binding allows 3 checks per 60 s per client IP, per Cloudflare location. The binding only supports 10 s or 60 s windows, so this is the closest to “10 per 10 minutes” while still allowing a short burst. Counts are approximate (see [docs](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)).

**Setup.**

```bash
npx wrangler secret put TURNSTILE_SECRET     # Turnstile widget secret key
# Local dev: put Cloudflare's always-pass test secret in .dev.vars
#   TURNSTILE_SECRET=1x0000000000000000000000000000000AA
```

Custom domain: Workers → mx-tools → Settings → Domains & Routes → add `dart.thecuckoocamp.co.uk`. The Cache API only works on custom domains.

### Health-check codes

Codes are stable. They are only ever added, never renamed. Where several apply, the first matching row in each group wins.

| Check | Code | Status | Meaning / key `facts` |
|-------|------|--------|-----------------------|
| spf | `spf_missing` | fail | No `v=spf1` TXT record |
| spf | `spf_multiple` | fail | More than one SPF record (invalid). `records[]` |
| spf | `spf_pass_all` | fail | Ends `+all`: anyone may send as the domain |
| spf | `spf_too_many_lookups` | fail | More than 10 DNS-lookup mechanisms after flattening. `lookups`, `lookupLimit` |
| spf | `spf_softfail_all` | warn | Ends `~all` |
| spf | `spf_neutral_all` | warn | `?all` or no `all` at all |
| spf | `spf_pass_hardfail` | pass | Valid and ends `-all`. `record`, `all`, `lookups` |
| dmarc | `dmarc_missing` | fail | No `_dmarc` record |
| dmarc | `dmarc_invalid` | fail | Record without a valid `p=` |
| dmarc | `dmarc_policy_none` | fail | `p=none` (monitoring only) |
| dmarc | `dmarc_no_rua` | warn | `p=quarantine`/`reject` but no `rua=` aggregate reports. Check `facts.policy` |
| dmarc | `dmarc_policy_quarantine` | warn | `p=quarantine` with `rua` |
| dmarc | `dmarc_policy_reject` | pass | `p=reject` with `rua`. Facts: `policy`, `subdomainPolicy`, `pct`, `rua`, `ruf`, `record` |
| dkim | `dkim_found` | pass | A key on at least one common selector. `found[{selector, record}]` |
| dkim | `dkim_not_found_common_selectors` | info | None of the common selectors has a key (a custom selector may still exist). `selectorsChecked`, `revoked` |
| mx | `mx_missing` | fail | No MX records |
| mx | `mx_unresolved` | warn | An MX host has no A/AAAA |
| mx | `mx_null` | info | Null MX (`0 .`): the domain explicitly receives no mail |
| mx | `mx_ok` | pass | `hosts[{preference, host, ips, resolves}]` |
| mta-sts | `mtasts_missing` | info | No `_mta-sts` TXT |
| mta-sts | `mtasts_policy_error` | warn | TXT present but the policy file can't be fetched or has no valid `mode`. `policyUrl`, `httpStatus`, `policyError` |
| mta-sts | `mtasts_none` | info | `mode: none` |
| mta-sts | `mtasts_testing` | info | `mode: testing` |
| mta-sts | `mtasts_enforce` | pass | `mode: enforce`. `maxAge`, `mx[]` |
| tlsrpt | `tlsrpt_missing` | info | No `_smtp._tls` record |
| tlsrpt | `tlsrpt_ok` | pass | `record`, `rua` |
| blacklist | `blacklist_listed` | fail | A genuine listing code (`127.0.0.0/8`, not `127.0.0.1` or `127.255.255.x`). `listed[{list, ip, role, codes}]` |
| blacklist | `blacklist_inconclusive` | info | No listings, but some lists refused, failed, or gave unexpected answers. `inconclusive[{list, ip, reason}]`, where reason is `query_refused`, `lookup_failed`, or `unexpected_answer` |
| blacklist | `blacklist_no_ips` | info | No mail or web IPs to check |
| blacklist | `blacklist_clean` | pass | `checkedIps`, `listsChecked`, `spamhausDqs` |
| bimi | `bimi_missing` | info | No `default._bimi` record |
| bimi | `bimi_ok` | pass | `record`, `logo`, `authority` |
| dns | `dns_no_nameservers` | fail | No NS records (domain probably doesn't exist) |
| dns | `dns_single_ns` | warn | Only one nameserver |
| dns | `dns_ns_unresolved` | warn | A nameserver has no address |
| dns | `dns_ok` | pass | `nameservers[{host, ips, resolves}]`, `count`, `soaSerial` |
| https | `https_fail` | fail | Neither apex nor `www.` answers over HTTPS. `apex.error`, `www.error` |
| https | `https_http_error` | warn | Reachable but returns HTTP 4xx/5xx |
| https | `https_www_only` | warn | Apex unreachable but `www.` works (visitors typing the bare domain get an error) |
| https | `https_ok` | pass | Apex answers 2xx/3xx. `apex{url, status, location}` |
| any | `check_error` | info | The check itself failed (lookup error). `facts.reason` |

### VPS agent as the health-check backend

Cloudflare egress IPs and public resolvers are refused by Spamhaus (and several other lists). When `AGENT_URL` plus `AGENT_HMAC_SECRET` (or `AGENT_TOKEN`) are set, the public health check gets its blacklist results from `mx agent` on the VPS (`POST /api/v1/probe`, quick mode, 7 s budget). If the agent is unreachable it falls back to the Worker's DoH scan. `facts.source` is `agent` or `worker`. Everything else runs on the Worker. The public endpoint never holds the Spamhaus DQS key: it stays on the agent.

## Gated full report (`POST /api/v1/report-request` → `GET /api/v1/report-confirm`)

The full report is not a public tool. It runs only after the requester proves they own the email address, and is emailed to them via Cloudflare Email Sending. Adam gets a lead notification.

1. The website POSTs `{ name, email, organisation?, domain, wantsCall | discoveryCall, consent: true, turnstileToken }`. The request needs the same CORS allowlist, Turnstile, and domain rules as the health check. Disposable-inbox domains are rejected (small built-in list).
2. The Worker checks limits, stores a **pending** row in D1 (only a SHA-256 of the token is kept), and emails a single-use confirmation link that expires after 24 h. Response `202 { "ok": true, "delayed": false }`.
3. `GET /api/v1/report-confirm?token=…` consumes the token and redirects (303) to `SITE_URL/health-check/thanks/?status=confirmed|delayed|expired|invalid`. If delivery limits allow, the request is enqueued; otherwise it's **deferred**.
4. The queue consumer reuses a full result for the domain from the last 24 h, or runs the full suite. That is the `full:` checks plus wider DKIM selector discovery, plus the agent's **full** probe: DNSBL via its resolver + DQS, PTR/FCrDNS for MX IPs, and SMTP 25 (MX) / 587 / 465 (submission host via SRV or `smtp.`/`mail.`) with banner, STARTTLS, TLS version, and certificate validity and expiry. It emails the report (HTML + text, `Reply-To: REPLY_TO`), then the lead to `LEAD_NOTIFY_TO` (`Reply-To:` the requester). Each step is recorded, so retries never double-send.
5. Retries: up to 3 (`max_retries: 3`, backoff 30/60/120 s). On final failure the requester gets a short apology and Adam a failure notice.
6. Cron (`*/15 * * * *`): retention cleanup, and release of deferred requests once limits allow.

Errors: `400 { error: invalid_request | invalid_name | invalid_email | invalid_domain | invalid_organisation | consent_required, fields: { <field>: "invalid" } }`, `403 turnstile_failed`, `429 { error: "rate_limited", retryAfter }` (+ `Retry-After`), `502 email_failed`.

**Limits** (all Worker vars, defaults in `worker/report/config.ts`). They are enforced before any email is sent. A `429` is the same whichever rule tripped, and never says whether a domain or address was seen before.

| Var | Default | Rule |
|-----|---------|------|
| `REPORT_IP_PER_HOUR` / `REPORT_IP_PER_DAY` | 5 / 10 | Report requests per client IP (hashed) |
| `REPORT_EMAIL_PENDING_PER_DAY` | 5 | Requests per recipient address in 24 h |
| `REPORT_EMAIL_CONFIRMED_PER_DAY` | 3 | Delivered reports per address in 24 h |
| `REPORT_DOMAIN_PER_HOUR` / `REPORT_DOMAIN_PER_DAY` | 1 / 3 | Delivered reports per domain (cached results are reused within 24 h) |
| `CONFIRM_EMAIL_COOLDOWN_MINUTES` | 10 | One confirmation email per address. Repeats get the same `202` and no email |
| `DAILY_REPORT_CAP` | 200 | Global. Over the cap, requests are still accepted (`delayed: true`), confirmations are deferred (`status=delayed`), and Adam is told once a day |
| `TOKEN_TTL_HOURS` | 24 | Confirmation link lifetime |
| `RESULT_CACHE_HOURS` | 24 | Reuse of a completed agent-backed result per domain |
| `RETENTION_DAYS` | 90 | Requests (name, email, organisation) are deleted after this. IP hashes after 24 h, expired pending rows straight away |

Request and confirmation limits are checked again at confirm time, because several pending links can be confirmed at once.

**Wording.** The report's plain-English text comes from the website's own file (`cuckoo-site/data/healthcheck.yaml`). `npm run build` runs `scripts/sync-wording.mjs`, which fetches `WORDING_URL` (default `https://www.thecuckoocamp.co.uk/health-check/wording.json`) into `worker/report/wording.json`. If the fetch fails, the last snapshot is kept. To seed it locally, run `node scripts/sync-wording.mjs --yaml ../cuckoo-site/data/healthcheck.yaml`. Optional per-code `why` and `fix` fields render as "Why it matters" and "What to do".

**Observability.** `{"event":"report","action":…}` logs cover these actions:
- `requested`, `invalid`, `turnstile_failed`, `rate_limited` (with rule), `confirmation_cooldown`
- `confirmed`, `confirm_rejected`, `queued`, `deferred`
- `report_sent`, `lead_sent`, `retry`, `failed`, `cron`

`agent_probe` logs status and ms only. No names, emails, domains, IPs, tokens, or secrets are logged.

### Full-report codes (in addition to the health-check codes)

| Check | Code | Status | Meaning / key `facts` |
|-------|------|--------|-----------------------|
| smtp | `smtp_unreachable` | fail | No MX accepted a connection on port 25 |
| smtp | `cert_expired` | fail | A mail-server certificate (25/587/465) has expired |
| smtp | `smtp_starttls_missing` | warn | An MX doesn't offer STARTTLS |
| smtp | `smtp_tls_failed` | warn | STARTTLS / implicit TLS handshake failed |
| smtp | `smtp_cert_invalid` | warn | Certificate doesn't validate (untrusted chain or wrong hostname). `cert.verifyError` |
| smtp | `cert_expiring_soon` | warn | A certificate expires within 21 days. `cert.daysLeft` |
| smtp | `smtp_not_checked` | info | Agent unavailable, port 25 egress blocked, or no MX. `reason` |
| smtp | `smtp_ok` | pass | `probes[{host, port, role, banner, startTls, tls, tlsVersion, cert}]`, `egress` |
| ptr | `ptr_missing` | warn | An MX IP has no reverse DNS |
| ptr | `ptr_mismatch` | warn | Reverse DNS doesn't resolve back to the IP (FCrDNS fails) |
| ptr | `ptr_not_checked` | info | Lookups failed or no MX IPs. `reason` |
| ptr | `ptr_ok` | pass | `addresses[{ip, role, ptr, forward, fcrdns}]`, `source` |

The full report's `checks[]` uses the same shape, adding `smtp` and `ptr` after the public ten.

### Full-report setup

```bash
npx wrangler d1 migrations apply mx-tools-reports --remote   # npm run db:migrate
npx wrangler secret put TURNSTILE_SECRET
npx wrangler secret put LEAD_NOTIFY_TO        # Adam's lead inbox
npx wrangler secret put REPLY_TO              # Reply-To on reports
npx wrangler secret put AGENT_URL             # e.g. https://dart-agent.thecuckoocamp.co.uk
npx wrangler secret put AGENT_HMAC_SECRET     # same value as MX_AGENT_HMAC_SECRET on the VPS
npx wrangler secret put AGENT_CLIENT_ID       # Cloudflare Access service token (optional, recommended)
npx wrangler secret put AGENT_CLIENT_SECRET
```

`REPORT_FROM` must be on an Email Sending domain (`thecuckoocamp.co.uk` is onboarded). The `EMAIL` binding only allows that sender.

**VPS agent (Hetzner).**

```bash
# Local recursive resolver so DNSBL queries come from the VPS IP, not a shared resolver
sudo apt install unbound
export SPAMHAUS_DQS_KEY=…            # stays on the VPS
export MX_AGENT_HMAC_SECRET=$(openssl rand -hex 32)
./mx agent --listen 127.0.0.1:8788 --resolver 127.0.0.1 --token "$(openssl rand -hex 24)"
# cloudflared tunnel: dart-agent.thecuckoocamp.co.uk → http://127.0.0.1:8788,
# protected by an Access application with a Service Auth policy for the Worker's service token.
```

- With `MX_AGENT_HMAC_SECRET` set, `/api/v1/probe` only accepts HMAC-signed requests: `x-mx-timestamp` plus `x-mx-signature` = HMAC-SHA256 of `ts\nPOST\n/api/v1/probe\nsha256(body)`. Signatures older than ±5 min or already used are rejected.
- The agent only dials public IPs, so a hostile MX record can't point it at the VPS's own network.
- `--resolver` defaults to `system` in agent mode. The CLI keeps 1.1.1.1.
- Hetzner blocks outbound **25** and **465** on new Cloud servers until you request an unblock. The agent self-tests port-25 egress (cached 10 min) and reports `smtp_not_checked` with `reason: egress_blocked` instead of marking every domain unreachable.

## CLI / TUI

```bash
cd cli && go mod tidy
go build -o ../bin/mx .
../bin/mx                     # interactive TUI
../bin/mx example.com         # TUI + auto-run
../bin/mx --once mx:gmail.com
../bin/mx --json spf:github.com
```

Requires Go 1.22+. `ping` / `traceroute` shell out to system binaries.

Spamhaus public mirrors return **query errors** (not listings) when asked via open resolvers such as 1.1.1.1 — notably `127.255.255.254`. D.A.R.T. labels those as query errors. For a **private** instance, set a DQS key:

```bash
# Worker (private deploy)
npx wrangler secret put SPAMHAUS_DQS_KEY

# CLI
export SPAMHAUS_DQS_KEY=your-key
```

The web UI Settings panel can also store a key in **this browser only** and send it as `x-spamhaus-dqs-key`. Do not paste keys into a public deployment.

### Local probe agent (recommended for DNSBL)

Spamhaus (and some other lists) reject queries that arrive via public/open resolvers such as Cloudflare DoH. Run the CLI as a small HTTP agent on your laptop or mail network so lookups use **local DNS / egress**:

```bash
cd cli && go build -o ../bin/mx .
# token printed if omitted; or:
export MX_AGENT_TOKEN=$(openssl rand -hex 24)
# optional DQS — stays on this host, never uploaded to the Worker
export SPAMHAUS_DQS_KEY=your-key
../bin/mx agent --listen 127.0.0.1:8788 --token "$MX_AGENT_TOKEN"
```

In the web UI: **Settings → Probe agent** → URL `http://127.0.0.1:8788` + token → **Test connection** → Save. Lookups then hit the agent (SSE-compatible `/api/lookup`). Bind non-loopback only with `--allow-lan`.

From an `https://` hosted UI, some browsers block `http://127.0.0.1` (mixed content). Prefer `npm start` locally, or `ssh -L 8788:127.0.0.1:8788 user@mailhost` and point Settings at loopback.

## Query syntax

Command prefixes with `tool:target` (optional extra segments for tools like DKIM):

```
example.com
mx:example.com
blacklist:1.2.3.4
dkim:selector:example.com
tcp:example.com:443
spf-flat:example.com
headers
smtp:example.com
smtp:smtp.gmail.com:587
full:example.com
```

## Layout

```
worker/          Cloudflare Worker API + check engine (TypeScript)
web/             React + Vite D.A.R.T. UI
cli/             Go Bubble Tea TUI + local check engine + `mx agent`
dist/            Built static assets (gitignored)
```

Both engines share the same command set and JSON-shaped results (`tool`, `rows[]`, `summary`, …).

## Private use

Intended for personal / internal diagnostics. Respect DNSBL and RDAP provider terms; avoid rapid repeated queries.
