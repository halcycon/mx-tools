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
      "status": "warn",
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
| dmarc | `dmarc_policy_none` | warn | `p=none` (monitoring only) |
| dmarc | `dmarc_no_rua` | warn | `p=quarantine`/`reject` but no `rua=` aggregate reports. Check `facts.policy` |
| dmarc | `dmarc_policy_quarantine` | pass | `p=quarantine` with `rua` |
| dmarc | `dmarc_policy_reject` | pass | `p=reject` with `rua`. Facts: `policy`, `subdomainPolicy`, `pct`, `rua`, `ruf`, `record` |
| dkim | `dkim_found` | pass | A key on at least one common selector. `found[{selector, record}]` |
| dkim | `dkim_not_found_common_selectors` | warn | None of the common selectors has a key (a custom selector may still exist). `selectorsChecked`, `revoked` |
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
