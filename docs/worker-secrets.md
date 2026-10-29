# Worker secrets and configuration

Everything the `mx-tools` Worker reads from its environment, what each value must be, and where it comes from. This repository is **public**, so secrets live only in Cloudflare (Worker secrets), on the VPS (the agent's `.env` in Arcane), or in your local `.dev.vars`. Never put them in `wrangler.jsonc` or commit them.

## Setting a secret

```bash
npx wrangler secret put NAME          # prompts for the value
npx wrangler secret list              # names only, never values
```

If Wrangler says *"the latest version of your Worker isn't currently deployed"* (a PR branch uploaded a preview version), use the version-aware form instead. Later versions inherit the secret:

```bash
npx wrangler versions secret put NAME
```

You can also set them in the dashboard: **Workers & Pages → mx-tools → Settings → Variables and Secrets → Add → Type: Secret**.

## Secrets

| Secret | Needed for | Value | Where it comes from | If missing or wrong |
|--------|-----------|-------|---------------------|-------------------|
| `TURNSTILE_SECRET` | `/api/v1/health-check`, `/api/v1/report-request` | Turnstile **secret key** (starts `0x4…`) | Cloudflare dashboard → **Turnstile** → your widget → **Settings** → Secret key. The site key (public) goes in the website's `hugo.toml` | Every request gets `403 turnstile_failed` (fails closed) |
| `AGENT_URL` | Accurate blacklist in the public check; DNSBL/SMTP/PTR in the full report | Base URL of the VPS agent, no path, e.g. `https://dart-agent.thecuckoocamp.co.uk` | The Tunnel public hostname you created ([`deploy/agent/README.md`](../deploy/agent/README.md)) | Agent unused. The public check falls back to the Worker (`facts.source: "worker"`, usually `blacklist_inconclusive`). The full report shows SMTP as `smtp_not_checked` and falls back for blacklist and PTR |
| `AGENT_HMAC_SECRET` | Signing every probe request | 64 hex characters (`openssl rand -hex 32`) | You generate it. **Must equal `MX_AGENT_HMAC_SECRET`** in the agent's `.env` | Agent answers `401` → Worker falls back as above |
| `AGENT_CLIENT_ID` | Getting through Cloudflare Access in front of the agent | Service token Client ID, e.g. `1a2b3c….access` | Zero Trust → **Access → Service credentials → Service Tokens** → Create | Access returns `403` → Worker falls back |
| `AGENT_CLIENT_SECRET` | Same | Service token Client Secret (64 hex) | Shown **once** when you create the service token | Same as above |
| `LEAD_NOTIFY_TO` | Lead notifications, failure notices, daily-cap notice | Your inbox, e.g. `adam@thecuckoocamp.co.uk` | You choose | Reports still go to requesters, but you get no leads or alerts |
| `REPLY_TO` | `Reply-To` on report and confirmation emails | The address requesters should reply to | You choose | Replies go to `REPORT_FROM` (`reports@…`), which may not be monitored |

### Optional or legacy

| Secret | Use | Advice |
|--------|-----|--------|
| `AGENT_TOKEN` | Bearer auth to the agent, used **only if `AGENT_HMAC_SECRET` is not set** | Prefer HMAC. If used, it must equal the agent's `MX_AGENT_TOKEN` |
| `SPAMHAUS_DQS_KEY` | Only the private D.A.R.T. web UI (`/api/lookup`) | **Don't set this on the public Worker.** The `/api/v1/*` endpoints never use it. Put the key in the agent's `.env` instead, so it stays on the VPS |

## The matching VPS values (agent `.env` in Arcane)

| Agent `.env` | Must match |
|--------------|-----------|
| `MX_AGENT_HMAC_SECRET` | Worker `AGENT_HMAC_SECRET` |
| `MX_AGENT_TOKEN` | Worker `AGENT_TOKEN`, only if you use bearer auth. Otherwise just a random value for the agent's interactive endpoints |
| `SPAMHAUS_DQS_KEY` | Your Spamhaus DQS key (lives only here) |
| `CLOUDFLARE_TUNNEL_TOKEN` | The tunnel's connector token. Not used by the Worker |

The Access service token (`AGENT_CLIENT_ID` / `AGENT_CLIENT_SECRET`) is **not** needed on the VPS. Cloudflare Access checks it at the edge, before requests reach the tunnel.

## Plain variables (in `wrangler.jsonc`, not secret)

These are committed and deployed with the code. Change them in `wrangler.jsonc`; dashboard edits are overwritten on the next deploy.

| Var | Default | Meaning |
|-----|---------|---------|
| `REPORT_FROM` | `reports@thecuckoocamp.co.uk` | Sender for all report emails. Must be on an Email Sending domain; the `EMAIL` binding only allows this address |
| `REPORT_FROM_NAME` | `The Cuckoo Camp` | Sender display name |
| `SITE_URL` | `https://www.thecuckoocamp.co.uk` | Confirm links redirect to `SITE_URL/health-check/thanks/?status=…` |
| `BOOKING_URL` | `https://www.thecuckoocamp.co.uk/contact/` | "Book your free 20-minute call" button |
| `HEALTH_CHECK_ALLOW_DEV_ORIGINS` | `false` | `true` also allows `http://localhost:1313` (Hugo dev) through CORS |
| `REPORT_*`, `CONFIRM_EMAIL_COOLDOWN_MINUTES`, `DAILY_REPORT_CAP`, `TOKEN_TTL_HOURS`, `RESULT_CACHE_HOURS`, `RETENTION_DAYS` | see README | Full-report rate limits and retention ([README](../README.md), "Limits") |

## Bindings (no action needed)

Declared in `wrangler.jsonc` and created already: `DB` (D1 `mx-tools-reports`), `REPORT_QUEUE` (Queue `mx-tools-reports`), `EMAIL` (Email Sending), `HEALTH_CHECK_RATE_LIMITER`, `ASSETS`. After a schema change, run `npm run db:migrate`.

## Checking it's all wired up

```bash
npx wrangler secret list
# expect: TURNSTILE_SECRET, AGENT_URL, AGENT_HMAC_SECRET, AGENT_CLIENT_ID, AGENT_CLIENT_SECRET, LEAD_NOTIFY_TO, REPLY_TO
npx wrangler tail --format pretty      # then run a check on the website
```

In the tail:

- `{"event":"agent_probe","status":200,"ok":true}`: the agent is reachable. A `status` of `401` means the HMAC secrets don't match. A `403` (from Access) means the service token is wrong. `0` means the URL, tunnel or DNS is wrong.
- `{"event":"health_check","outcome":"ok",…}`: the check completed. `outcome":"turnstile_failed"` means the site key and secret are from different widgets.

## Rotating

- **HMAC:** change `MX_AGENT_HMAC_SECRET` in Arcane and redeploy, then immediately `wrangler secret put AGENT_HMAC_SECRET`. Between the two, checks fall back to Worker-only results; nothing fails outright.
- **Access service token:** create a new token, add it to the Access policy, update both Worker secrets, then delete the old token.
- **Turnstile:** rotating the secret in the Turnstile dashboard keeps the old one valid for a grace period. Update `TURNSTILE_SECRET` within it.

## Local development

Copy [`.dev.vars.example`](../.dev.vars.example) to `.dev.vars` (gitignored). It uses Cloudflare's always-pass Turnstile test secret and a local agent at `http://127.0.0.1:8788`.
