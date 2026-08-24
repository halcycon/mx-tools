# mx-tools

Private integrated diagnostic tool: DNS, mail authentication, blacklists, RDAP, and connectivity checks — with a reactive web UI (Cloudflare Worker) and a Charm Bracelet Bubble Tea CLI/TUI.

## Features

| Command | Description | Web (Worker) | CLI |
|---------|-------------|--------------|-----|
| _(bare input)_ | Domain health report (live progress): MX + SPF + DMARC + blacklist + SOA | ✓ | ✓ |
| `full` | Email health report (live progress): mail auth, DNS, blacklist, HTTPS, RDAP | ✓ | ✓ |
| `a` `aaaa` `cname` `mx` `ns` `ptr` `soa` `txt` | DNS lookups | ✓ | ✓ |
| `spf` `dmarc` `dkim` `bimi` `mta-sts` `tlsrpt` | Email auth / reporting | ✓ | ✓ |
| `blacklist` | Multi-DNSBL reputation | ✓ | ✓ |
| `dns` | Nameserver health | ✓ | ✓ |
| `whois` `arin` `asn` | RDAP / Cymru ASN | ✓ | ✓ |
| `http` `https` `tcp` | Connectivity | ✓* | ✓ |
| `smtp` | SMTP banner (port 25) | ✗ (Workers block :25) | ✓ |
| `ping` `trace` | ICMP | ✗ | ✓ |

\* TCP port **25** is blocked on Cloudflare Workers; use the CLI for SMTP.

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

## Query syntax

Command prefixes with `tool:target` (optional extra segments for tools like DKIM):

```
example.com
mx:example.com
blacklist:1.2.3.4
dkim:selector:example.com
tcp:example.com:443
smtp:example.com
full:example.com
```

## Layout

```
worker/          Cloudflare Worker API + check engine (TypeScript)
web/             React + Vite D.A.R.T. UI
cli/             Go Bubble Tea TUI + local check engine
dist/            Built static assets (gitignored)
```

Both engines share the same command set and JSON-shaped results (`tool`, `rows[]`, `summary`, …).

## Private use

Intended for personal / internal diagnostics. Respect DNSBL and RDAP provider terms; avoid rapid repeated queries.
