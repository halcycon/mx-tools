# mx-tools agents

Private integrated diagnostic tool: Cloudflare Worker web app + Go Bubble Tea CLI.

## Stack

- **Web**: React + Vite → `dist/`, Worker in `worker/` (`wrangler.jsonc`, assets + `/api/*`)
- **Checks (TS)**: `worker/checks/`
- **CLI**: `cli/` (Bubble Tea TUI, `miekg/dns`)

## Commands

| Command | Purpose |
|---------|---------|
| `npm run dev` | Vite + `wrangler dev` |
| `npm run deploy` | Build SPA and deploy Worker |
| `npm run cli:build` | Build `bin/mx` |
| `../bin/mx agent` | Local probe HTTP server for the web UI |
| `cd cli && go test ./...` | CLI unit tests |

## Cloudflare notes

- Retrieve current Workers docs before changing platform APIs.
- Port **25** is blocked for outbound TCP on Workers; SMTP **587** / **465** work. ICMP and inbound port 25 stay CLI-only.
- Prefer **`mx agent`** for accurate Spamhaus/DNSBL from a user’s network; keep DQS keys on the agent (`SPAMHAUS_DQS_KEY`), not in a public Worker.
- After binding changes: `npm run cf-typegen`.

## Conventions

- Keep web and CLI command IDs aligned (`parseQuery` / `ParseQuery`).
- Prefer DoH (`1.1.1.1` / cloudflare-dns.com) for DNS in the Worker; agent uses system/recursive DNS via `miekg/dns`.
- Do not commit secrets or deploy tokens.
