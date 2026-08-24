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
| `cd cli && go test ./...` | CLI unit tests (if any) |

## Cloudflare notes

- Retrieve current Workers docs before changing platform APIs.
- Port **25** and **ICMP** are unavailable on Workers; CLI implements SMTP/ping/trace.
- After binding changes: `npm run cf-typegen`.

## Conventions

- Keep web and CLI command IDs aligned (`parseQuery` / `ParseQuery`).
- Prefer DoH (`1.1.1.1` / cloudflare-dns.com) for DNS in the Worker.
- Do not commit secrets or deploy tokens.
