# D.A.R.T. agent stack (VPS)

Runs `mx agent` as the backend for the public health check (accurate DNSBL) and the gated full report (DNSBL, SMTP 25/587/465 with certificates, PTR/FCrDNS). Cloudflare egress IPs and public resolvers are refused by Spamhaus and others, so these checks have to run from your own server with its own resolver.

| Service | Image | Role |
|---------|-------|------|
| `agent` | `ghcr.io/halcycon/mx-tools-agent` | Probe API on `:8788`, internal network only |
| `unbound` | `klutchell/unbound` | Recursive resolver, so DNSBL queries come from this server's IP, not a shared resolver |
| `cloudflared` | `cloudflare/cloudflared` | Cloudflare Tunnel to the agent. Nothing listens on the VPS's public interface |

The agent runs as non-root with a read-only filesystem and no capabilities. It only connects to public IPs, so a hostile MX record can't point it at your network.

## 1. Cloudflare Tunnel + Access

1. **Zero Trust → Networks → Tunnels → Create a tunnel** (Cloudflared). Name it e.g. `mx-agent`, then copy the **token** from the install step. That's `CLOUDFLARE_TUNNEL_TOKEN`.
2. **Public hostname:** `dart-agent.thecuckoocamp.co.uk` → service `HTTP` → `agent:8788`.
3. **Access → Service credentials → Service Tokens → Create.** Copy the Client ID and Secret. These are the Worker's `AGENT_CLIENT_ID` and `AGENT_CLIENT_SECRET`.
4. **Access → Applications → Add → Self-hosted** for `dart-agent.thecuckoocamp.co.uk`, with one policy: **Action: Service Auth**, include **Service Token** = the token above. With this in place, only the Worker can reach the agent at all.

## 2. Deploy in Arcane

**From Git (recommended: updates follow the repo):**

1. Projects → Create Project ▾ → **From Git Repo** → **Pull**.
2. Repository `https://github.com/halcycon/mx-tools`, branch `main`, Compose File Path `deploy/agent/compose.yaml`.
3. Turn on **Pull Image After Sync** and **Redeploy After Sync**. Auto Sync is optional.
4. Open the project's **Environment Configuration (.env)** and fill in the values from [`.env.example`](.env.example). They are stored only in Arcane, never in Git.

**Or paste it:** Create Project → paste `compose.yaml` → add the `.env` values → Create.

Generate the secrets with:

```bash
openssl rand -hex 24   # MX_AGENT_TOKEN
openssl rand -hex 32   # MX_AGENT_HMAC_SECRET (also the Worker's AGENT_HMAC_SECRET)
```

Plain Docker works too: `docker compose --env-file .env -f deploy/agent/compose.yaml up -d`.

## 3. Point the Worker at it

```bash
npx wrangler secret put AGENT_URL             # https://dart-agent.thecuckoocamp.co.uk
npx wrangler secret put AGENT_HMAC_SECRET     # = MX_AGENT_HMAC_SECRET
npx wrangler secret put AGENT_CLIENT_ID       # Access service token
npx wrangler secret put AGENT_CLIENT_SECRET
```

If `wrangler secret put` refuses because a newer preview version exists, use `npx wrangler versions secret put …`. New versions inherit the secret.

## Checks

- The containers show **healthy** in Arcane: the agent answers `/api/health` and `unbound` resolves `dnssec.works`.
- Cloudflared logs show `Registered tunnel connection`.
- A health check on the site returns `blacklist.facts.source: "agent"`. With the agent down it returns `"worker"`, the fallback.

## Notes

- **Hetzner Cloud blocks outbound 25 and 465** on new servers. Request the unblock in the Hetzner console. Until then the full report shows the mail-server check as "couldn't check" (`smtp_not_checked`, `egress_blocked`) instead of failing every domain. Port 587 works regardless.
- **Spamhaus.** With the stack's own resolver, Spamhaus public mirrors answer for low, non-commercial volume. A DQS key (`SPAMHAUS_DQS_KEY`) is the supported route for anything else, and it stays on this server.
- **Images.** The image is built for `linux/amd64` and `linux/arm64` by `.github/workflows/agent-image.yml` on every push to `main` that touches `cli/`. After the first publish, set the package to **Public** (GitHub → Packages → `mx-tools-agent` → Package settings) so Arcane can pull without credentials. Pin a release with `AGENT_IMAGE_TAG` (for example `sha-abc1234` or `1.2.0`).
