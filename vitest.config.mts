import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
	plugins: [
		cloudflareTest({
			wrangler: { configPath: "./wrangler.jsonc" },
			// Ignore local .dev.vars so tests always run fail-closed.
			miniflare: {
				bindings: { TURNSTILE_SECRET: "", HEALTH_CHECK_ALLOW_DEV_ORIGINS: "false", SPAMHAUS_DQS_KEY: "" },
			},
		}),
	],
});
