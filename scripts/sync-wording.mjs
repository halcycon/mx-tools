#!/usr/bin/env node
// Sync the plain-English health-check wording from the Cuckoo Camp website into
// worker/report/wording.json (used by the full-report emails). The website owns the
// wording; this only copies it.
//
//   node scripts/sync-wording.mjs                       # fetch WORDING_URL (default below)
//   node scripts/sync-wording.mjs --yaml ../cuckoo-site/data/healthcheck.yaml
//
// A failed fetch keeps the existing snapshot so builds never break on a website outage.
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const out = path.join(root, 'worker/report/wording.json');
const url = process.env.WORDING_URL || 'https://www.thecuckoocamp.co.uk/health-check/wording.json';

function validate(w) {
	if (!w || typeof w !== 'object' || !w.codes || !w.checks || !w.statuses) {
		throw new Error('wording must have statuses, checks and codes');
	}
	return w;
}

async function load() {
	const i = process.argv.indexOf('--yaml');
	if (i > 0) {
		const { parse } = await import('yaml');
		const file = process.argv[i + 1];
		return { source: path.basename(file), data: validate(parse(await readFile(file, 'utf8'))) };
	}
	const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
	if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
	return { source: url, data: validate(await res.json()) };
}

try {
	const { source, data } = await load();
	const { statuses, summary, checks, codes } = data;
	await writeFile(out, JSON.stringify({ _source: source, statuses, summary, checks, codes }, null, '\t') + '\n');
	console.log(`wording: ${Object.keys(codes).length} codes from ${source}`);
} catch (e) {
	console.warn(`wording: keeping existing snapshot (${e instanceof Error ? e.message : e})`);
}
