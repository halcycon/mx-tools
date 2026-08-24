import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
	plugins: [react()],
	root: 'web',
	resolve: {
		alias: {
			'@engine': path.join(rootDir, 'worker/checks'),
		},
	},
	build: {
		outDir: '../dist',
		emptyOutDir: true,
	},
	server: {
		port: 5173,
		fs: { allow: [rootDir] },
		proxy: {
			'/api': 'http://127.0.0.1:8787',
		},
	},
});
