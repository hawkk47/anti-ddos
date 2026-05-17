import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// Build output is consumed by control plane Fastify via @fastify/static.
// Dev server proxies API calls to the local control plane (9090 by default).
export default defineConfig({
  plugins: [svelte()],
  base: '/ui/',
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/v1': {
        target: 'http://127.0.0.1:9090',
        changeOrigin: false,
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    target: 'es2022',
  },
});
