import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  base: '/vibe-guard/',
  root: 'documents',
  build: {
    outDir: '../dist/docs',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'documents/index.html'),
        gettingStarted: resolve(__dirname, 'documents/getting-started.html'),
        rules: resolve(__dirname, 'documents/rules.html'),
        docs: resolve(__dirname, 'documents/docs.html'),
        performance: resolve(__dirname, 'documents/performance.html')
      }
    },
    cssCodeSplit: false,
    assetsInlineLimit: 4096
  },
  server: {
    port: 3000,
    open: true
  },
  preview: {
    port: 3000
  },
  optimizeDeps: {
    include: []
  }
}); 