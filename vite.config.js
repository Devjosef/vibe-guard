import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  base: '/vibe-guard/',
  root: 'frontend-new',
  publicDir: 'assets',
  build: {
    outDir: '../dist/docs',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'frontend-new/index.html'),
        features: resolve(__dirname, 'frontend-new/features.html'),
        docs: resolve(__dirname, 'frontend-new/docs.html'),
        gettingStarted: resolve(__dirname, 'frontend-new/getting-started.html'),
        performance: resolve(__dirname, 'frontend-new/performance.html')
      }
    },
    cssCodeSplit: false,
    assetsInlineLimit: 4096,
    assetsDir: 'assets'
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
  },
  assetsInclude: ['**/*.svg', '**/*.png', '**/*.jpg', '**/*.jpeg', '**/*.gif']
}); 