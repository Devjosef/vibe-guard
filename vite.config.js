import { defineConfig } from 'vite'

export default defineConfig({
  root: 'documents',
  build: {
    outDir: '../dist/docs',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        index: 'documents/index.html',
        'getting-started': 'documents/getting-started.html',
        rules: 'documents/rules.html',
        docs: 'documents/docs.html',
        performance: 'documents/performance.html'
      }
    }
  },
  server: {
    port: 3000
  }
})
