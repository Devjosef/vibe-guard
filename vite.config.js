import { defineConfig } from 'vite'

export default defineConfig({
  root: 'documents',
  build: {
    outDir: '../dist/docs',
    emptyOutDir: true
  },
  server: {
    port: 3000
  }
})
