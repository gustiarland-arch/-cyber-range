import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: process.env.CR_API_URL || 'http://127.0.0.1:8000', changeOrigin: false, ws: true },
      '/terminal': { target: process.env.CR_TERMINAL_URL || 'http://127.0.0.1:8100', changeOrigin: false, ws: true },
    },
  },
  build: { chunkSizeWarningLimit: 700 },
  test: { environment: 'happy-dom', include: ['tests/**/*.test.js'] },
})
