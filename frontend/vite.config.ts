import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: true,
    proxy: {
      '/.well-known': 'http://127.0.0.1:8080',
      '/v1': 'http://127.0.0.1:8080',
      '/oauth2': 'http://127.0.0.1:8080',
    },
  },
})
