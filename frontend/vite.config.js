import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Vite 4 is pinned deliberately: Vite 5 requires Node 20+, and this environment
// runs Node 18.
export default defineConfig({
  plugins: [react()],
  define: {
    // Bumped whenever the UI changes in a way the user must be able to see.
    // The admin console prints it so a stale browser tab is obvious.
    __APP_BUILD__: JSON.stringify(process.env.APP_BUILD ?? 'dev'),
  },
  server: {
    host: '0.0.0.0',
    port: 5173,
    proxy: {
      // Proxy the API so the browser stays on a single origin. This also lets the
      // session cookie used by Lab 18 travel with same-origin requests.
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      // Lab 6 - the exposed static files live in the backend's web root.
      '/.env': { target: 'http://localhost:8080', changeOrigin: true },
      '/.git': { target: 'http://localhost:8080', changeOrigin: true },
      '/backup.zip': { target: 'http://localhost:8080', changeOrigin: true },
      '/uploads': { target: 'http://localhost:8080', changeOrigin: true },
    },
  },
})
