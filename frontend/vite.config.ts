/**
 * Configurazione di Vite per il frontend React.
 *
 * In modalità sviluppo locale, tutte le richieste verso /api vengono
 * proxy-izzate al backend FastAPI (porta 8000). In Docker questa funzione
 * è svolta da Nginx, quindi il proxy qui serve solo per `npm run dev`.
 */
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],

  server: {
    // Porta del server di sviluppo Vite
    port: 5173,

    proxy: {
      // Tutte le chiamate a /api/* vengono inoltrate al backend FastAPI
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },

  build: {
    // Directory di output per la build di produzione
    outDir: 'dist',
    // Suddivide il bundle in chunk separati per un caricamento più rapido
    rollupOptions: {
      output: {
        manualChunks: {
          // Separa React e Recharts in chunk distinti per ottimizzare il caching
          react:    ['react', 'react-dom'],
          recharts: ['recharts'],
        },
      },
    },
  },
})
