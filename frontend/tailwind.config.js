/**
 * Configurazione di Tailwind CSS.
 *
 * Definisce la palette di colori personalizzata usata in tutta l'app
 * e specifica i percorsi da analizzare per eliminare le classi inutilizzate
 * nella build di produzione (purging).
 */
/** @type {import('tailwindcss').Config} */
export default {
  // Tailwind analizza questi file per il tree-shaking delle classi CSS
  content: ['./index.html', './src/**/*.{ts,tsx}'],

  theme: {
    extend: {
      colors: {
        // Palette principale dell'app (tema scuro)
        brand: {
          50:  '#eef2ff',
          100: '#e0e7ff',
          400: '#818cf8',
          500: '#6366f1', // colore accent principale
          600: '#4f46e5',
          700: '#4338ca',
        },
      },

      // Animazione personalizzata per il drag-and-drop dell'upload
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
    },
  },

  plugins: [],
}
