/**
 * Componente radice dell'applicazione.
 *
 * Gestisce lo stato globale della sessione di analisi:
 *   - null     → mostra la pagina di upload
 *   - loading  → mostra lo spinner di analisi
 *   - result   → mostra il dashboard con i risultati
 *
 * La navigazione tra le tre viste avviene senza React Router:
 * basta cambiare lo stato locale.
 */
import { useState } from 'react'
import { Network } from 'lucide-react'
import FileUpload from './components/FileUpload'
import Dashboard from './components/Dashboard'
import type { AnalysisResult } from './types/analysis'

export default function App() {
  // Risultato dell'ultima analisi (null = nessuna analisi ancora eseguita)
  const [result, setResult] = useState<AnalysisResult | null>(null)

  // true durante la chiamata HTTP al backend
  const [loading, setLoading] = useState(false)

  // Messaggio di errore dell'ultima operazione (null = nessun errore)
  const [error, setError] = useState<string | null>(null)

  /**
   * Invia il file PCAP al backend e aggiorna lo stato con il risultato.
   * Gestisce tutti i casi di errore (rete, server, formato non valido).
   */
  const handleUpload = async (file: File) => {
    setLoading(true)
    setError(null)

    // Costruisce il form multipart richiesto dall'endpoint /api/analyze
    const formData = new FormData()
    formData.append('file', file)

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        body: formData,
      })

      if (!response.ok) {
        // Il backend ha restituito un codice di errore HTTP (4xx / 5xx)
        const data = await response.json().catch(() => ({}))
        throw new Error(data.detail ?? `Errore ${response.status}: ${response.statusText}`)
      }

      // Analisi completata: deserializza il JSON e aggiorna il dashboard
      const analysisResult: AnalysisResult = await response.json()
      setResult(analysisResult)

    } catch (err) {
      // Errori di rete (backend non raggiungibile) o errori HTTP
      setError(err instanceof Error ? err.message : 'Errore sconosciuto')
    } finally {
      setLoading(false)
    }
  }

  /** Resetta l'applicazione allo stato iniziale per analizzare un nuovo file */
  const handleReset = () => {
    setResult(null)
    setError(null)
  }

  return (
    <div className="min-h-screen bg-slate-900 flex flex-col">

      {/* ── Header fisso in cima ──────────────────────────────────────── */}
      <header className="bg-slate-800 border-b border-slate-700 px-6 py-3 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-3">
          {/* Logo e nome dell'applicazione */}
          <div className="p-1.5 bg-brand-500 rounded-lg">
            <Network className="w-5 h-5 text-white" />
          </div>
          <div>
            <span className="text-lg font-bold text-white">PCAPCaper</span>
            <span className="ml-2 text-xs text-slate-400 hidden sm:inline">
              PCAP Analyzer
            </span>
          </div>
        </div>

        {/* Pulsante visibile solo quando si visualizzano i risultati */}
        {result && (
          <button
            onClick={handleReset}
            className="flex items-center gap-2 px-4 py-1.5 bg-slate-700 hover:bg-slate-600
                       text-slate-200 text-sm rounded-lg transition-colors"
          >
            ↑ Nuova analisi
          </button>
        )}
      </header>

      {/* ── Contenuto principale ──────────────────────────────────────── */}
      <main className="flex-1">
        {result ? (
          // Vista dashboard: mostra i risultati dell'analisi
          <Dashboard result={result} onReset={handleReset} />
        ) : (
          // Vista upload: mostra il form di caricamento file
          <FileUpload
            onUpload={handleUpload}
            loading={loading}
            error={error}
          />
        )}
      </main>

      {/* ── Footer minimalista ────────────────────────────────────────── */}
      <footer className="text-center text-slate-600 text-xs py-3 border-t border-slate-800">
        PCAPCaper — Open Source PCAP Analyzer
      </footer>
    </div>
  )
}
