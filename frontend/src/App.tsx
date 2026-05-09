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

export interface UploadProgress {
  phase: 'idle' | 'uploading' | 'processing' | 'analyzing' | 'complete'
  percent: number
  message: string
}

export default function App() {
  // Risultato dell'ultima analisi (null = nessuna analisi ancora eseguita)
  const [result, setResult] = useState<AnalysisResult | null>(null)

  // true durante la chiamata HTTP al backend
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState<UploadProgress>({
    phase: 'idle',
    percent: 0,
    message: 'In attesa del file',
  })

  // Messaggio di errore dell'ultima operazione (null = nessun errore)
  const [error, setError] = useState<string | null>(null)

  /**
   * Invia il file PCAP al backend e aggiorna lo stato con il risultato.
   * Gestisce tutti i casi di errore (rete, server, formato non valido).
   */
  const handleUpload = async (file: File) => {
    setLoading(true)
    setError(null)
    setProgress({
      phase: 'uploading',
      percent: 0,
      message: 'Caricamento del file PCAP',
    })

    // Costruisce il form multipart richiesto dall'endpoint /api/analyze
    const formData = new FormData()
    formData.append('file', file)

    try {
      const analysisResult = await new Promise<AnalysisResult>((resolve, reject) => {
        const xhr = new XMLHttpRequest()
        xhr.open('POST', '/api/analyze')

        xhr.upload.onprogress = (event) => {
          // Il browser espone il progresso di upload; il backend analizza dopo
          // aver ricevuto il file, quindi le fasi successive sono determinate.
          if (event.lengthComputable) {
            const uploadPercent = Math.round((event.loaded / event.total) * 70)
            setProgress({
              phase: 'uploading',
              percent: uploadPercent,
              message: `Caricamento file: ${Math.min(100, Math.round((event.loaded / event.total) * 100))}%`,
            })
          }
        }

        xhr.onloadstart = () => {
          setProgress({ phase: 'uploading', percent: 5, message: 'Caricamento del file PCAP' })
        }

        xhr.upload.onload = () => {
          setProgress({ phase: 'processing', percent: 75, message: 'File ricevuto, preparazione elaborazione' })
        }

        xhr.onreadystatechange = () => {
          if (xhr.readyState === XMLHttpRequest.HEADERS_RECEIVED) {
            setProgress({ phase: 'analyzing', percent: 85, message: 'Analisi del PCAP in corso' })
          }
        }

        xhr.onload = () => {
          if (xhr.status < 200 || xhr.status >= 300) {
            try {
              const data = JSON.parse(xhr.responseText || '{}')
              reject(new Error(data.detail ?? `Errore ${xhr.status}: ${xhr.statusText}`))
            } catch {
              reject(new Error(`Errore ${xhr.status}: ${xhr.statusText}`))
            }
            return
          }

          try {
            setProgress({ phase: 'complete', percent: 100, message: 'Analisi completata' })
            resolve(JSON.parse(xhr.responseText) as AnalysisResult)
          } catch {
            reject(new Error('Risposta del backend non valida'))
          }
        }

        xhr.onerror = () => reject(new Error('Errore di rete durante il caricamento'))
        xhr.send(formData)
      })

      // Analisi completata: deserializza il JSON e aggiorna il dashboard
      setResult(analysisResult)

    } catch (err) {
      // Errori di rete (backend non raggiungibile) o errori HTTP
      setError(err instanceof Error ? err.message : 'Errore sconosciuto')
      setProgress({ phase: 'idle', percent: 0, message: 'Analisi non completata' })
    } finally {
      setLoading(false)
    }
  }

  /** Resetta l'applicazione allo stato iniziale per analizzare un nuovo file */
  const handleReset = () => {
    setResult(null)
    setError(null)
    setProgress({ phase: 'idle', percent: 0, message: 'In attesa del file' })
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
      <main className="flex-1 pb-12">
        {result ? (
          // Vista dashboard: mostra i risultati dell'analisi
          <Dashboard result={result} onReset={handleReset} onResultUpdate={setResult} />
        ) : (
          // Vista upload: mostra il form di caricamento file
          <FileUpload
            onUpload={handleUpload}
            loading={loading}
            error={error}
            progress={progress}
          />
        )}
      </main>

      {/* ── Footer fisso sempre visibile come l'header ────────────────── */}
      <footer className="fixed bottom-0 left-0 right-0 z-50 border-t border-slate-700 bg-slate-800/95 px-4 py-2 text-center text-xs text-slate-400 backdrop-blur">
        <span>PCAPCaper - Open Source PCAP Analyzer</span>
        <span className="mx-2 text-slate-600">|</span>
        <span>(C) Antonio Maulucci - 2026</span>
        <span className="mx-2 text-slate-600">|</span>
        <a
          href="https://github.com/myblacksloth"
          target="_blank"
          rel="noreferrer"
          className="text-brand-300 hover:text-brand-100"
        >
          GitHub: myblacksloth
        </a>
      </footer>
    </div>
  )
}
