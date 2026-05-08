/**
 * Componente per il caricamento del file PCAP.
 *
 * Presenta un'area di drag-and-drop centrale con:
 *   - Trascinamento del file direttamente sull'area
 *   - Click per aprire il file picker del sistema operativo
 *   - Feedback visivo durante il trascinamento
 *   - Indicatore di caricamento (spinner) durante l'analisi
 *   - Messaggio di errore in caso di problema
 */
import { useState, useCallback, useRef } from 'react'
import { Upload, FileSearch, AlertCircle, Loader2 } from 'lucide-react'
import type { UploadProgress } from '../App'

interface FileUploadProps {
  /** Callback invocata quando l'utente seleziona un file valido */
  onUpload: (file: File) => void
  /** true durante la chiamata HTTP al backend */
  loading: boolean
  /** Messaggio di errore da mostrare (null = nessun errore) */
  error: string | null
  /** Stato di avanzamento upload/elaborazione */
  progress: UploadProgress
}

/** Estensioni file accettate — deve corrispondere al backend */
const ACCEPTED_EXTENSIONS = ['.pcap', '.pcapng', '.cap']

export default function FileUpload({ onUpload, loading, error, progress }: FileUploadProps) {
  // true quando l'utente trascina un file sopra l'area
  const [isDragOver, setIsDragOver] = useState(false)

  // Riferimento all'input file nascosto (attivato dal click sull'area)
  const inputRef = useRef<HTMLInputElement>(null)

  /**
   * Verifica che il file abbia un'estensione accettata prima di inviarlo.
   * Mostra un alert se il formato non è supportato.
   */
  const processFile = useCallback((file: File) => {
    const ext = '.' + file.name.split('.').pop()?.toLowerCase()
    if (!ACCEPTED_EXTENSIONS.includes(ext)) {
      alert(`Formato non supportato: "${ext}".\nUsa ${ACCEPTED_EXTENSIONS.join(', ')}`)
      return
    }
    onUpload(file)
  }, [onUpload])

  // ── Gestori degli eventi drag-and-drop ──────────────────────────────────

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()   // necessario per abilitare il drop
    setIsDragOver(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragOver(false)
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragOver(false)

    // Prende solo il primo file trascinato
    const file = e.dataTransfer.files[0]
    if (file) processFile(file)
  }, [processFile])

  const handleInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) processFile(file)
    // Resetta l'input per permettere di ricaricare lo stesso file
    e.target.value = ''
  }, [processFile])

  return (
    <div className="flex flex-col items-center justify-center min-h-[calc(100vh-120px)] px-4 py-12">

      {/* ── Titolo e sottotitolo ────────────────────────────────────────── */}
      <div className="text-center mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">
          Analisi PCAP
        </h1>
        <p className="text-slate-400 text-lg">
          Carica un file di cattura di rete per visualizzare statistiche dettagliate
        </p>
      </div>

      {/* ── Area drag-and-drop ──────────────────────────────────────────── */}
      <div
        role="button"
        tabIndex={0}
        aria-label="Area di caricamento file PCAP"
        onClick={() => !loading && inputRef.current?.click()}
        onKeyDown={(e) => e.key === 'Enter' && !loading && inputRef.current?.click()}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={[
          'w-full max-w-xl border-2 border-dashed rounded-2xl p-12 text-center',
          'transition-all duration-200 cursor-pointer outline-none',
          'focus-visible:ring-2 focus-visible:ring-brand-500',
          // Cambia colore in base allo stato
          loading
            ? 'border-slate-600 bg-slate-800/50 cursor-not-allowed'
            : isDragOver
              ? 'border-brand-400 bg-brand-500/10 scale-[1.02]'
              : 'border-slate-600 bg-slate-800/50 hover:border-brand-500 hover:bg-slate-800',
        ].join(' ')}
      >
        {/* Input file nascosto — l'utente non lo vede mai direttamente */}
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng,.cap"
          className="hidden"
          onChange={handleInputChange}
          disabled={loading}
        />

        {loading ? (
          // ── Stato: analisi in corso ──────────────────────────────────
          <div className="flex flex-col items-center gap-4">
            <Loader2 className="w-14 h-14 text-brand-400 animate-spin" />
            <div>
              <p className="text-white font-semibold text-lg">Analisi in corso…</p>
              <p className="text-slate-400 text-sm mt-1">
                {progress.message}
              </p>
              <div className="mt-4 w-72 overflow-hidden rounded-full bg-slate-700">
                <div
                  className="h-2 rounded-full bg-brand-400 transition-all"
                  style={{ width: `${Math.max(5, Math.min(progress.percent, 100))}%` }}
                />
              </div>
              <div className="mt-3 grid w-72 grid-cols-3 gap-2 text-[11px] text-slate-500">
                <span className={progress.phase === 'uploading' ? 'text-brand-300' : ''}>Upload</span>
                <span className={progress.phase === 'processing' ? 'text-brand-300' : ''}>Elaborazione</span>
                <span className={progress.phase === 'analyzing' ? 'text-brand-300' : ''}>Analisi</span>
              </div>
            </div>
          </div>
        ) : isDragOver ? (
          // ── Stato: file trascinato sopra l'area ─────────────────────
          <div className="flex flex-col items-center gap-4">
            <FileSearch className="w-14 h-14 text-brand-400" />
            <p className="text-brand-300 font-semibold text-lg">
              Rilascia il file qui
            </p>
          </div>
        ) : (
          // ── Stato: normale (in attesa di upload) ────────────────────
          <div className="flex flex-col items-center gap-4">
            <Upload className="w-14 h-14 text-slate-500" />
            <div>
              <p className="text-white font-semibold text-lg">
                Trascina il file PCAP qui
              </p>
              <p className="text-slate-400 text-sm mt-1">
                oppure <span className="text-brand-400 underline">clicca per sfogliare</span>
              </p>
            </div>
          </div>
        )}
      </div>

      {/* ── Dettagli sui formati supportati ────────────────────────────── */}
      <p className="mt-4 text-slate-500 text-sm">
        Formati supportati: <code className="text-slate-400">.pcap</code>,{' '}
        <code className="text-slate-400">.pcapng</code>,{' '}
        <code className="text-slate-400">.cap</code> · Nessun limite applicativo predefinito
      </p>

      {/* ── Messaggio di errore ─────────────────────────────────────────── */}
      {error && (
        <div className="mt-6 w-full max-w-xl flex items-start gap-3 bg-red-900/30
                        border border-red-700 rounded-xl p-4">
          <AlertCircle className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
          <div>
            <p className="text-red-300 font-semibold text-sm">Errore</p>
            <p className="text-red-400 text-sm mt-0.5">{error}</p>
          </div>
        </div>
      )}

      {/* ── Feature highlights ─────────────────────────────────────────── */}
      <div className="mt-10 grid grid-cols-2 sm:grid-cols-4 gap-4 max-w-2xl w-full">
        {[
          { icon: '🔍', label: 'Protocolli', desc: 'TCP, UDP, DNS, HTTP…' },
          { icon: '🌐', label: 'Indirizzi IP', desc: 'Top talkers & flussi' },
          { icon: '🔌', label: 'Porte', desc: 'Servizi più usati' },
          { icon: '📈', label: 'Timeline', desc: 'Traffico nel tempo' },
        ].map((f) => (
          <div key={f.label} className="card text-center">
            <div className="text-2xl mb-1">{f.icon}</div>
            <div className="text-sm font-semibold text-slate-200">{f.label}</div>
            <div className="text-xs text-slate-500 mt-0.5">{f.desc}</div>
          </div>
        ))}
      </div>
    </div>
  )
}
