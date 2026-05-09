/**
 * PCAP file upload component.
 *
 * Presents a central drag-and-drop area with:
 *   - Dragging the file directly onto the area
 *   - Click to open the operating-system file picker
 *   - Visual feedback while dragging
 *   - Upload indicator (spinner) during analysis
 *   - Error message when a problem occurs
 */
import { useState, useCallback, useRef } from 'react'
import { Upload, FileSearch, AlertCircle, Loader2 } from 'lucide-react'
import type { UploadProgress } from '../App'

interface FileUploadProps {
  /** Callback invoked when the user selects a valid file */
  onUpload: (file: File) => void
  /** true while the HTTP request to the backend is running */
  loading: boolean
  /** Error message to show (null = no error) */
  error: string | null
  /** Upload/processing progress state */
  progress: UploadProgress
}

/** Accepted file extensions - must match the backend */
const ACCEPTED_EXTENSIONS = ['.pcap', '.pcapng', '.cap']

export default function FileUpload({ onUpload, loading, error, progress }: FileUploadProps) {
  // true when the user drags a file over the area
  const [isDragOver, setIsDragOver] = useState(false)

  // Reference to the hidden file input activated by clicking the drop area.
  const inputRef = useRef<HTMLInputElement>(null)

  /**
   * Checks that the file has an accepted extension before sending it.
   * Shows an alert if the format is unsupported.
   */
  const processFile = useCallback((file: File) => {
    const ext = '.' + file.name.split('.').pop()?.toLowerCase()
    if (!ACCEPTED_EXTENSIONS.includes(ext)) {
      alert(`Unsupported format: "${ext}".\nUse ${ACCEPTED_EXTENSIONS.join(', ')}`)
      return
    }
    onUpload(file)
  }, [onUpload])

  // ── Drag-and-drop event handlers ──────────────────────────────────

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()   // required to enable drop
    setIsDragOver(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragOver(false)
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragOver(false)

    // Uses only the first dragged file
    const file = e.dataTransfer.files[0]
    if (file) processFile(file)
  }, [processFile])

  const handleInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) processFile(file)
    // Resets the input to allow uploading the same file again
    e.target.value = ''
  }, [processFile])

  return (
    <div className="flex flex-col items-center justify-center min-h-[calc(100vh-120px)] px-4 py-12">

      {/* ── Title and subtitle ────────────────────────────────────────── */}
      <div className="text-center mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">
          PCAP analysis
        </h1>
        <p className="text-slate-400 text-lg">
          Upload a network capture file to view detailed statistics
        </p>
      </div>

      {/* ── Drag-and-drop area ──────────────────────────────────────────── */}
      <div
        role="button"
        tabIndex={0}
        aria-label="PCAP file upload area"
        onClick={() => !loading && inputRef.current?.click()}
        onKeyDown={(e) => e.key === 'Enter' && !loading && inputRef.current?.click()}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={[
          'w-full max-w-xl border-2 border-dashed rounded-2xl p-12 text-center',
          'transition-all duration-200 cursor-pointer outline-none',
          'focus-visible:ring-2 focus-visible:ring-brand-500',
          // Changes color based on state
          loading
            ? 'border-slate-600 bg-slate-800/50 cursor-not-allowed'
            : isDragOver
              ? 'border-brand-400 bg-brand-500/10 scale-[1.02]'
              : 'border-slate-600 bg-slate-800/50 hover:border-brand-500 hover:bg-slate-800',
        ].join(' ')}
      >
        {/* Hidden file input - the user never sees it directly */}
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng,.cap"
          className="hidden"
          onChange={handleInputChange}
          disabled={loading}
        />

        {loading ? (
          // ── State: analysis in progress ──────────────────────────────────
          <div className="flex flex-col items-center gap-4">
            <Loader2 className="w-14 h-14 text-brand-400 animate-spin" />
            <div>
              <p className="text-white font-semibold text-lg">Analysis in progress...</p>
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
                <span className={progress.phase === 'processing' ? 'text-brand-300' : ''}>Processing</span>
                <span className={progress.phase === 'analyzing' ? 'text-brand-300' : ''}>Analysis</span>
              </div>
            </div>
          </div>
        ) : isDragOver ? (
          // ── State: file dragged over the drop area ───────────────────
          <div className="flex flex-col items-center gap-4">
            <FileSearch className="w-14 h-14 text-brand-400" />
            <p className="text-brand-300 font-semibold text-lg">
              Drop the file here
            </p>
          </div>
        ) : (
          // ── State: idle, waiting for upload ──────────────────────────
          <div className="flex flex-col items-center gap-4">
            <Upload className="w-14 h-14 text-slate-500" />
            <div>
              <p className="text-white font-semibold text-lg">
                Drag the PCAP file here
              </p>
              <p className="text-slate-400 text-sm mt-1">
                or <span className="text-brand-400 underline">click to browse</span>
              </p>
            </div>
          </div>
        )}
      </div>

      {/* ── Supported format details ──────────────────────────────────── */}
      <p className="mt-4 text-slate-500 text-sm">
        Supported formats: <code className="text-slate-400">.pcap</code>,{' '}
        <code className="text-slate-400">.pcapng</code>,{' '}
        <code className="text-slate-400">.cap</code> · No default application upload limit
      </p>

      {/* ── Error message ─────────────────────────────────────────── */}
      {error && (
        <div className="mt-6 w-full max-w-xl flex items-start gap-3 bg-red-900/30
                        border border-red-700 rounded-xl p-4">
          <AlertCircle className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
          <div>
            <p className="text-red-300 font-semibold text-sm">Error</p>
            <p className="text-red-400 text-sm mt-0.5">{error}</p>
          </div>
        </div>
      )}

      {/* ── Feature highlights ─────────────────────────────────────────── */}
      <div className="mt-10 grid grid-cols-2 sm:grid-cols-4 gap-4 max-w-2xl w-full">
        {[
          { icon: '🔍', label: 'Protocols', desc: 'TCP, UDP, DNS, HTTP...' },
          { icon: '🌐', label: 'IP addresses', desc: 'Top talkers & flows' },
          { icon: '🔌', label: 'Ports', desc: 'Most used services' },
          { icon: '📈', label: 'Timeline', desc: 'Traffic over time' },
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
