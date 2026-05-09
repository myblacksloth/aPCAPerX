/**
 * Root application component.
 *
 * Manages the global state of the analysis session:
 *   - null     → shows the upload page
 *   - loading  → shows the analysis spinner
 *   - result   → shows the dashboard with results
 *
 * Navigation between the three views does not use React Router; changing local state is enough.
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
  // Result of the latest analysis (null = no analysis has been run yet)
  const [result, setResult] = useState<AnalysisResult | null>(null)

  // true while the HTTP request to the backend is running
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState<UploadProgress>({
    phase: 'idle',
    percent: 0,
    message: 'Waiting for file',
  })

  // Error message from the latest operation (null = no error)
  const [error, setError] = useState<string | null>(null)

  /**
   * Sends the PCAP file to the backend and updates state with the result.
   * Handles network, server, and invalid-format errors.
   */
  const handleUpload = async (file: File) => {
    setLoading(true)
    setError(null)
    setProgress({
      phase: 'uploading',
      percent: 0,
      message: 'Uploading the PCAP file',
    })

    // Builds the multipart form required by the /api/analyze endpoint
    const formData = new FormData()
    formData.append('file', file)

    try {
      const analysisResult = await new Promise<AnalysisResult>((resolve, reject) => {
        const xhr = new XMLHttpRequest()
        xhr.open('POST', '/api/analyze')

        xhr.upload.onprogress = (event) => {
          // The browser exposes upload progress; the backend analyzes after
          // receiving the file, so later phases are inferred.
          if (event.lengthComputable) {
            const uploadPercent = Math.round((event.loaded / event.total) * 70)
            setProgress({
              phase: 'uploading',
              percent: uploadPercent,
              message: `File upload: ${Math.min(100, Math.round((event.loaded / event.total) * 100))}%`,
            })
          }
        }

        xhr.onloadstart = () => {
          setProgress({ phase: 'uploading', percent: 5, message: 'Uploading the PCAP file' })
        }

        xhr.upload.onload = () => {
          setProgress({ phase: 'processing', percent: 75, message: 'File received, preparing processing' })
        }

        xhr.onreadystatechange = () => {
          if (xhr.readyState === XMLHttpRequest.HEADERS_RECEIVED) {
            setProgress({ phase: 'analyzing', percent: 85, message: 'PCAP analysis in progress' })
          }
        }

        xhr.onload = () => {
          if (xhr.status < 200 || xhr.status >= 300) {
            try {
              const data = JSON.parse(xhr.responseText || '{}')
              reject(new Error(data.detail ?? `Error ${xhr.status}: ${xhr.statusText}`))
            } catch {
              reject(new Error(`Error ${xhr.status}: ${xhr.statusText}`))
            }
            return
          }

          try {
            setProgress({ phase: 'complete', percent: 100, message: 'Analysis completed' })
            resolve(JSON.parse(xhr.responseText) as AnalysisResult)
          } catch {
            reject(new Error('Invalid backend response'))
          }
        }

        xhr.onerror = () => reject(new Error('Network error during upload'))
        xhr.send(formData)
      })

      // Analysis completed: deserializza il JSON e aggiorna il dashboard
      setResult(analysisResult)

    } catch (err) {
      // Network errors (backend unreachable) or HTTP errors
      setError(err instanceof Error ? err.message : 'Unknown error')
      setProgress({ phase: 'idle', percent: 0, message: 'Analysis not completed' })
    } finally {
      setLoading(false)
    }
  }

  /** Resets the application to its initial state to analyze a new file */
  const handleReset = () => {
    setResult(null)
    setError(null)
    setProgress({ phase: 'idle', percent: 0, message: 'Waiting for file' })
  }

  return (
    <div className="min-h-screen bg-slate-900 flex flex-col">

      {/* ── Sticky top header ──────────────────────────────────────── */}
      <header className="bg-slate-800 border-b border-slate-700 px-6 py-3 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-3">
          {/* Application logo and name */}
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

        {/* Button visible only while results are displayed */}
        {result && (
          <button
            onClick={handleReset}
            className="flex items-center gap-2 px-4 py-1.5 bg-slate-700 hover:bg-slate-600
                       text-slate-200 text-sm rounded-lg transition-colors"
          >
            ↑ New analysis
          </button>
        )}
      </header>

      {/* ── Main content ──────────────────────────────────────── */}
      <main className="flex-1 pb-12">
        {result ? (
          // Dashboard view: shows analysis results
          <Dashboard result={result} onReset={handleReset} onResultUpdate={setResult} />
        ) : (
          // Upload view: shows the file upload form
          <FileUpload
            onUpload={handleUpload}
            loading={loading}
            error={error}
            progress={progress}
          />
        )}
      </main>

      {/* ── Fixed footer, always visible like the header ────────────────── */}
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
