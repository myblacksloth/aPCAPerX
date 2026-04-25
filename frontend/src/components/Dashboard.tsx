/**
 * Componente principale del dashboard di analisi.
 *
 * Organizza tutti i sotto-componenti in una griglia responsive:
 *
 *   ┌──────────────────────────────────────────────────────────┐
 *   │  [6 Summary Cards — full width]                          │
 *   ├─────────────────────────────┬────────────────────────────┤
 *   │  [Protocol Donut + Table]   │  [Top IP Chart — tab]      │
 *   ├──────────────────────────────┴───────────────────────────┤
 *   │  [Timeline AreaChart — full width]                       │
 *   ├─────────────────────────────┬────────────────────────────┤
 *   │  [Top Ports Chart — tab]    │  [Conversations Table]     │
 *   ├──────────────────────────────┴───────────────────────────┤
 *   │  [Packet List — full width]                              │
 *   └──────────────────────────────────────────────────────────┘
 *
 * Ogni sezione è incapsulata nel suo componente dedicato per
 * mantenere il codice organizzato e facile da manutenere.
 */
import { useState } from 'react'
import { FileText, Download, BarChart2, GitBranch } from 'lucide-react'
import type { AnalysisResult } from '../types/analysis'
import SummaryCards       from './SummaryCards'
import ProtocolChart      from './ProtocolChart'
import TopIPsChart        from './TopIPsChart'
import TimelineChart      from './TimelineChart'
import TopPortsChart      from './TopPortsChart'
import ConversationsTable from './ConversationsTable'
import PacketTable        from './PacketTable'
import TracesView         from './TracesView'

type ActiveTab = 'overview' | 'traces'

interface DashboardProps {
  result: AnalysisResult
  onReset: () => void
}

export default function Dashboard({ result }: DashboardProps) {
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview')
  /**
   * Esporta il risultato dell'analisi come file JSON scaricabile.
   * Utile per archiviare o condividere i dati estratti dal PCAP.
   */
  const handleExportJSON = () => {
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = result.filename.replace(/\.[^.]+$/, '') + '_analysis.json'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="max-w-[1600px] mx-auto px-4 py-6 space-y-4">

      {/* ── Intestazione risultati ────────────────────────────────────── */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <FileText className="w-5 h-5 text-brand-400" />
          <div>
            <h1 className="text-lg font-bold text-white">{result.filename}</h1>
            <p className="text-xs text-slate-500">
              {result.summary.total_packets.toLocaleString('it-IT')} pacchetti analizzati
              {result.summary.capture_start && (
                <> · {new Date(result.summary.capture_start).toLocaleString('it-IT')}</>
              )}
            </p>
          </div>
        </div>

        {/* Tab switcher + export */}
        <div className="flex items-center gap-2">
          {/* Tab buttons */}
          <div className="flex items-center bg-slate-700/60 rounded-lg p-0.5 gap-0.5">
            <button
              onClick={() => setActiveTab('overview')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors
                ${activeTab === 'overview'
                  ? 'bg-slate-600 text-slate-100 shadow'
                  : 'text-slate-400 hover:text-slate-200'}`}
            >
              <BarChart2 className="w-3.5 h-3.5" />
              Overview
            </button>
            <button
              onClick={() => setActiveTab('traces')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors
                ${activeTab === 'traces'
                  ? 'bg-slate-600 text-slate-100 shadow'
                  : 'text-slate-400 hover:text-slate-200'}`}
            >
              <GitBranch className="w-3.5 h-3.5" />
              Tracce
            </button>
          </div>

          {/* Export JSON */}
          <button
            onClick={handleExportJSON}
            className="flex items-center gap-2 px-3 py-1.5 bg-slate-700 hover:bg-slate-600
                       text-slate-200 text-xs rounded-lg transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Esporta JSON
          </button>
        </div>
      </div>

      {/* ── Tab: Overview ─────────────────────────────────────────────── */}
      {activeTab === 'overview' && (
        <>
          {/* Riga 1: 6 card di riepilogo */}
          <SummaryCards result={result} />

          {/* Riga 2: distribuzione protocolli + top IP */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <ProtocolChart result={result} />
            <TopIPsChart   result={result} />
          </div>

          {/* Riga 3: timeline del traffico */}
          <TimelineChart result={result} />

          {/* Riga 4: top porte + conversazioni */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <TopPortsChart      result={result} />
            <ConversationsTable conversations={result.conversations} />
          </div>

          {/* Riga 5: lista pacchetti */}
          <PacketTable packets={result.packets} />
        </>
      )}

      {/* ── Tab: Tracce ───────────────────────────────────────────────── */}
      {activeTab === 'traces' && (
        <TracesView packets={result.packets} />
      )}
    </div>
  )
}
