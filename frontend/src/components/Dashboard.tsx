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
import { FileText, Download, BarChart2, GitBranch, Search, ShieldAlert, Globe2, Server, Lock } from 'lucide-react'
import type { AnalysisResult, IPEnrichmentResponse, IPExternalInfo, IPEntry } from '../types/analysis'
import SummaryCards       from './SummaryCards'
import ProtocolChart      from './ProtocolChart'
import TopIPsChart        from './TopIPsChart'
import SecurityPanel      from './SecurityPanel'
import WorldTrafficMap    from './WorldTrafficMap'
import TimelineChart      from './TimelineChart'
import TopPortsChart      from './TopPortsChart'
import ConversationsTable from './ConversationsTable'
import PacketFilters      from './PacketFilters'
import PacketTable        from './PacketTable'
import TracesView         from './TracesView'
import AdvancedTracesView from './AdvancedTracesView'
import SecurityAnalysisView from './SecurityAnalysisView'
import DNSAnalysisView from './DNSAnalysisView'
import HTTPAnalysisView from './HTTPAnalysisView'
import TLSAnalysisView from './TLSAnalysisView'
import { parsePacketFilter } from '../utils/packetFilters'

type ActiveTab = 'overview' | 'traces' | 'advanced-traces' | 'security-analysis' | 'dns-analysis' | 'http-analysis' | 'tls-analysis'

interface DashboardProps {
  result: AnalysisResult
  onReset: () => void
  onResultUpdate: (result: AnalysisResult) => void
}

function collectIPs(result: AnalysisResult): string[] {
  // Raccoglie gli IP da tutte le sezioni disponibili del report evitando duplicati.
  const ips = new Set<string>()

  result.top_src_ips.forEach((entry) => ips.add(entry.ip))
  result.top_dst_ips.forEach((entry) => ips.add(entry.ip))
  result.conversations.forEach((conversation) => {
    ips.add(conversation.src_ip)
    ips.add(conversation.dst_ip)
  })
  result.packets.forEach((packet) => {
    if (packet.src_ip) ips.add(packet.src_ip)
    if (packet.dst_ip) ips.add(packet.dst_ip)
  })

  return [...ips]
}

function mergeExternalInfo(entries: IPEntry[], external: Record<string, IPExternalInfo>): IPEntry[] {
  // Aggiorna solo gli IP per cui il backend ha restituito dati esterni.
  return entries.map((entry) => ({
    ...entry,
    external: external[entry.ip] ?? entry.external ?? null,
  }))
}

export default function Dashboard({ result, onResultUpdate }: DashboardProps) {
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview')
  const [externalLoading, setExternalLoading] = useState(false)
  const [externalError, setExternalError] = useState<string | null>(null)
  const [externalSummary, setExternalSummary] = useState<string | null>(null)
  const [externalConfirmOpen, setExternalConfirmOpen] = useState(false)
  const [packetFilter, setPacketFilter] = useState('')
  const parsedPacketFilter = parsePacketFilter(packetFilter)
  const filteredPackets = parsedPacketFilter.error
    ? result.packets
    : result.packets.filter(parsedPacketFilter.predicate)
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

  /**
   * Invia al backend gli IP osservati nel PCAP e fonde nel report corrente
   * le informazioni recuperate da RDAP, ASN, reverse DNS e servizi GeoIP.
   */
  const handleExternalAnalysis = async () => {
    // La chiamata ai servizi esterni parte solo dopo il popup di consenso.
    setExternalConfirmOpen(false)
    const ips = collectIPs(result)
    if (ips.length === 0) return

    setExternalLoading(true)
    setExternalError(null)
    setExternalSummary(null)

    try {
      const response = await fetch('/api/enrich-ips', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ips }),
      })

      if (!response.ok) {
        const data = await response.json().catch(() => ({}))
        throw new Error(data.detail ?? `Errore ${response.status}: ${response.statusText}`)
      }

      const enrichment: IPEnrichmentResponse = await response.json()
      const enrichedCount = Object.values(enrichment.results).filter((item) => item.status === 'enriched').length
      const skippedCount = Object.values(enrichment.results).filter((item) => item.status === 'skipped').length

      onResultUpdate({
        ...result,
        top_src_ips: mergeExternalInfo(result.top_src_ips, enrichment.results),
        top_dst_ips: mergeExternalInfo(result.top_dst_ips, enrichment.results),
        external_ip_info: {
          ...(result.external_ip_info ?? {}),
          ...enrichment.results,
        },
      })

      setExternalSummary(`${enrichedCount} IP arricchiti, ${skippedCount} IP privati/locali non inviati`)
    } catch (err) {
      setExternalError(err instanceof Error ? err.message : "Errore sconosciuto durante l'arricchimento")
    } finally {
      setExternalLoading(false)
    }
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
            <button
              onClick={() => setActiveTab('advanced-traces')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors
                ${activeTab === 'advanced-traces'
                  ? 'bg-slate-600 text-slate-100 shadow'
                  : 'text-slate-400 hover:text-slate-200'}`}
            >
              <GitBranch className="w-3.5 h-3.5" />
              Tracce avanzate
            </button>
            <button
              onClick={() => setActiveTab('security-analysis')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors
                ${activeTab === 'security-analysis'
                  ? 'bg-slate-600 text-slate-100 shadow'
                  : 'text-slate-400 hover:text-slate-200'}`}
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              Security avanzata
            </button>
            <button
              onClick={() => setActiveTab('dns-analysis')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors
                ${activeTab === 'dns-analysis'
                  ? 'bg-slate-600 text-slate-100 shadow'
                  : 'text-slate-400 hover:text-slate-200'}`}
            >
              <Globe2 className="w-3.5 h-3.5" />
              DNS
            </button>
            <button
              onClick={() => setActiveTab('http-analysis')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors
                ${activeTab === 'http-analysis'
                  ? 'bg-slate-600 text-slate-100 shadow'
                  : 'text-slate-400 hover:text-slate-200'}`}
            >
              <Server className="w-3.5 h-3.5" />
              HTTP analysis
            </button>
            <button
              onClick={() => setActiveTab('tls-analysis')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors
                ${activeTab === 'tls-analysis'
                  ? 'bg-slate-600 text-slate-100 shadow'
                  : 'text-slate-400 hover:text-slate-200'}`}
            >
              <Lock className="w-3.5 h-3.5" />
              TLS
            </button>
            <button
              onClick={() => setExternalConfirmOpen(true)}
              disabled={externalLoading}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors
                ${externalLoading
                  ? 'cursor-wait bg-slate-600 text-slate-300'
                  : 'text-slate-300 hover:bg-slate-600 hover:text-slate-100'}`}
            >
              <Search className="w-3.5 h-3.5" />
              {externalLoading ? 'Analisi...' : 'Analizza con tool esterni'}
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

      {/* Stato dell'arricchimento esterno avviato manualmente dall'utente */}
      {(externalSummary || externalError) && (
        <div className={`rounded-lg border px-4 py-2 text-xs ${
          externalError
            ? 'border-red-500/30 bg-red-500/10 text-red-200'
            : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
        }`}>
          {externalError ?? externalSummary}
        </div>
      )}

      {/* ── Tab: Overview ─────────────────────────────────────────────── */}
      {activeTab === 'overview' && (
        <>
          {/* Riga 1: 6 card di riepilogo */}
          <SummaryCards result={result} />

          {/* Riga 2: filtri stile Wireshark applicati alle viste pacchetto */}
          <PacketFilters
            filter={packetFilter}
            filteredCount={filteredPackets.length}
            totalCount={result.packets.length}
            error={parsedPacketFilter.error}
            onFilterChange={setPacketFilter}
          />

          {/* Riga 3: distribuzione protocolli + top IP */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <ProtocolChart result={result} />
            <TopIPsChart   result={result} />
          </div>

          {/* Riga 4: segnalazioni Security basate sulle informazioni IP raccolte */}
          <SecurityPanel result={result} />

          {/* Riga 5: mappa mondiale del traffico verso IP pubblici */}
          <WorldTrafficMap result={result} />

          {/* Riga 6: timeline del traffico */}
          <TimelineChart result={result} />

          {/* Riga 7: top porte + conversazioni */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <TopPortsChart      result={result} />
            <ConversationsTable conversations={result.conversations} />
          </div>

          {/* Riga 8: lista pacchetti filtrata */}
          <PacketTable packets={filteredPackets} />
        </>
      )}

      {/* ── Tab: Tracce ───────────────────────────────────────────────── */}
      {activeTab === 'traces' && (
        <>
          <PacketFilters
            filter={packetFilter}
            filteredCount={filteredPackets.length}
            totalCount={result.packets.length}
            error={parsedPacketFilter.error}
            onFilterChange={setPacketFilter}
          />
          <TracesView packets={filteredPackets} />
        </>
      )}

      {/* ── Tab: Tracce avanzate ──────────────────────────────────────── */}
      {activeTab === 'advanced-traces' && (
        <>
          <PacketFilters
            filter={packetFilter}
            filteredCount={filteredPackets.length}
            totalCount={result.packets.length}
            error={parsedPacketFilter.error}
            onFilterChange={setPacketFilter}
          />
          <AdvancedTracesView packets={filteredPackets} flows={result.flows ?? []} />
        </>
      )}

      {/* ── Tab: Security avanzata ────────────────────────────────────── */}
      {activeTab === 'security-analysis' && (
        <SecurityAnalysisView result={result} />
      )}

      {/* ── Tab: DNS ──────────────────────────────────────────────────── */}
      {activeTab === 'dns-analysis' && (
        <DNSAnalysisView result={result} />
      )}

      {/* ── Tab: HTTP analysis ────────────────────────────────────────── */}
      {activeTab === 'http-analysis' && (
        <HTTPAnalysisView result={result} />
      )}

      {/* ── Tab: TLS analysis ─────────────────────────────────────────── */}
      {activeTab === 'tls-analysis' && (
        <TLSAnalysisView result={result} />
      )}

      {/* Popup privacy per l'arricchimento IP esterno generale */}
      {externalConfirmOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 px-4">
          <div className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-900 p-5 shadow-2xl">
            <div className="flex items-start gap-3">
              <Search className="mt-0.5 h-5 w-5 flex-shrink-0 text-brand-300" />
              <div>
                <h3 className="text-base font-semibold text-white">Conferma analisi con tool esterni</h3>
                <p className="mt-2 text-sm text-slate-300">
                  Verranno inviati solo gli IP pubblici osservati nel PCAP a servizi esterni per recuperare ASN,
                  RDAP, reverse DNS e dati GeoIP. Gli IP privati, locali e riservati saranno scartati dal backend.
                </p>
                <p className="mt-2 text-xs text-slate-500">
                  Fonti usate: RDAP/IANA, Team Cymru, resolver DNS inverso e ip-api.
                </p>
              </div>
            </div>

            <div className="mt-5 flex justify-end gap-2">
              <button
                onClick={() => setExternalConfirmOpen(false)}
                className="rounded-lg bg-slate-700 px-4 py-2 text-sm text-slate-200 hover:bg-slate-600"
              >
                Annulla
              </button>
              <button
                onClick={handleExternalAnalysis}
                className="rounded-lg bg-brand-500 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-400"
              >
                Confermo e analizza
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
