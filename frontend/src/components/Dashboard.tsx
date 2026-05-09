/**
 * Componente principale del dashboard di analysis.
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
 * Ogni sezione is incapsulata nel suo componente dedicato per
 * mantenere il codice organizzato e facile da manutenere.
 */
import { useState } from 'react'
import { FileText, Download, BarChart2, GitBranch, Search, ShieldAlert, Globe2, Server, Lock, Monitor, CheckCircle2, Network } from 'lucide-react'
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
import HostsView from './HostsView'
import NetworkGraphView from './NetworkGraphView'
import { parsePacketFilter } from '../utils/packetFilters'

type ActiveTab = 'overview' | 'traces' | 'advanced-traces' | 'security-analysis' | 'dns-analysis' | 'http-analysis' | 'tls-analysis' | 'hosts' | 'network-graph'

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
  // Updates only IPs for which the backend returned external data.
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
  const [selectedHostIp, setSelectedHostIp] = useState<string | null>(null)
  const parsedPacketFilter = parsePacketFilter(packetFilter)
  const filteredPackets = parsedPacketFilter.error
    ? result.packets
    : result.packets.filter(parsedPacketFilter.predicate)
  const externalResultsCount = Object.keys(result.external_ip_info ?? {}).length
  const externalFeatureActive = externalResultsCount > 0 || Boolean(externalSummary && !externalError)

  const openHost = (ip: string) => {
    // Permette alle viste con IP clickbili di aprire direttamente la tab Hosts.
    setSelectedHostIp(ip)
    setActiveTab('hosts')
  }
  /**
   * Esport il risultato dell'analysis come file JSON scaricabile.
   * Utile per archiviare o condividere i data estratti dal PCAP.
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
   * Sends IPs observed in the PCAP to the backend and merges them into the current report
   * information retrieved from RDAP, ASN, reverse DNS, and GeoIP services.
   */
  const handleExternalAnalysis = async () => {
    // External-service calls start only after the consent popup.
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
        throw new Error(data.detail ?? `Error ${response.status}: ${response.statusText}`)
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

      setExternalSummary(`${enrichedCount} IPs enriched, ${skippedCount} private/local IPs not sent`)
    } catch (err) {
      setExternalError(err instanceof Error ? err.message : "Unknown error during enrichment")
    } finally {
      setExternalLoading(false)
    }
  }

  return (
    <div className="max-w-[1600px] mx-auto px-4 py-6 space-y-4">

      {/* ── Results header ────────────────────────────────────── */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <FileText className="w-5 h-5 text-brand-400" />
          <div>
            <h1 className="text-lg font-bold text-white">{result.filename}</h1>
            <p className="text-xs text-slate-500">
              {result.summary.total_packets.toLocaleString('it-IT')} packets analyzed
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
              Traces
            </button>
            <button
              onClick={() => setActiveTab('advanced-traces')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors
                ${activeTab === 'advanced-traces'
                  ? 'bg-slate-600 text-slate-100 shadow'
                  : 'text-slate-400 hover:text-slate-200'}`}
            >
              <GitBranch className="w-3.5 h-3.5" />
              Advanced traces
            </button>
            <button
              onClick={() => setActiveTab('hosts')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors
                ${activeTab === 'hosts'
                  ? 'bg-slate-600 text-slate-100 shadow'
                  : 'text-slate-400 hover:text-slate-200'}`}
            >
              <Monitor className="w-3.5 h-3.5" />
              Hosts
            </button>
            <button
              onClick={() => setActiveTab('network-graph')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors
                ${activeTab === 'network-graph'
                  ? 'bg-slate-600 text-slate-100 shadow'
                  : 'text-slate-400 hover:text-slate-200'}`}
            >
              <Network className="w-3.5 h-3.5" />
              Grafo
            </button>
            <button
              onClick={() => setActiveTab('security-analysis')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors
                ${activeTab === 'security-analysis'
                  ? 'bg-slate-600 text-slate-100 shadow'
                  : 'text-slate-400 hover:text-slate-200'}`}
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              Advanced Security
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
              onClick={() => {
                // If enrichment has already completed, do not reopen the popup.
                if (!externalFeatureActive) setExternalConfirmOpen(true)
              }}
              disabled={externalLoading || externalFeatureActive}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors
                ${externalFeatureActive
                  ? 'cursor-not-allowed border border-emerald-500/30 bg-emerald-500/15 text-emerald-100'
                  : externalLoading
                    ? 'cursor-wait bg-slate-600 text-slate-300'
                    : 'text-slate-300 hover:bg-slate-600 hover:text-slate-100'}`}
            >
              {externalFeatureActive ? <CheckCircle2 className="w-3.5 h-3.5" /> : <Search className="w-3.5 h-3.5" />}
              {externalFeatureActive ? 'External tools active' : externalLoading ? 'Retrieving info...' : 'Analyze with external tools'}
            </button>
          </div>

          {/* Export JSON */}
          <button
            onClick={handleExportJSON}
            className="flex items-center gap-2 px-3 py-1.5 bg-slate-700 hover:bg-slate-600
                       text-slate-200 text-xs rounded-lg transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Export JSON
          </button>
        </div>
      </div>

      {/* Status of external enrichment manually started by the user */}
      {(externalSummary || externalError) && (
        <div className={`rounded-lg border px-4 py-2 text-xs ${
          externalError
            ? 'border-red-500/30 bg-red-500/10 text-red-200'
            : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
        }`}>
          {externalError ?? `External tools active: ${externalSummary}`}
        </div>
      )}

      {/* ── Tab: Overview ─────────────────────────────────────────────── */}
      {activeTab === 'overview' && (
        <>
          {/* Row 1: 6 summary cards */}
          <SummaryCards result={result} />

          {/* Row 2: Wireshark-style filters applied to packet views */}
          <PacketFilters
            filter={packetFilter}
            filteredCount={filteredPackets.length}
            totalCount={result.packets.length}
            error={parsedPacketFilter.error}
            onFilterChange={setPacketFilter}
          />

          {/* Row 3: protocol distribution + top IPs */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <ProtocolChart result={result} />
            <TopIPsChart   result={result} />
          </div>

          {/* Row 4: Security findings based on collected IP information */}
          <SecurityPanel result={result} />

          {/* Row 5: world map of traffic to public IPs */}
          <WorldTrafficMap result={result} />

          {/* Row 6: traffic timeline */}
          <TimelineChart result={result} />

          {/* Row 7: top ports + conversations */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <TopPortsChart      result={result} />
            <ConversationsTable conversations={result.conversations} />
          </div>

          {/* Row 8: filtered packet list */}
          <PacketTable packets={filteredPackets} onHostClick={openHost} />
        </>
      )}

      {/* ── Tab: Traces ───────────────────────────────────────────────── */}
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

      {/* ── Tab: Advanced traces ──────────────────────────────────────── */}
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

      {/* ── Tab: Hosts ────────────────────────────────────────────────── */}
      {activeTab === 'hosts' && (
        <HostsView result={result} selectedHostIp={selectedHostIp} />
      )}

      {/* ── Tab: Network graph ────────────────────────────────────────── */}
      {activeTab === 'network-graph' && (
        <NetworkGraphView result={result} />
      )}

      {/* ── Tab: Advanced Security ────────────────────────────────────── */}
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

      {/* Privacy popup for general external IP enrichment */}
      {externalConfirmOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 px-4">
          <div className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-900 p-5 shadow-2xl">
            <div className="flex items-start gap-3">
              <Search className="mt-0.5 h-5 w-5 flex-shrink-0 text-brand-300" />
              <div>
                <h3 className="text-base font-semibold text-white">Confirm external-tool analysis</h3>
                <p className="mt-2 text-sm text-slate-300">
                  Only public IPs observed in the PCAP will be sent to external services to retrieve ASN,
                  RDAP, reverse DNS, and GeoIP data. Private, local, and reserved IPs will be discarded by the backend.
                </p>
                <p className="mt-2 text-xs text-slate-500">
                  Sources used: RDAP/IANA, Team Cymru, reverse DNS resolver, and ip-api.
                </p>
              </div>
            </div>

            <div className="mt-5 flex justify-end gap-2">
              <button
                onClick={() => setExternalConfirmOpen(false)}
                className="rounded-lg bg-slate-700 px-4 py-2 text-sm text-slate-200 hover:bg-slate-600"
              >
                Cancel
              </button>
              <button
                onClick={handleExternalAnalysis}
                className="rounded-lg bg-brand-500 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-400"
              >
                Confirm and analyze
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
