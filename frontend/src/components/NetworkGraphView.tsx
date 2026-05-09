/**
 * Vista grafo host-to-host.
 *
 * Usa un SVG leggero invece di introdurre nuove dipendenze: i nodi sono IP/host
 * e gli archi aggregano uno o piu flow tra la stessa coppia. Per mantenere
 * performance accettabili vengono considerati i flow piu pesanti e i nodi
 * vengono disposti su anelli deterministici.
 */
import { useMemo, useState } from 'react'
import { AlertTriangle, Filter, GitBranch, Network, Server, ShieldAlert } from 'lucide-react'
import type { AnalysisResult, FlowEntry, HostEntry, IPExternalInfo } from '../types/analysis'
import { formatBytes, formatCount, protocolColor } from '../utils/format'

interface NetworkGraphViewProps {
  result: AnalysisResult
}

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'none'
type ScopeFilter = 'all' | 'internal' | 'external' | 'mixed'
type WeightMode = 'bytes' | 'packets'

interface GraphNode {
  id: string
  host: HostEntry | null
  label: string
  isPrivate: boolean
  severity: Severity
  findings: string[]
  flowIds: string[]
  bytes: number
  packets: number
  x: number
  y: number
}

interface GraphEdge {
  id: string
  source: string
  target: string
  protocols: string[]
  flows: FlowEntry[]
  bytes: number
  packets: number
}

interface SelectedNode {
  kind: 'node'
  node: GraphNode
}

interface SelectedEdge {
  kind: 'edge'
  edge: GraphEdge
}

type Selection = SelectedNode | SelectedEdge | null

const GRAPH_WIDTH = 980
const GRAPH_HEIGHT = 560
const MAX_FLOWS = 350
const MAX_NODES = 140

const severityRank: Record<Severity, number> = {
  none: 0,
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
}

function hostMap(result: AnalysisResult) {
  // Indicizza gli host prodotti dal backend; i report vecchi possono non avere `hosts`.
  const map = new Map<string, HostEntry>()
  for (const host of result.hosts?.hosts ?? []) {
    map.set(host.ip, host)
  }
  return map
}

function externalForIp(result: AnalysisResult, ip: string): IPExternalInfo | null {
  // Recupera indicatori esterni gia disponibili dopo "Analizza con tool esterni".
  return (
    result.external_ip_info?.[ip]
    ?? result.top_src_ips.find((entry) => entry.ip === ip)?.external
    ?? result.top_dst_ips.find((entry) => entry.ip === ip)?.external
    ?? null
  )
}

function fallbackPrivate(ip: string): boolean {
  // Fallback semplice lato frontend per report vecchi senza `hosts`.
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|127\.|169\.254\.)/.test(ip)
}

function severityForHost(host: HostEntry | null, external: IPExternalInfo | null): Severity {
  // Stima severita dal materiale disponibile nella vista host e dall'enrichment.
  const findings = host?.findings ?? []
  const text = findings.join(' ').toLowerCase()
  if (text.includes('crit') || text.includes('malware') || text.includes('c2')) return 'critical'
  if (text.includes('scaduto') || text.includes('tls vecchio') || text.includes('self-signed')) return 'high'
  if (text.includes('http in chiaro') || text.includes('sni mancante') || external?.proxy || external?.hosting) return 'medium'
  if (findings.length > 0) return 'low'
  return 'none'
}

function nodeColor(severity: Severity, isPrivate: boolean): string {
  // Colore del nodo: finding prima, altrimenti distinzione interno/esterno.
  if (severity === 'critical') return '#ef4444'
  if (severity === 'high') return '#f97316'
  if (severity === 'medium') return '#eab308'
  if (severity === 'low') return '#38bdf8'
  if (severity === 'info') return '#94a3b8'
  return isPrivate ? '#22c55e' : '#6366f1'
}

function nodeRadius(node: GraphNode): number {
  // Scala compatta basata sul volume per evitare nodi enormi su catture sbilanciate.
  return Math.max(8, Math.min(22, 7 + Math.log10(Math.max(node.bytes, 1))))
}

function shortLabel(ip: string): string {
  // Accorcia IPv6 o host molto lunghi dentro il canvas.
  return ip.length > 18 ? `${ip.slice(0, 16)}...` : ip
}

function edgeKey(flow: FlowEntry): string {
  // Aggrega flow tra la stessa coppia host indipendentemente dalla direzione.
  return flow.src_ip <= flow.dst_ip ? `${flow.src_ip}<->${flow.dst_ip}` : `${flow.dst_ip}<->${flow.src_ip}`
}

function passScope(edge: GraphEdge, nodes: Map<string, GraphNode>, scope: ScopeFilter): boolean {
  // Applica filtro interno/esterno sul tipo di comunicazione.
  if (scope === 'all') return true
  const source = nodes.get(edge.source)
  const target = nodes.get(edge.target)
  if (!source || !target) return false
  if (scope === 'internal') return source.isPrivate && target.isPrivate
  if (scope === 'external') return !source.isPrivate && !target.isPrivate
  return source.isPrivate !== target.isPrivate
}

function passSeverity(edge: GraphEdge, nodes: Map<string, GraphNode>, severity: Severity | 'all'): boolean {
  // Mantiene un arco se almeno uno dei due nodi soddisfa la severita richiesta.
  if (severity === 'all') return true
  const source = nodes.get(edge.source)
  const target = nodes.get(edge.target)
  if (!source || !target) return false
  return source.severity === severity || target.severity === severity
}

function buildGraph(result: AnalysisResult, protocolFilter: string, scopeFilter: ScopeFilter, severityFilter: Severity | 'all') {
  const hosts = hostMap(result)
  const selectedFlows = [...(result.flows ?? [])]
    .filter((flow) => protocolFilter === 'all' || flow.protocol === protocolFilter)
    .sort((left, right) => right.bytes_total - left.bytes_total)
    .slice(0, MAX_FLOWS)

  const edgeBuckets = new Map<string, GraphEdge>()
  for (const flow of selectedFlows) {
    const key = edgeKey(flow)
    const current = edgeBuckets.get(key)
    const source = flow.src_ip <= flow.dst_ip ? flow.src_ip : flow.dst_ip
    const target = flow.src_ip <= flow.dst_ip ? flow.dst_ip : flow.src_ip
    if (!current) {
      edgeBuckets.set(key, {
        id: key,
        source,
        target,
        protocols: [flow.protocol],
        flows: [flow],
        bytes: flow.bytes_total,
        packets: flow.packets_total,
      })
    } else {
      current.flows.push(flow)
      current.bytes += flow.bytes_total
      current.packets += flow.packets_total
      if (!current.protocols.includes(flow.protocol)) current.protocols.push(flow.protocol)
    }
  }

  const nodeIds = new Set<string>()
  const nodeFlowIds = new Map<string, Set<string>>()
  const nodeTraffic = new Map<string, { bytes: number; packets: number }>()
  for (const edge of edgeBuckets.values()) {
    nodeIds.add(edge.source)
    nodeIds.add(edge.target)
    for (const flow of edge.flows) {
      for (const ip of [flow.src_ip, flow.dst_ip]) {
        const flowIds = nodeFlowIds.get(ip) ?? new Set<string>()
        flowIds.add(flow.flow_id)
        nodeFlowIds.set(ip, flowIds)
        const traffic = nodeTraffic.get(ip) ?? { bytes: 0, packets: 0 }
        traffic.bytes += flow.bytes_total
        traffic.packets += flow.packets_total
        nodeTraffic.set(ip, traffic)
      }
    }
  }

  const orderedNodeIds = [...nodeIds].slice(0, MAX_NODES)
  const allowedNodes = new Set(orderedNodeIds)
  const nodes = new Map<string, GraphNode>()
  orderedNodeIds.forEach((ip, index) => {
    const host = hosts.get(ip) ?? null
    const external = externalForIp(result, ip)
    const fallbackTraffic = nodeTraffic.get(ip) ?? { bytes: 0, packets: 0 }
    const fallbackFlowIds = [...(nodeFlowIds.get(ip) ?? new Set<string>())]
    const angle = (index / Math.max(orderedNodeIds.length, 1)) * Math.PI * 2
    const ring = index % 3
    const radiusX = 260 + ring * 58
    const radiusY = 150 + ring * 34
    nodes.set(ip, {
      id: ip,
      host,
      label: host?.hostnames[0] ?? external?.reverse_dns ?? ip,
      isPrivate: host?.is_private ?? fallbackPrivate(ip),
      severity: severityForHost(host, external),
      findings: host?.findings ?? [],
      flowIds: host?.flow_ids?.length ? host.flow_ids : fallbackFlowIds,
      bytes: host ? host.bytes_sent + host.bytes_received : fallbackTraffic.bytes,
      packets: host ? host.packets_sent + host.packets_received : fallbackTraffic.packets,
      x: GRAPH_WIDTH / 2 + Math.cos(angle) * radiusX,
      y: GRAPH_HEIGHT / 2 + Math.sin(angle) * radiusY,
    })
  })

  const edges = [...edgeBuckets.values()]
    .filter((edge) => allowedNodes.has(edge.source) && allowedNodes.has(edge.target))
    .filter((edge) => passScope(edge, nodes, scopeFilter))
    .filter((edge) => passSeverity(edge, nodes, severityFilter))
    .sort((left, right) => right.bytes - left.bytes)

  const visibleNodeIds = new Set<string>()
  for (const edge of edges) {
    visibleNodeIds.add(edge.source)
    visibleNodeIds.add(edge.target)
  }

  return {
    nodes: [...nodes.values()].filter((node) => visibleNodeIds.has(node.id)),
    nodeMap: nodes,
    edges,
    limited: selectedFlows.length >= MAX_FLOWS || nodeIds.size > MAX_NODES,
  }
}

function edgeWidth(edge: GraphEdge, maxWeight: number, mode: WeightMode): number {
  // Peso visivo dell'arco basato su byte o pacchetti.
  const value = mode === 'bytes' ? edge.bytes : edge.packets
  const ratio = maxWeight > 0 ? value / maxWeight : 0
  return Math.max(1.2, Math.min(9, 1.2 + ratio * 7.8))
}

function severityBadge(severity: Severity) {
  const labels: Record<Severity, string> = {
    critical: 'critica',
    high: 'alta',
    medium: 'media',
    low: 'bassa',
    info: 'info',
    none: 'nessuna',
  }
  return labels[severity]
}

function SelectionPanel({ selection }: { selection: Selection }) {
  if (!selection) {
    return (
      <div className="card h-full">
        <h3 className="text-sm font-semibold text-slate-200">Dettaglio</h3>
        <p className="mt-2 text-xs text-slate-500">Clicca un nodo o un arco per vedere host, flow e finding collegati.</p>
      </div>
    )
  }

  if (selection.kind === 'node') {
    const node = selection.node
    const host = node.host
    return (
      <div className="card h-full overflow-hidden">
        <div className="flex items-start gap-2">
          <Server className="mt-0.5 h-4 w-4 text-brand-300" />
          <div className="min-w-0">
            <h3 className="truncate font-mono text-sm font-semibold text-slate-100">{node.id}</h3>
            <p className="truncate text-xs text-slate-500">{node.label}</p>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-2 gap-2 text-xs">
          <div className="rounded bg-slate-900/70 p-3">
            <p className="text-slate-500">Ruolo</p>
            <p className="mt-1 text-slate-200">{host?.role ?? 'ignoto'}</p>
          </div>
          <div className="rounded bg-slate-900/70 p-3">
            <p className="text-slate-500">Severità</p>
            <p className="mt-1 text-slate-200">{severityBadge(node.severity)}</p>
          </div>
          <div className="rounded bg-slate-900/70 p-3">
            <p className="text-slate-500">Traffico</p>
            <p className="mt-1 text-slate-200">{formatBytes(node.bytes)}</p>
          </div>
          <div className="rounded bg-slate-900/70 p-3">
            <p className="text-slate-500">Flow</p>
            <p className="mt-1 text-slate-200">{formatCount(node.flowIds.length)}</p>
          </div>
        </div>

        <div className="mt-4 space-y-3 text-xs">
          <div>
            <p className="mb-1 font-semibold uppercase tracking-wide text-slate-500">Protocolli</p>
            <p className="text-slate-300">{host?.protocols.join(', ') || 'n/d'}</p>
          </div>
          <div>
            <p className="mb-1 font-semibold uppercase tracking-wide text-slate-500">Host osservati</p>
            <p className="break-words text-slate-300">
              {[...(host?.hostnames ?? []), ...(host?.sni_hosts ?? []), ...(host?.http_hosts ?? [])].slice(0, 12).join(', ') || 'n/d'}
            </p>
          </div>
          <div>
            <p className="mb-1 font-semibold uppercase tracking-wide text-slate-500">Finding</p>
            {node.findings.length === 0 ? (
              <p className="text-slate-500">Nessun finding associato.</p>
            ) : (
              <div className="space-y-1">
                {node.findings.slice(0, 8).map((finding) => (
                  <div key={finding} className="rounded bg-amber-500/10 px-2 py-1 text-amber-100">{finding}</div>
                ))}
              </div>
            )}
          </div>
          <div>
            <p className="mb-1 font-semibold uppercase tracking-wide text-slate-500">Flow collegati</p>
            <div className="flex max-h-28 flex-wrap gap-1 overflow-y-auto">
              {node.flowIds.slice(0, 40).map((flowId) => (
                <span key={flowId} className="rounded bg-slate-700 px-2 py-1 font-mono text-[11px] text-slate-200">{flowId}</span>
              ))}
            </div>
          </div>
        </div>
      </div>
    )
  }

  const edge = selection.edge
  return (
    <div className="card h-full overflow-hidden">
      <div className="flex items-start gap-2">
        <GitBranch className="mt-0.5 h-4 w-4 text-brand-300" />
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-slate-100">Arco host-to-host</h3>
          <p className="truncate font-mono text-xs text-slate-500">{edge.source} ↔ {edge.target}</p>
        </div>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-2 text-xs">
        <div className="rounded bg-slate-900/70 p-3">
          <p className="text-slate-500">Flow</p>
          <p className="mt-1 text-slate-200">{formatCount(edge.flows.length)}</p>
        </div>
        <div className="rounded bg-slate-900/70 p-3">
          <p className="text-slate-500">Traffico</p>
          <p className="mt-1 text-slate-200">{formatBytes(edge.bytes)}</p>
        </div>
      </div>

      <div className="mt-4 max-h-[430px] space-y-2 overflow-y-auto">
        {edge.flows.map((flow) => (
          <div key={flow.flow_id} className="rounded-lg border border-slate-700 bg-slate-900/70 p-3 text-xs">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-slate-100">{flow.flow_id}</span>
              <span className="rounded bg-slate-700 px-2 py-0.5 text-[11px] text-slate-300">{flow.protocol}</span>
            </div>
            <p className="mt-1 font-mono text-slate-500">
              {flow.src_ip}:{flow.src_port ?? '-'} → {flow.dst_ip}:{flow.dst_port ?? '-'}
            </p>
            <p className="mt-1 text-slate-400">
              {formatBytes(flow.bytes_total)} · {formatCount(flow.packets_total)} pacchetti · {flow.state}
            </p>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function NetworkGraphView({ result }: NetworkGraphViewProps) {
  const [protocolFilter, setProtocolFilter] = useState('all')
  const [scopeFilter, setScopeFilter] = useState<ScopeFilter>('all')
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all')
  const [weightMode, setWeightMode] = useState<WeightMode>('bytes')
  const [selection, setSelection] = useState<Selection>(null)

  const protocols = useMemo(() => ['all', ...new Set((result.flows ?? []).map((flow) => flow.protocol).sort())], [result.flows])
  const graph = useMemo(
    () => buildGraph(result, protocolFilter, scopeFilter, severityFilter),
    [protocolFilter, result, scopeFilter, severityFilter],
  )
  const maxWeight = Math.max(...graph.edges.map((edge) => weightMode === 'bytes' ? edge.bytes : edge.packets), 0)

  return (
    <div className="space-y-4">
      <div className="card">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-slate-200">Grafo di rete</h2>
            <p className="mt-1 max-w-3xl text-xs text-slate-500">
              Grafo host-to-host basato sui flow 5-tuple. Ogni nodo è un IP/host, ogni arco aggrega i flow tra due host.
            </p>
          </div>
          {graph.limited && (
            <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-100">
              <AlertTriangle className="h-4 w-4" />
              Vista limitata ai flow più pesanti
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="grid grid-cols-1 gap-2 lg:grid-cols-[1fr_170px_170px_170px_170px]">
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <Network className="h-4 w-4 text-brand-300" />
            {formatCount(graph.nodes.length)} nodi · {formatCount(graph.edges.length)} archi · peso su {weightMode === 'bytes' ? 'byte' : 'pacchetti'}
          </div>
          <select value={protocolFilter} onChange={(event) => setProtocolFilter(event.target.value)} className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200">
            {protocols.map((item) => <option key={item} value={item}>{item === 'all' ? 'Protocollo' : item}</option>)}
          </select>
          <select value={scopeFilter} onChange={(event) => setScopeFilter(event.target.value as ScopeFilter)} className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200">
            <option value="all">Interni/esterni</option>
            <option value="internal">Solo interni</option>
            <option value="external">Solo esterni</option>
            <option value="mixed">Interno ↔ esterno</option>
          </select>
          <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value as Severity | 'all')} className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200">
            <option value="all">Severità finding</option>
            <option value="critical">Critica</option>
            <option value="high">Alta</option>
            <option value="medium">Media</option>
            <option value="low">Bassa</option>
            <option value="none">Nessun finding</option>
          </select>
          <select value={weightMode} onChange={(event) => setWeightMode(event.target.value as WeightMode)} className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200">
            <option value="bytes">Peso: byte</option>
            <option value="packets">Peso: pacchetti</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1fr_360px]">
        <section className="card overflow-hidden">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap gap-2 text-[11px] text-slate-400">
              <span className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-emerald-500" /> interno</span>
              <span className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-indigo-500" /> esterno</span>
              <span className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-amber-500" /> finding</span>
              <span className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-red-500" /> severità alta/critica</span>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-500">
              <Filter className="h-3.5 w-3.5" />
              Clicca nodi o archi per i dettagli
            </div>
          </div>

          <div className="overflow-x-auto rounded-lg border border-slate-700 bg-slate-950">
            <svg viewBox={`0 0 ${GRAPH_WIDTH} ${GRAPH_HEIGHT}`} className="h-[560px] min-w-[980px] w-full">
              <defs>
                <marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto" markerUnits="strokeWidth">
                  <path d="M0,0 L0,6 L7,3 z" fill="#64748b" />
                </marker>
              </defs>

              {graph.edges.map((edge) => {
                const source = graph.nodeMap.get(edge.source)
                const target = graph.nodeMap.get(edge.target)
                if (!source || !target) return null
                const width = edgeWidth(edge, maxWeight, weightMode)
                const color = edge.protocols.length === 1 ? protocolColor(edge.protocols[0]) : '#64748b'
                return (
                  <g key={edge.id}>
                    <line
                      x1={source.x}
                      y1={source.y}
                      x2={target.x}
                      y2={target.y}
                      stroke={color}
                      strokeWidth={width}
                      strokeOpacity={selection?.kind === 'edge' && selection.edge.id === edge.id ? 0.95 : 0.42}
                      markerEnd="url(#arrow)"
                    />
                    <line
                      role="button"
                      tabIndex={0}
                      x1={source.x}
                      y1={source.y}
                      x2={target.x}
                      y2={target.y}
                      stroke="transparent"
                      strokeWidth={Math.max(12, width + 8)}
                      className="cursor-pointer"
                      onClick={() => setSelection({ kind: 'edge', edge })}
                    />
                  </g>
                )
              })}

              {graph.nodes.map((node) => {
                const radius = nodeRadius(node)
                const fill = nodeColor(node.severity, node.isPrivate)
                return (
                  <g
                    key={node.id}
                    role="button"
                    tabIndex={0}
                    className="cursor-pointer"
                    onClick={() => setSelection({ kind: 'node', node })}
                  >
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={radius + 5}
                      fill={selection?.kind === 'node' && selection.node.id === node.id ? fill : 'transparent'}
                      opacity="0.18"
                    />
                    <circle cx={node.x} cy={node.y} r={radius} fill={fill} stroke="#0f172a" strokeWidth="2" />
                    {severityRank[node.severity] >= severityRank.medium && (
                      <ShieldAlert x={node.x - 7} y={node.y - 7} width={14} height={14} color="#0f172a" />
                    )}
                    <text x={node.x} y={node.y + radius + 14} textAnchor="middle" className="fill-slate-300 text-[10px] font-mono">
                      {shortLabel(node.id)}
                    </text>
                  </g>
                )
              })}
            </svg>
          </div>

          {graph.nodes.length === 0 && (
            <p className="py-8 text-center text-sm text-slate-500">Nessun flow corrisponde ai filtri selezionati.</p>
          )}
        </section>

        <SelectionPanel selection={selection} />
      </div>
    </div>
  )
}
