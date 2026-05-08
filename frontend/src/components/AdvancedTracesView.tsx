/**
 * Vista "Tracce avanzate".
 *
 * Mostra i flow come radici di un'alberatura e i pacchetti come nodi figli.
 * Per TCP prova a correlare ACK/risposte usando seq, ack, flag e direzione.
 * Per UDP o protocolli senza ACK usa una correlazione temporale e direzionale
 * tra richiesta e risposta nello stesso flow.
 */
import { useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, GitBranch, Network, Search } from 'lucide-react'
import type { LayerInfo, PacketEntry } from '../types/analysis'
import { formatBytes, formatCount, protocolColor } from '../utils/format'

interface AdvancedTracesViewProps {
  packets: PacketEntry[]
}

interface Endpoint {
  ip: string
  port: number | null
}

interface TcpMeta {
  seq: number | null
  ack: number | null
  flags: string[]
  payloadLen: number
}

interface CorrelatedPacket {
  packet: PacketEntry
  direction: 'a-to-b' | 'b-to-a'
  time: number
  tcp: TcpMeta | null
  parentNumber: number | null
  relation: string
  children: number[]
  depth: number
}

interface AdvancedFlow {
  key: string
  a: Endpoint
  b: Endpoint
  protocol: string
  packets: CorrelatedPacket[]
  totalBytes: number
  firstTime: number
  lastTime: number
}

function parseTimestamp(ts: string): number {
  // Converte HH:MM:SS.mmm in secondi relativi alla giornata della cattura.
  const parts = ts.split(':')
  if (parts.length !== 3) return 0
  return parseInt(parts[0], 10) * 3600 + parseInt(parts[1], 10) * 60 + parseFloat(parts[2])
}

function endpointKey(endpoint: Endpoint) {
  // Rappresentazione stabile di un endpoint IP:porta.
  return `${endpoint.ip}:${endpoint.port ?? 0}`
}

function packetEndpoint(packet: PacketEntry, side: 'src' | 'dst'): Endpoint {
  // Estrae un endpoint sorgente o destinazione dal pacchetto.
  return side === 'src'
    ? { ip: packet.src_ip ?? '?', port: packet.src_port }
    : { ip: packet.dst_ip ?? '?', port: packet.dst_port }
}

function canonicalFlow(packet: PacketEntry) {
  // Normalizza la coppia di endpoint in modo che richiesta e risposta cadano nello stesso flow.
  const src = packetEndpoint(packet, 'src')
  const dst = packetEndpoint(packet, 'dst')
  return endpointKey(src) <= endpointKey(dst)
    ? { key: `${endpointKey(src)}<->${endpointKey(dst)}`, a: src, b: dst }
    : { key: `${endpointKey(dst)}<->${endpointKey(src)}`, a: dst, b: src }
}

function layerField(layer: LayerInfo | undefined, name: string) {
  // Cerca un campo dentro un layer Scapy serializzato dal backend.
  return layer?.fields.find((field) => field.name === name)?.value ?? null
}

function parseNumber(value: string | null) {
  // Scapy spesso serializza numeri come stringhe decimali: li normalizziamo.
  if (!value) return null
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : null
}

function parseTcpFlags(value: string | null, info: string) {
  // Preferisce il campo flags del layer TCP, ma gestisce anche il fallback da info.
  const source = value || info.match(/\[([^\]]+)\]/)?.[1] || ''
  const expanded: Record<string, string> = {
    S: 'SYN',
    A: 'ACK',
    F: 'FIN',
    R: 'RST',
    P: 'PSH',
    U: 'URG',
  }

  return source
    .replace(/[,\[\]]/g, ' ')
    .split(/\s+/)
    .map((flag) => expanded[flag] ?? flag.toUpperCase())
    .filter((flag) => ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG'].includes(flag))
}

function tcpMeta(packet: PacketEntry): TcpMeta | null {
  // Estrae seq/ack/flags/payloadLen dal layer TCP quando disponibile.
  const tcp = packet.layers.find((layer) => layer.name === 'TCP')
  if (!tcp && packet.protocol !== 'TCP' && !packet.info.startsWith('[')) return null

  const seq = parseNumber(layerField(tcp, 'seq'))
  const ack = parseNumber(layerField(tcp, 'ack'))
  const flags = parseTcpFlags(layerField(tcp, 'flags'), packet.info)
  const payloadMatch = packet.info.match(/Len=(\d+)/)
  const payloadLen = payloadMatch ? Number(payloadMatch[1]) : 0

  return { seq, ack, flags, payloadLen: Number.isFinite(payloadLen) ? payloadLen : 0 }
}

function expectedAck(node: CorrelatedPacket) {
  // Calcola il prossimo ACK atteso per un segmento TCP.
  if (!node.tcp || node.tcp.seq === null) return null
  const controlByte = node.tcp.flags.includes('SYN') || node.tcp.flags.includes('FIN') ? 1 : 0
  return node.tcp.seq + Math.max(node.tcp.payloadLen, 0) + controlByte
}

function relationLabel(packet: PacketEntry, tcp: TcpMeta | null, parent: CorrelatedPacket | null) {
  // Produce una descrizione leggibile del tipo di correlazione.
  if (!parent) {
    if (tcp?.flags.includes('SYN')) return 'apertura connessione'
    return 'inizio flow'
  }

  if (tcp?.flags.includes('SYN') && tcp.flags.includes('ACK')) return `risposta SYN/ACK a #${parent.packet.number}`
  if (tcp?.flags.includes('ACK') && tcp.payloadLen === 0) return `ACK di #${parent.packet.number}`
  if (packet.protocol === 'DNS' && packet.info.toLowerCase().includes('response')) return `risposta DNS a #${parent.packet.number}`
  return `risposta/correlato a #${parent.packet.number}`
}

function findParent(nodes: CorrelatedPacket[], current: CorrelatedPacket) {
  // Cerca il miglior pacchetto precedente da collegare al nodo corrente.
  const opposite = nodes
    .filter((node) => node.direction !== current.direction && node.time <= current.time)
    .reverse()

  if (current.tcp?.ack !== null && current.tcp?.ack !== undefined) {
    const ackParent = opposite.find((node) => {
      const expected = expectedAck(node)
      return expected !== null && expected === current.tcp?.ack
    })
    if (ackParent) return ackParent
  }

  if (current.tcp?.flags.includes('ACK')) {
    const recentOpposite = opposite.find((node) => current.time - node.time <= 10)
    if (recentOpposite) return recentOpposite
  }

  const requestResponse = opposite.find((node) => current.time - node.time <= 5)
  return requestResponse ?? null
}

function buildCorrelatedFlow(packets: PacketEntry[], a: Endpoint, b: Endpoint, key: string): AdvancedFlow {
  // Costruisce nodi correlati e relazioni padre/figlio per un singolo flow.
  const nodes: CorrelatedPacket[] = []
  let totalBytes = 0
  let firstTime = Infinity
  let lastTime = -Infinity
  const protocols = new Set<string>()

  for (const packet of packets.sort((left, right) => left.number - right.number)) {
    const time = parseTimestamp(packet.timestamp)
    const direction = packet.src_ip === a.ip && (packet.src_port ?? null) === a.port ? 'a-to-b' : 'b-to-a'
    const node: CorrelatedPacket = {
      packet,
      direction,
      time,
      tcp: tcpMeta(packet),
      parentNumber: null,
      relation: 'inizio flow',
      children: [],
      depth: 0,
    }

    const parent = findParent(nodes, node)
    if (parent) {
      node.parentNumber = parent.packet.number
      node.depth = Math.min(parent.depth + 1, 6)
      node.relation = relationLabel(packet, node.tcp, parent)
      parent.children.push(packet.number)
    } else {
      node.relation = relationLabel(packet, node.tcp, null)
    }

    nodes.push(node)
    protocols.add(packet.protocol)
    totalBytes += packet.length
    if (time < firstTime) firstTime = time
    if (time > lastTime) lastTime = time
  }

  return {
    key,
    a,
    b,
    protocol: [...protocols][0] ?? 'Other',
    packets: nodes,
    totalBytes,
    firstTime: firstTime === Infinity ? 0 : firstTime,
    lastTime: lastTime === -Infinity ? 0 : lastTime,
  }
}

function buildFlows(packets: PacketEntry[]) {
  // Raggruppa i pacchetti per flow bidirezionale e costruisce le alberature.
  const grouped = new Map<string, { a: Endpoint; b: Endpoint; packets: PacketEntry[] }>()

  for (const packet of packets) {
    const canonical = canonicalFlow(packet)
    const group = grouped.get(canonical.key) ?? { a: canonical.a, b: canonical.b, packets: [] }
    group.packets.push(packet)
    grouped.set(canonical.key, group)
  }

  return [...grouped.entries()]
    .map(([key, group]) => buildCorrelatedFlow(group.packets, group.a, group.b, key))
    .sort((left, right) => left.firstTime - right.firstTime)
}

function flagBadges(flags: string[]) {
  // Render compatto dei flag TCP principali.
  return flags.map((flag) => (
    <span key={flag} className="rounded border border-slate-600 bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300">
      {flag}
    </span>
  ))
}

function endpointLabel(endpoint: Endpoint) {
  // Formatta endpoint con porta opzionale.
  return `${endpoint.ip}${endpoint.port ? `:${endpoint.port}` : ''}`
}

function TreePacketRow({ node }: { node: CorrelatedPacket }) {
  const packet = node.packet
  const color = protocolColor(packet.protocol)
  const isResponse = node.parentNumber !== null
  const directionSymbol = node.direction === 'a-to-b' ? '→' : '←'

  return (
    <div className="grid grid-cols-[minmax(18rem,1.2fr)_minmax(18rem,1fr)_minmax(14rem,1fr)] items-start gap-3 border-t border-slate-700/40 px-4 py-2 text-xs">
      <div className="flex min-w-0 items-start gap-2 font-mono">
        <div className="flex shrink-0 items-center" style={{ paddingLeft: `${node.depth * 18}px` }}>
          <span className="text-slate-600">{node.depth === 0 ? '●' : '├─'}</span>
        </div>
        <span className="w-12 shrink-0 text-right text-slate-500">#{packet.number}</span>
        <span className="shrink-0 text-slate-500">{directionSymbol}</span>
        <span className="truncate text-slate-300">
          {packet.src_ip ?? '?'}{packet.src_port ? `:${packet.src_port}` : ''}
          <span className="mx-1 text-slate-600">→</span>
          {packet.dst_ip ?? '?'}{packet.dst_port ? `:${packet.dst_port}` : ''}
        </span>
      </div>

      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="protocol-badge" style={{ backgroundColor: color + '22', color }}>{packet.protocol}</span>
          {node.tcp && flagBadges(node.tcp.flags)}
          <span className={`rounded px-2 py-0.5 text-[10px] ${isResponse ? 'bg-brand-500/15 text-brand-200' : 'bg-slate-700 text-slate-300'}`}>
            {node.relation}
          </span>
        </div>
        <p className="mt-1 truncate text-slate-500">{packet.info}</p>
      </div>

      <div className="grid grid-cols-3 gap-2 text-right font-mono text-[11px] text-slate-500">
        <span>{packet.timestamp}</span>
        <span>{packet.length} B</span>
        <span>{node.children.length > 0 ? `figli: ${node.children.join(', ')}` : '—'}</span>
      </div>
    </div>
  )
}

function FlowTree({ flow }: { flow: AdvancedFlow }) {
  const [expanded, setExpanded] = useState(true)
  const color = protocolColor(flow.protocol)
  const durationMs = Math.max(0, Math.round((flow.lastTime - flow.firstTime) * 1000))

  return (
    <section className="overflow-hidden rounded-lg border border-slate-700 bg-slate-800/70">
      <button
        type="button"
        onClick={() => setExpanded((value) => !value)}
        className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-slate-700/40"
      >
        {expanded ? <ChevronDown className="h-4 w-4 text-slate-500" /> : <ChevronRight className="h-4 w-4 text-slate-500" />}
        <Network className="h-4 w-4 text-brand-300" />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="protocol-badge" style={{ backgroundColor: color + '22', color }}>{flow.protocol}</span>
            <span className="font-mono text-sm text-slate-100">{endpointLabel(flow.a)}</span>
            <span className="text-slate-600">↔</span>
            <span className="font-mono text-sm text-slate-100">{endpointLabel(flow.b)}</span>
          </div>
          <p className="mt-1 text-xs text-slate-500">
            Flow principale: connessione bidirezionale con pacchetti correlati in alberatura
          </p>
        </div>
        <div className="flex shrink-0 gap-4 text-xs text-slate-500">
          <span>{formatCount(flow.packets.length)} pkt</span>
          <span>{formatBytes(flow.totalBytes)}</span>
          <span>{durationMs >= 1000 ? `${(durationMs / 1000).toFixed(2)}s` : `${durationMs}ms`}</span>
        </div>
      </button>

      {expanded && (
        <div>
          <div className="grid grid-cols-[minmax(18rem,1.2fr)_minmax(18rem,1fr)_minmax(14rem,1fr)] gap-3 border-t border-slate-700 bg-slate-900/40 px-4 py-2 text-[10px] uppercase tracking-wide text-slate-500">
            <span>Pacchetto / direzione</span>
            <span>Correlazione logica</span>
            <span className="text-right">Tempo / byte / figli</span>
          </div>
          {flow.packets.map((node) => (
            <TreePacketRow key={node.packet.number} node={node} />
          ))}
        </div>
      )}
    </section>
  )
}

export default function AdvancedTracesView({ packets }: AdvancedTracesViewProps) {
  const [search, setSearch] = useState('')
  const [protocol, setProtocol] = useState('all')
  const [sortBy, setSortBy] = useState<'time' | 'packets' | 'bytes'>('time')
  const flows = useMemo(() => buildFlows(packets), [packets])
  const protocols = useMemo(() => ['all', ...new Set(packets.map((packet) => packet.protocol).sort())], [packets])

  const visibleFlows = useMemo(() => {
    // Applica filtri locali alla lista dei flow avanzati.
    const query = search.trim().toLowerCase()
    let result = flows.filter((flow) => {
      if (protocol !== 'all' && !flow.packets.some((node) => node.packet.protocol === protocol)) return false
      if (!query) return true
      return (
        endpointLabel(flow.a).toLowerCase().includes(query)
        || endpointLabel(flow.b).toLowerCase().includes(query)
        || flow.packets.some((node) => node.packet.info.toLowerCase().includes(query))
      )
    })

    if (sortBy === 'packets') result = [...result].sort((left, right) => right.packets.length - left.packets.length)
    else if (sortBy === 'bytes') result = [...result].sort((left, right) => right.totalBytes - left.totalBytes)
    else result = [...result].sort((left, right) => left.firstTime - right.firstTime)

    return result
  }, [flows, protocol, search, sortBy])

  return (
    <div className="space-y-4">
      <div className="card">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <GitBranch className="h-4 w-4 text-brand-400" />
            <div>
              <h2 className="text-base font-semibold text-slate-200">Tracce avanzate</h2>
              <p className="text-xs text-slate-500">
                Alberatura per flow: pacchetto, risposta e ACK correlati quando deducibili
              </p>
            </div>
          </div>
          <span className="text-xs text-slate-500">{visibleFlows.length} flow · {packets.length} pacchetti</span>
        </div>

        <div className="grid grid-cols-1 gap-2 lg:grid-cols-[1fr_180px_180px]">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Cerca IP, porta o info pacchetto..."
              className="w-full rounded-lg border border-slate-700 bg-slate-900 py-2 pl-9 pr-3 text-sm text-slate-100 placeholder-slate-600"
            />
          </div>

          <select
            value={protocol}
            onChange={(event) => setProtocol(event.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200"
          >
            {protocols.map((item) => (
              <option key={item} value={item}>{item === 'all' ? 'Tutti i protocolli' : item}</option>
            ))}
          </select>

          <select
            value={sortBy}
            onChange={(event) => setSortBy(event.target.value as typeof sortBy)}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200"
          >
            <option value="time">Cronologico</option>
            <option value="packets">Piu pacchetti</option>
            <option value="bytes">Piu volume</option>
          </select>
        </div>

        <div className="mt-4 rounded-lg border border-slate-700 bg-slate-900/50 px-4 py-3 text-xs text-slate-400">
          <strong className="text-slate-200">Legenda:</strong> il nodo radice e il flow; i nodi figli sono pacchetti.
          Le etichette "ACK di #N" e "risposta a #N" indicano il pacchetto precedente correlato tramite ACK TCP o risposta logica.
        </div>
      </div>

      <div className="space-y-3">
        {visibleFlows.map((flow) => (
          <FlowTree key={flow.key} flow={flow} />
        ))}

        {visibleFlows.length === 0 && (
          <div className="card py-12 text-center text-sm text-slate-500">
            Nessuna traccia avanzata corrisponde ai filtri applicati
          </div>
        )}
      </div>
    </div>
  )
}
