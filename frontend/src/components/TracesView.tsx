import { useState, useMemo, useCallback } from 'react'
import { Search, X, ChevronDown, ChevronRight, ArrowRight } from 'lucide-react'
import type { PacketEntry } from '../types/analysis'
import { protocolColor, formatBytes } from '../utils/format'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Flow {
  key: string
  primarySrcIp: string
  primaryDstIp: string
  primarySrcPort: number | null
  primaryDstPort: number | null
  protocol: string
  protocols: Set<string>
  packets: PacketEntry[]
  firstTime: number
  lastTime: number
  totalBytes: number
}

interface TracesViewProps {
  packets: PacketEntry[]
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function parseTimestamp(ts: string): number {
  const parts = ts.split(':')
  if (parts.length !== 3) return 0
  return parseInt(parts[0], 10) * 3600 + parseInt(parts[1], 10) * 60 + parseFloat(parts[2])
}

function buildFlowKey(pkt: PacketEntry): string {
  const s = `${pkt.src_ip ?? '?'}:${pkt.src_port ?? 0}`
  const d = `${pkt.dst_ip ?? '?'}:${pkt.dst_port ?? 0}`
  return s < d ? `${s}↔${d}` : `${d}↔${s}`
}

function extractFlags(info: string): string[] {
  const m = info.match(/\[([^\]]+)\]/)
  return m ? m[1].split(',').map(f => f.trim()) : []
}

const FLAG_COLORS: Record<string, string> = {
  SYN: '#22c55e',
  ACK: '#3b82f6',
  PSH: '#eab308',
  FIN: '#f97316',
  RST: '#ef4444',
  URG: '#a855f7',
}

// ─── Flag badge ───────────────────────────────────────────────────────────────

function FlagBadge({ flag }: { flag: string }) {
  const color = FLAG_COLORS[flag] ?? '#64748b'
  return (
    <span
      style={{ backgroundColor: color + '22', color, border: `1px solid ${color}44` }}
      className="inline-block px-1 py-0 rounded text-[9px] font-bold font-mono leading-tight"
    >
      {flag}
    </span>
  )
}

// ─── Waterfall SVG ────────────────────────────────────────────────────────────

function WaterfallBar({
  flow,
  captureStartTime,
  captureDuration,
  timeByPkt,
}: {
  flow: Flow
  captureStartTime: number
  captureDuration: number
  timeByPkt: Map<number, number>
}) {
  const W = 1000
  const H = 28

  const flowStartX = ((flow.firstTime - captureStartTime) / captureDuration) * W
  const flowEndX   = Math.max(((flow.lastTime  - captureStartTime) / captureDuration) * W, flowStartX + 4)
  const color      = protocolColor(flow.protocol)

  return (
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="w-full h-7">
      {/* full-duration track */}
      <rect x={0} y={9} width={W} height={10} rx={2} fill="#1e293b" />

      {/* flow active span highlight */}
      <rect x={flowStartX} y={7} width={flowEndX - flowStartX} height={14} rx={2} fill={color + '28'} />

      {/* individual packets as vertical lines */}
      {flow.packets.map(pkt => {
        const t = timeByPkt.get(pkt.number) ?? flow.firstTime
        const x = ((t - captureStartTime) / captureDuration) * W
        return (
          <line
            key={pkt.number}
            x1={x} y1={3} x2={x} y2={H - 3}
            stroke={protocolColor(pkt.protocol)}
            strokeWidth={1.5}
            opacity={0.85}
          />
        )
      })}
    </svg>
  )
}

// ─── Timeline ruler ───────────────────────────────────────────────────────────

function TimelineRuler({ duration }: { duration: number }) {
  const ticks = 6
  return (
    <div className="relative h-6">
      <div className="absolute inset-x-0 top-2 border-t border-slate-700" />
      {Array.from({ length: ticks + 1 }, (_, i) => {
        const pct = (i / ticks) * 100
        const sec = (i / ticks) * duration
        return (
          <div
            key={i}
            className="absolute top-0 flex flex-col items-center"
            style={{ left: `${pct}%`, transform: 'translateX(-50%)' }}
          >
            <div className="w-px h-2 bg-slate-600 mt-1" />
            <span className="text-[9px] text-slate-500 mt-0.5 whitespace-nowrap">
              {sec >= 60
                ? `${Math.floor(sec / 60)}m${Math.floor(sec % 60).toString().padStart(2, '0')}s`
                : `+${sec.toFixed(1)}s`}
            </span>
          </div>
        )
      })}
    </div>
  )
}

// ─── Individual packet row (inside expanded flow) ─────────────────────────────

function PacketRow({
  pkt,
  flowSrcIp,
  flowFirstTime,
  timeByPkt,
  selected,
  onClick,
}: {
  pkt: PacketEntry
  flowSrcIp: string
  flowFirstTime: number
  timeByPkt: Map<number, number>
  selected: boolean
  onClick: () => void
}) {
  const t       = timeByPkt.get(pkt.number) ?? 0
  const relMs   = Math.max(0, Math.round((t - flowFirstTime) * 1000))
  const fwd     = pkt.src_ip === flowSrcIp
  const flags   = (pkt.protocol === 'TCP' || pkt.info.startsWith('[')) ? extractFlags(pkt.info) : []
  const color   = protocolColor(pkt.protocol)

  return (
    <div
      onClick={onClick}
      className={`
        flex items-center gap-2 px-3 py-1 cursor-pointer text-xs font-mono transition-colors
        border-l-2
        ${selected
          ? 'bg-brand-500/10 border-brand-500'
          : 'hover:bg-slate-700/25 border-transparent'}
      `}
    >
      <span className="text-slate-600 w-9 text-right shrink-0">{pkt.number}</span>

      <span className="text-slate-500 w-20 shrink-0 text-right">+{relMs} ms</span>

      <span className="w-4 shrink-0 text-center" style={{ color }}>
        {fwd ? '→' : '←'}
      </span>

      <span
        className="protocol-badge shrink-0"
        style={{ backgroundColor: color + '22', color }}
      >
        {pkt.protocol}
      </span>

      {flags.length > 0 && (
        <span className="flex gap-0.5 shrink-0">
          {flags.map(f => <FlagBadge key={f} flag={f} />)}
        </span>
      )}

      <span className="text-slate-400 shrink-0">
        {pkt.src_ip ?? '?'}{pkt.src_port ? `:${pkt.src_port}` : ''}
        <span className="text-slate-600 mx-1">›</span>
        {pkt.dst_ip ?? '?'}{pkt.dst_port ? `:${pkt.dst_port}` : ''}
      </span>

      <span className="text-slate-500 truncate flex-1 min-w-0">{pkt.info}</span>

      <span className="text-slate-600 shrink-0 w-14 text-right">{pkt.length} B</span>
    </div>
  )
}

// ─── Flow row ─────────────────────────────────────────────────────────────────

const LEFT_W = 'w-[18rem] shrink-0'

function FlowRow({
  flow,
  expanded,
  onToggle,
  captureStartTime,
  captureDuration,
  timeByPkt,
  selectedPacket,
  onSelectPacket,
}: {
  flow: Flow
  expanded: boolean
  onToggle: () => void
  captureStartTime: number
  captureDuration: number
  timeByPkt: Map<number, number>
  selectedPacket: PacketEntry | null
  onSelectPacket: (p: PacketEntry) => void
}) {
  const durationMs = Math.round((flow.lastTime - flow.firstTime) * 1000)
  const color      = protocolColor(flow.protocol)

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
      {/* Header */}
      <div
        onClick={onToggle}
        className="flex items-center gap-2 px-3 py-2 cursor-pointer hover:bg-slate-700/30 transition-colors"
      >
        {/* expand icon */}
        <span className="text-slate-500 shrink-0">
          {expanded
            ? <ChevronDown  className="w-3.5 h-3.5" />
            : <ChevronRight className="w-3.5 h-3.5" />}
        </span>

        {/* left panel: protocol + endpoints + stats */}
        <div className={`${LEFT_W} flex items-center gap-2 min-w-0`}>
          <span
            className="protocol-badge shrink-0"
            style={{ backgroundColor: color + '22', color }}
          >
            {flow.protocol}
          </span>

          <div className="flex items-center gap-1 font-mono text-xs min-w-0 truncate">
            <span className="text-slate-300 truncate">
              {flow.primarySrcIp}{flow.primarySrcPort ? `:${flow.primarySrcPort}` : ''}
            </span>
            <ArrowRight className="w-2.5 h-2.5 text-slate-600 shrink-0" />
            <span className="text-slate-300 truncate">
              {flow.primaryDstIp}{flow.primaryDstPort ? `:${flow.primaryDstPort}` : ''}
            </span>
          </div>
        </div>

        {/* stats */}
        <div className="flex items-center gap-3 shrink-0 text-xs">
          <span className="text-slate-400 w-14 text-right">
            {flow.packets.length} pkt
          </span>
          <span className="text-slate-500 w-16 text-right">
            {formatBytes(flow.totalBytes)}
          </span>
          <span className="text-slate-600 w-14 text-right">
            {durationMs >= 1000
              ? `${(durationMs / 1000).toFixed(2)}s`
              : `${durationMs}ms`}
          </span>
        </div>

        {/* waterfall — takes remaining width */}
        <div className="flex-1 min-w-0">
          <WaterfallBar
            flow={flow}
            captureStartTime={captureStartTime}
            captureDuration={captureDuration}
            timeByPkt={timeByPkt}
          />
        </div>
      </div>

      {/* Expanded packet list */}
      {expanded && (
        <div className="border-t border-slate-700/50 divide-y divide-slate-700/20">
          {flow.packets.map(pkt => (
            <PacketRow
              key={pkt.number}
              pkt={pkt}
              flowSrcIp={flow.primarySrcIp}
              flowFirstTime={flow.firstTime}
              timeByPkt={timeByPkt}
              selected={selectedPacket?.number === pkt.number}
              onClick={() => onSelectPacket(pkt)}
            />
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Packet detail side-panel ─────────────────────────────────────────────────

function PacketDetailPanel({
  packet,
  captureStartTime,
  timeByPkt,
  onClose,
}: {
  packet: PacketEntry
  captureStartTime: number
  timeByPkt: Map<number, number>
  onClose: () => void
}) {
  const t     = timeByPkt.get(packet.number) ?? 0
  const relS  = (t - captureStartTime).toFixed(6)
  const flags = extractFlags(packet.info)
  const color = protocolColor(packet.protocol)

  const fields: [string, string][] = [
    ['#',            String(packet.number)],
    ['Timestamp',    packet.timestamp],
    ['Tempo relativo', `+${relS} s`],
    ['Sorgente',     `${packet.src_ip ?? '—'}${packet.src_port ? `:${packet.src_port}` : ''}`],
    ['Destinazione', `${packet.dst_ip ?? '—'}${packet.dst_port ? `:${packet.dst_port}` : ''}`],
    ['Protocol',   packet.protocol],
    ['Lunghezza',    `${packet.length} byte`],
    ['Info',         packet.info],
  ]

  return (
    <div className="w-64 shrink-0 bg-slate-800 border border-slate-700 rounded-xl p-4 space-y-3 sticky top-20 h-fit">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span
            className="protocol-badge"
            style={{ backgroundColor: color + '22', color }}
          >
            {packet.protocol}
          </span>
          <span className="text-sm font-semibold text-slate-200">#{packet.number}</span>
        </div>
        <button
          onClick={onClose}
          className="p-1 hover:bg-slate-700 rounded-lg transition-colors"
        >
          <X className="w-4 h-4 text-slate-400" />
        </button>
      </div>

      {flags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {flags.map(f => <FlagBadge key={f} flag={f} />)}
        </div>
      )}

      <div className="space-y-2.5">
        {fields.map(([label, value]) => (
          <div key={label}>
            <div className="text-[10px] text-slate-500 uppercase tracking-wide mb-0.5">{label}</div>
            <div className="text-xs text-slate-200 font-mono break-all leading-relaxed">{value}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Main TracesView ──────────────────────────────────────────────────────────

export default function TracesView({ packets }: TracesViewProps) {
  const [search,         setSearch]         = useState('')
  const [protocolFilter, setProtocolFilter] = useState('all')
  const [sortBy,         setSortBy]         = useState<'time' | 'packets' | 'bytes'>('time')
  const [expandedFlows,  setExpandedFlows]  = useState<Set<string>>(new Set())
  const [selectedPacket, setSelectedPacket] = useState<PacketEntry | null>(null)

  // Parse timestamps once
  const timeByPkt = useMemo(() => {
    const m = new Map<number, number>()
    packets.forEach(p => m.set(p.number, parseTimestamp(p.timestamp)))
    return m
  }, [packets])

  const captureStartTime = useMemo(() => {
    let min = Infinity
    timeByPkt.forEach(t => { if (t < min) min = t })
    return min === Infinity ? 0 : min
  }, [timeByPkt])

  const captureDuration = useMemo(() => {
    let max = -Infinity
    timeByPkt.forEach(t => { if (t > max) max = t })
    return Math.max(max - captureStartTime, 0.001)
  }, [timeByPkt, captureStartTime])

  // Build flows
  const flows = useMemo((): Flow[] => {
    const map = new Map<string, Flow>()
    packets.forEach(pkt => {
      const key = buildFlowKey(pkt)
      const t   = timeByPkt.get(pkt.number) ?? 0
      if (!map.has(key)) {
        map.set(key, {
          key,
          primarySrcIp:   pkt.src_ip   ?? '?',
          primaryDstIp:   pkt.dst_ip   ?? '?',
          primarySrcPort: pkt.src_port,
          primaryDstPort: pkt.dst_port,
          protocol:       pkt.protocol,
          protocols:      new Set([pkt.protocol]),
          packets:        [],
          firstTime:      t,
          lastTime:       t,
          totalBytes:     0,
        })
      }
      const flow = map.get(key)!
      flow.packets.push(pkt)
      flow.protocols.add(pkt.protocol)
      flow.totalBytes += pkt.length
      if (t < flow.firstTime) flow.firstTime = t
      if (t > flow.lastTime)  flow.lastTime  = t
    })
    return Array.from(map.values())
  }, [packets, timeByPkt])

  const allProtocols = useMemo(() => {
    const s = new Set(packets.map(p => p.protocol))
    return ['all', ...Array.from(s).sort()]
  }, [packets])

  const visibleFlows = useMemo(() => {
    const q = search.toLowerCase().trim()
    let result = flows.filter(flow => {
      if (protocolFilter !== 'all' && !flow.protocols.has(protocolFilter)) return false
      if (!q) return true
      return (
        flow.primarySrcIp.includes(q) ||
        flow.primaryDstIp.includes(q) ||
        flow.protocol.toLowerCase().includes(q) ||
        String(flow.primarySrcPort).includes(q) ||
        String(flow.primaryDstPort).includes(q)
      )
    })
    if (sortBy === 'time')    result = result.sort((a, b) => a.firstTime - b.firstTime)
    else if (sortBy === 'packets') result = result.sort((a, b) => b.packets.length - a.packets.length)
    else                      result = result.sort((a, b) => b.totalBytes - a.totalBytes)
    return result
  }, [flows, search, protocolFilter, sortBy])

  const toggleFlow = useCallback((key: string) => {
    setExpandedFlows(prev => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }, [])

  const handleSelectPacket = useCallback((pkt: PacketEntry) => {
    setSelectedPacket(prev => prev?.number === pkt.number ? null : pkt)
  }, [])

  const handleSearch = (q: string) => {
    setSearch(q)
    setExpandedFlows(new Set())
    setSelectedPacket(null)
  }

  return (
    <div className="flex gap-4 items-start">
      {/* ── Main flows panel ───────────────────────────────────────────── */}
      <div className="flex-1 min-w-0 space-y-3">

        {/* Filter bar */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative flex-1 min-w-48">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search by IP, port, protocol..."
              value={search}
              onChange={e => handleSearch(e.target.value)}
              className="w-full pl-9 pr-4 py-1.5 bg-slate-700/60 border border-slate-600 rounded-lg
                         text-sm text-slate-200 placeholder-slate-500
                         focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500/30"
            />
          </div>

          <select
            value={protocolFilter}
            onChange={e => setProtocolFilter(e.target.value)}
            className="px-3 py-1.5 bg-slate-700/60 border border-slate-600 rounded-lg
                       text-sm text-slate-200 focus:outline-none focus:border-brand-500"
          >
            {allProtocols.map(p => (
              <option key={p} value={p}>{p === 'all' ? 'All protocols' : p}</option>
            ))}
          </select>

          <select
            value={sortBy}
            onChange={e => setSortBy(e.target.value as typeof sortBy)}
            className="px-3 py-1.5 bg-slate-700/60 border border-slate-600 rounded-lg
                       text-sm text-slate-200 focus:outline-none focus:border-brand-500"
          >
            <option value="time">Chronological</option>
            <option value="packets">Per packets ↓</option>
            <option value="bytes">Per volume ↓</option>
          </select>

          <span className="text-xs text-slate-500 ml-auto whitespace-nowrap">
            {visibleFlows.length} flows · {packets.length} packets
          </span>
        </div>

        {/* Ruler header row */}
        <div className="flex items-center gap-2 px-3 py-1 bg-slate-800/40 border border-slate-700/40 rounded-xl">
          {/* matches expand icon width */}
          <span className="w-3.5 shrink-0" />

          {/* matches left panel width */}
          <div className={`${LEFT_W} flex items-center gap-8 text-[10px] text-slate-500 uppercase tracking-wide`}>
            <span>Flusso</span>
          </div>

          {/* matches stats column widths */}
          <div className="flex items-center gap-3 shrink-0 text-[10px] text-slate-500 uppercase tracking-wide">
            <span className="w-14 text-right">Packets</span>
            <span className="w-16 text-right">Volume</span>
            <span className="w-14 text-right">Duration</span>
          </div>

          {/* ruler timeline */}
          <div className="flex-1 min-w-0">
            <TimelineRuler duration={captureDuration} />
          </div>
        </div>

        {/* Flow rows */}
        <div className="space-y-1.5">
          {visibleFlows.map(flow => (
            <FlowRow
              key={flow.key}
              flow={flow}
              expanded={expandedFlows.has(flow.key)}
              onToggle={() => toggleFlow(flow.key)}
              captureStartTime={captureStartTime}
              captureDuration={captureDuration}
              timeByPkt={timeByPkt}
              selectedPacket={selectedPacket}
              onSelectPacket={handleSelectPacket}
            />
          ))}

          {visibleFlows.length === 0 && (
            <div className="card text-center py-14 text-slate-500 text-sm">
              No flow found for the applied filters
            </div>
          )}
        </div>
      </div>

      {/* ── Detail side-panel ──────────────────────────────────────────── */}
      {selectedPacket && (
        <PacketDetailPanel
          packet={selectedPacket}
          captureStartTime={captureStartTime}
          timeByPkt={timeByPkt}
          onClose={() => setSelectedPacket(null)}
        />
      )}
    </div>
  )
}
