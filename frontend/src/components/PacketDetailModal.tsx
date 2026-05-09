import { useState, useEffect, useCallback } from 'react'
import { X, ChevronDown, ChevronRight, ChevronLeft, ChevronRight as ChevronRightNav, Copy, Check } from 'lucide-react'
import type { PacketEntry, LayerInfo } from '../types/analysis'
import { protocolColor } from '../utils/format'

// ─── Nomi colore per i layer (diversi dal protocol applicativo) ─────────────

const LAYER_COLORS: Record<string, string> = {
  'Ethernet II':                    '#94a3b8',
  'Internet Protocol v4':           '#60a5fa',
  'Internet Protocol v6':           '#2dd4bf',
  'Transmission Control Protocol':  '#6366f1',
  'User Datagram Protocol':         '#06b6d4',
  'Internet Control Message Protocol': '#f97316',
  'Domain Name System':             '#eab308',
  'Address Resolution Protocol':    '#ec4899',
  'Data':                           '#64748b',
  'Padding':                        '#374151',
}

function layerColor(display: string): string {
  return LAYER_COLORS[display] ?? '#818cf8'
}

// ─── Componente: riga singola di un layer ────────────────────────────────────

function FieldRow({ name, value }: { name: string; value: string }) {
  const isDecoded = name.startsWith('[')
  return (
    <div className={`flex gap-3 px-4 py-1 hover:bg-slate-700/20 text-xs font-mono ${isDecoded ? 'border-t border-slate-700/40' : ''}`}>
      <span className="text-slate-500 w-40 shrink-0 truncate" title={name}>
        {isDecoded ? <span className="text-slate-400 italic">{name}</span> : name}
      </span>
      <span className={`break-all leading-relaxed ${isDecoded ? 'text-green-400/80 whitespace-pre-wrap' : 'text-slate-200'}`}>
        {value}
      </span>
    </div>
  )
}

// ─── Componente: sezione layer (collassabile) ─────────────────────────────────

function LayerSection({ layer, defaultOpen }: { layer: LayerInfo; defaultOpen: boolean }) {
  const [open, setOpen] = useState(defaultOpen)
  const color = layerColor(layer.display)

  return (
    <div className="border border-slate-700/60 rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2.5 px-4 py-2 bg-slate-700/30 hover:bg-slate-700/50 transition-colors text-left"
      >
        {open
          ? <ChevronDown  className="w-3.5 h-3.5 text-slate-400 shrink-0" />
          : <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />}

        <span
          className="text-xs font-semibold px-2 py-0.5 rounded shrink-0"
          style={{ backgroundColor: color + '22', color }}
        >
          {layer.name}
        </span>

        <span className="text-xs text-slate-300 font-medium truncate">
          {layer.display}
        </span>

        <span className="ml-auto text-[10px] text-slate-600 shrink-0">
          {layer.fields.length} campi
        </span>
      </button>

      {open && layer.fields.length > 0 && (
        <div className="divide-y divide-slate-700/20 bg-slate-800/40">
          {layer.fields.map((f, i) => (
            <FieldRow key={i} name={f.name} value={f.value} />
          ))}
        </div>
      )}

      {open && layer.fields.length === 0 && (
        <p className="px-4 py-2 text-xs text-slate-600 italic">No field available</p>
      )}
    </div>
  )
}

// ─── Componente: hex dump ─────────────────────────────────────────────────────

function HexDump({ hex }: { hex: string }) {
  const [copied, setCopied] = useState(false)

  const bytes = hex.match(/.{1,2}/g) ?? []
  const lines: { offset: string; hexPart: string; asciiPart: string }[] = []

  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16)
    const left  = chunk.slice(0, 8)
    const right = chunk.slice(8)

    const hexLeft  = left.join(' ')
    const hexRight = right.join(' ')
    const hexPart  = right.length > 0
      ? `${hexLeft.padEnd(23)}  ${hexRight}`
      : hexLeft

    const asciiPart = chunk
      .map(b => {
        const n = parseInt(b, 16)
        return n >= 32 && n < 127 ? String.fromCharCode(n) : '·'
      })
      .join('')

    lines.push({
      offset:    i.toString(16).padStart(4, '0'),
      hexPart:   hexPart.padEnd(48),
      asciiPart,
    })
  }

  const copyHex = async () => {
    await navigator.clipboard.writeText(hex)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-slate-700/60">
        <span className="text-[10px] text-slate-500 uppercase tracking-wide font-medium">
          Hex dump · {bytes.length} byte
        </span>
        <button
          onClick={copyHex}
          className="flex items-center gap-1 text-[10px] text-slate-500 hover:text-slate-300 transition-colors"
        >
          {copied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
          {copied ? 'Copiato' : 'Copia hex'}
        </button>
      </div>

      <div className="flex-1 overflow-y-auto">
        {/* Header */}
        <div className="flex gap-3 px-3 py-1 text-[9px] text-slate-600 uppercase tracking-wide border-b border-slate-700/40 font-mono sticky top-0 bg-slate-900/90">
          <span className="w-8">Offs</span>
          <span className="flex-1">00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f</span>
          <span>ASCII</span>
        </div>

        {lines.map((line, i) => (
          <div
            key={i}
            className="flex gap-3 px-3 py-0.5 hover:bg-slate-700/20 font-mono text-[11px] leading-5"
          >
            <span className="text-slate-600 w-8 shrink-0">{line.offset}</span>
            <span className="text-emerald-400/80 flex-1 whitespace-pre">{line.hexPart}</span>
            <span className="text-slate-400 whitespace-pre tracking-wide">{line.asciiPart}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Modal principale ─────────────────────────────────────────────────────────

interface PacketDetailModalProps {
  packet: PacketEntry
  allPackets: PacketEntry[]
  currentIndex: number
  onNavigate: (index: number) => void
  onClose: () => void
}

export default function PacketDetailModal({
  packet,
  allPackets,
  currentIndex,
  onNavigate,
  onClose,
}: PacketDetailModalProps) {
  const [activeTab, setActiveTab] = useState<'layers' | 'hex'>('layers')
  const color = protocolColor(packet.protocol)

  const canPrev = currentIndex > 0
  const canNext = currentIndex < allPackets.length - 1

  const handlePrev = useCallback(() => { if (canPrev) onNavigate(currentIndex - 1) }, [canPrev, currentIndex, onNavigate])
  const handleNext = useCallback(() => { if (canNext) onNavigate(currentIndex + 1) }, [canNext, currentIndex, onNavigate])

  // Keyboard navigation
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape')      onClose()
      if (e.key === 'ArrowLeft')   handlePrev()
      if (e.key === 'ArrowRight')  handleNext()
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose, handlePrev, handleNext])

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
      onClick={e => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="bg-slate-800 border border-slate-700 rounded-2xl w-full max-w-5xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">

        {/* ── Header ────────────────────────────────────────────────────── */}
        <div className="flex items-center gap-3 px-5 py-3 border-b border-slate-700 shrink-0">
          {/* Protocol badge */}
          <span
            className="protocol-badge text-sm"
            style={{ backgroundColor: color + '22', color }}
          >
            {packet.protocol}
          </span>

          {/* Packet info */}
          <div className="flex items-center gap-3 flex-1 min-w-0 font-mono text-xs">
            <span className="text-slate-300 font-semibold">#{packet.number}</span>
            <span className="text-slate-500">{packet.timestamp}</span>
            {packet.src_ip && (
              <>
                <span className="text-slate-300 truncate">
                  {packet.src_ip}{packet.src_port ? `:${packet.src_port}` : ''}
                </span>
                <span className="text-slate-600">→</span>
                <span className="text-slate-300 truncate">
                  {packet.dst_ip}{packet.dst_port ? `:${packet.dst_port}` : ''}
                </span>
              </>
            )}
            <span className="text-slate-600 ml-auto shrink-0">{packet.length} byte</span>
          </div>

          {/* Navigation */}
          <div className="flex items-center gap-1 shrink-0">
            <button
              onClick={handlePrev}
              disabled={!canPrev}
              title="Pacchetto precedente (←)"
              className="p-1.5 rounded-lg hover:bg-slate-700 disabled:opacity-25 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronLeft className="w-4 h-4 text-slate-300" />
            </button>
            <span className="text-xs text-slate-500 w-20 text-center">
              {currentIndex + 1} / {allPackets.length}
            </span>
            <button
              onClick={handleNext}
              disabled={!canNext}
              title="Pacchetto successivo (→)"
              className="p-1.5 rounded-lg hover:bg-slate-700 disabled:opacity-25 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronRightNav className="w-4 h-4 text-slate-300" />
            </button>
          </div>

          {/* Close */}
          <button
            onClick={onClose}
            title="Chiudi (Esc)"
            className="p-1.5 rounded-lg hover:bg-slate-700 transition-colors ml-1"
          >
            <X className="w-4 h-4 text-slate-400" />
          </button>
        </div>

        {/* ── Info bar ──────────────────────────────────────────────────── */}
        <div className="px-5 py-2 bg-slate-900/40 border-b border-slate-700/50 shrink-0">
          <p className="text-xs text-slate-400 font-mono truncate" title={packet.info}>
            {packet.info || '—'}
          </p>
        </div>

        {/* ── Tab bar (mobile) ──────────────────────────────────────────── */}
        <div className="flex md:hidden border-b border-slate-700 shrink-0">
          {(['layers', 'hex'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`flex-1 py-2 text-xs font-medium transition-colors
                ${activeTab === tab
                  ? 'text-brand-400 border-b-2 border-brand-500'
                  : 'text-slate-500 hover:text-slate-300'}`}
            >
              {tab === 'layers' ? 'Layer protocollari' : 'Hex dump'}
            </button>
          ))}
        </div>

        {/* ── Body: split desktop / tab mobile ─────────────────────────── */}
        <div className="flex-1 overflow-hidden flex min-h-0">

          {/* Layer tree — sempre visibile su desktop, tab su mobile */}
          <div className={`flex-1 overflow-y-auto p-4 space-y-2 min-w-0
            ${activeTab !== 'layers' ? 'hidden md:block' : ''}`}
          >
            {packet.layers.length > 0
              ? packet.layers.map((layer, i) => (
                  <LayerSection
                    key={i}
                    layer={layer}
                    defaultOpen={i < 4}
                  />
                ))
              : (
                <div className="flex items-center justify-center h-32 text-slate-600 text-sm">
                  Layer details are not available for this packet
                </div>
              )
            }
          </div>

          {/* Divider */}
          <div className="hidden md:block w-px bg-slate-700/60 shrink-0" />

          {/* Hex dump — sempre visibile su desktop, tab su mobile */}
          <div className={`w-full md:w-[42%] shrink-0 bg-slate-900/50 min-h-0 flex flex-col
            ${activeTab !== 'hex' ? 'hidden md:flex' : 'flex'}`}
          >
            {packet.raw_hex
              ? <HexDump hex={packet.raw_hex} />
              : (
                <div className="flex items-center justify-center flex-1 text-slate-600 text-sm">
                  Dati grezzi not available
                </div>
              )
            }
          </div>
        </div>
      </div>
    </div>
  )
}
