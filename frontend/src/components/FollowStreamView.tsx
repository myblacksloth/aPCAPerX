import { useMemo, useState } from 'react'
import { ArrowDownUp, Binary, FileText, Search } from 'lucide-react'
import type { FollowStreamEntry } from '../types/analysis'
import { formatBytes, formatCount } from '../utils/format'

interface FollowStreamViewProps {
  streams: FollowStreamEntry[]
}

type ViewMode = 'combined' | 'client' | 'server' | 'segments'

function endpoint(stream: FollowStreamEntry) {
  // Keep endpoint formatting consistent across the stream list and details.
  return `${stream.src_ip}:${stream.src_port ?? '-'} -> ${stream.dst_ip}:${stream.dst_port ?? '-'}`
}

function directionLabel(direction: string) {
  // Translate backend direction keys into compact UI labels.
  return direction === 'client_to_server' ? 'C -> S' : 'S -> C'
}

export default function FollowStreamView({ streams }: FollowStreamViewProps) {
  const [search, setSearch] = useState('')
  const [selectedId, setSelectedId] = useState(streams[0]?.stream_id ?? '')
  const [viewMode, setViewMode] = useState<ViewMode>('combined')

  const filteredStreams = useMemo(() => {
    // Search across endpoints, protocol labels, and visible transcript text.
    const query = search.trim().toLowerCase()
    if (!query) return streams
    return streams.filter((stream) => {
      const haystack = [
        stream.stream_id,
        endpoint(stream),
        stream.transport_protocol,
        stream.application_protocol ?? '',
        stream.combined_text,
      ].join(' ').toLowerCase()
      return haystack.includes(query)
    })
  }, [search, streams])

  const selected = streams.find((stream) => stream.stream_id === selectedId) ?? filteredStreams[0] ?? streams[0]
  const transcript = selected
    ? viewMode === 'client'
      ? selected.client_text
      : viewMode === 'server'
        ? selected.server_text
        : selected.combined_text
    : ''

  if (streams.length === 0) {
    return (
      <section className="rounded-lg border border-slate-700 bg-slate-800 p-6">
        <div className="mb-2 flex items-center gap-2 text-white">
          <ArrowDownUp className="h-5 w-5 text-brand-300" />
          <h2 className="text-base font-semibold">Follow stream</h2>
        </div>
        <p className="text-sm text-slate-400">Nessun payload TCP/UDP ricostruibile in questa cattura.</p>
      </section>
    )
  }

  return (
    <section className="grid gap-4 lg:grid-cols-[360px_1fr]">
      <aside className="rounded-lg border border-slate-700 bg-slate-800 p-4">
        <div className="mb-3 flex items-center gap-2 text-white">
          <ArrowDownUp className="h-5 w-5 text-brand-300" />
          <h2 className="text-base font-semibold">Follow stream</h2>
        </div>
        <div className="relative mb-3">
          <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Cerca stream, IP, payload"
            className="w-full rounded-md border border-slate-600 bg-slate-900 py-2 pl-9 pr-3 text-sm text-slate-100"
          />
        </div>
        <div className="max-h-[620px] space-y-2 overflow-y-auto pr-1">
          {filteredStreams.map((stream) => (
            <button
              key={stream.stream_id}
              onClick={() => setSelectedId(stream.stream_id)}
              className={`w-full rounded-md border px-3 py-2 text-left text-sm transition-colors ${
                selected?.stream_id === stream.stream_id
                  ? 'border-brand-400 bg-brand-500/15'
                  : 'border-slate-700 bg-slate-900 hover:border-slate-500'
              }`}
            >
              <div className="truncate font-mono text-xs text-slate-100">{endpoint(stream)}</div>
              <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-400">
                <span>{stream.transport_protocol}</span>
                {stream.application_protocol && <span>{stream.application_protocol}</span>}
                <span>{formatBytes(stream.bytes)}</span>
                <span>{formatCount(stream.packets)} pkt</span>
                {stream.truncated && <span className="text-amber-300">troncato</span>}
              </div>
            </button>
          ))}
        </div>
      </aside>

      {selected && (
        <div className="space-y-4">
          <section className="rounded-lg border border-slate-700 bg-slate-800 p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="font-mono text-sm font-semibold text-white">{endpoint(selected)}</h3>
                <p className="mt-1 text-xs text-slate-400">
                  Stream {selected.stream_id} · {selected.transport_protocol}
                  {selected.application_protocol ? ` · ${selected.application_protocol}` : ''} · {formatBytes(selected.bytes)}
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                {(['combined', 'client', 'server', 'segments'] as ViewMode[]).map((mode) => (
                  <button
                    key={mode}
                    onClick={() => setViewMode(mode)}
                    className={`rounded-md border px-3 py-1.5 text-xs font-medium ${
                      viewMode === mode
                        ? 'border-brand-400 bg-brand-500/20 text-brand-100'
                        : 'border-slate-600 text-slate-300 hover:border-slate-400'
                    }`}
                  >
                    {mode === 'combined' ? 'Transcript' : mode === 'client' ? 'Client' : mode === 'server' ? 'Server' : 'Segmenti'}
                  </button>
                ))}
              </div>
            </div>
          </section>

          {viewMode === 'segments' ? (
            <section className="rounded-lg border border-slate-700 bg-slate-800 p-4">
              <div className="mb-3 flex items-center gap-2 text-white">
                <Binary className="h-5 w-5 text-brand-300" />
                <h3 className="text-sm font-semibold">Segmenti payload</h3>
              </div>
              <div className="space-y-3">
                {selected.segments.map((segment) => (
                  <div key={`${segment.packet_number}-${segment.direction}-${segment.sequence ?? 'udp'}`} className="rounded-md border border-slate-700 bg-slate-900 p-3">
                    <div className="mb-2 flex flex-wrap items-center gap-2 text-xs text-slate-400">
                      <span>Packet #{segment.packet_number}</span>
                      <span>{segment.timestamp}</span>
                      <span>{directionLabel(segment.direction)}</span>
                      {segment.sequence !== null && <span>seq {segment.sequence}</span>}
                      <span>{formatBytes(segment.length)}</span>
                      {segment.truncated && <span className="text-amber-300">preview troncata</span>}
                    </div>
                    <pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded bg-slate-950 p-3 font-mono text-xs text-slate-200">{segment.text || '(payload binario)'}</pre>
                    <pre className="mt-2 max-h-32 overflow-auto break-all rounded bg-slate-950 p-3 font-mono text-[11px] leading-5 text-slate-500">{segment.hex_preview}</pre>
                  </div>
                ))}
              </div>
            </section>
          ) : (
            <section className="rounded-lg border border-slate-700 bg-slate-800 p-4">
              <div className="mb-3 flex items-center gap-2 text-white">
                <FileText className="h-5 w-5 text-brand-300" />
                <h3 className="text-sm font-semibold">Transcript</h3>
              </div>
              <pre className="min-h-[420px] max-h-[720px] overflow-auto whitespace-pre-wrap rounded-md bg-slate-950 p-4 font-mono text-xs leading-5 text-slate-200">
                {transcript || '(payload non testuale o vuoto nel verso selezionato)'}
              </pre>
            </section>
          )}
        </div>
      )}
    </section>
  )
}
