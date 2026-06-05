/**
 * Vista di correlazione MAC/IP.
 *
 * Usa la sezione `mac_correlations` prodotta dal backend. Per i report vecchi
 * mostra una tab vuota invece di dedurre dati incompleti dai soli pacchetti
 * persistiti nel JSON.
 */
import { useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, Cpu, Filter, Search } from 'lucide-react'
import type { AnalysisResult, MACExternalInfo, MACIPCorrelation } from '../types/analysis'
import { formatBytes, formatCount } from '../utils/format'

interface MACIPCorrelationViewProps {
  result: AnalysisResult
  onHostClick?: (ip: string) => void
}

function chips(values: string[], onClick?: (value: string) => void, empty = 'n/d') {
  if (values.length === 0) return <span className="text-xs text-slate-600">{empty}</span>

  return (
    <div className="flex flex-wrap gap-1.5">
      {values.slice(0, 24).map((value) => {
        const clickable = Boolean(onClick)
        return (
          <button
            key={value}
            type="button"
            onClick={clickable ? () => onClick?.(value) : undefined}
            className={`rounded bg-slate-700 px-2 py-1 font-mono text-[11px] text-slate-200 ${
              clickable ? 'hover:bg-brand-500/40 hover:text-white' : ''
            }`}
          >
            {value}
          </button>
        )
      })}
      {values.length > 24 && (
        <span className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-500">+{values.length - 24}</span>
      )}
    </div>
  )
}

function externalForMac(result: AnalysisResult, entry: MACIPCorrelation): MACExternalInfo | null {
  return entry.external ?? result.external_mac_info?.[entry.mac] ?? null
}

function rowVendor(external: MACExternalInfo | null): string {
  if (external?.vendor) return external.vendor
  if (external?.status === 'skipped') return 'lookup saltato'
  if (external?.status === 'error') return 'vendor non trovato'
  return 'vendor n/d'
}

function MACDetails({
  entry,
  external,
  onHostClick,
}: {
  entry: MACIPCorrelation
  external: MACExternalInfo | null
  onHostClick?: (ip: string) => void
}) {
  return (
    <div className="border-t border-slate-700/60 bg-slate-900/35 px-4 py-4">
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <section className="rounded-lg border border-slate-700 bg-slate-800/60 p-4">
          <h4 className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500">Identità</h4>
          <div className="space-y-2 text-xs text-slate-300">
            <p><span className="text-slate-500">MAC:</span> <span className="font-mono">{entry.mac}</span></p>
            <p><span className="text-slate-500">Prima vista:</span> {entry.first_seen ?? 'n/d'}</p>
            <p><span className="text-slate-500">Ultima vista:</span> {entry.last_seen ?? 'n/d'}</p>
            <p><span className="text-slate-500">OUI:</span> {external?.oui ?? entry.mac.slice(0, 8).toUpperCase().replace(/:/g, '-')}</p>
            <div className="rounded-lg border border-brand-500/20 bg-brand-500/10 p-3">
              <p className="font-semibold text-brand-100">Produttore</p>
              <p className="mt-1 text-slate-300">{rowVendor(external)}</p>
              {external?.reason && <p className="mt-1 text-slate-500">{external.reason}</p>}
            </div>
          </div>
        </section>

        <section className="rounded-lg border border-slate-700 bg-slate-800/60 p-4">
          <h4 className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500">IP correlati</h4>
          <div className="space-y-3">
            <div>
              <p className="mb-1 text-xs text-slate-500">Come sorgente</p>
              {chips(entry.src_ips, onHostClick, 'nessun IP sorgente')}
            </div>
            <div>
              <p className="mb-1 text-xs text-slate-500">Come destinazione</p>
              {chips(entry.dst_ips, onHostClick, 'nessun IP destinazione')}
            </div>
          </div>
        </section>

        <section className="rounded-lg border border-slate-700 bg-slate-800/60 p-4">
          <h4 className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500">Traffico L2</h4>
          <div className="space-y-3">
            <div>
              <p className="mb-1 text-xs text-slate-500">Protocolli</p>
              {chips(entry.protocols)}
            </div>
            <div>
              <p className="mb-1 text-xs text-slate-500">Peer MAC</p>
              {chips(entry.peer_macs, undefined, 'nessun peer')}
            </div>
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="rounded bg-slate-900 p-3">
                <p className="text-slate-500">Inviati</p>
                <p className="mt-1 font-semibold text-slate-100">{formatCount(entry.packets_sent)} pkt</p>
                <p className="text-slate-400">{formatBytes(entry.bytes_sent)}</p>
              </div>
              <div className="rounded bg-slate-900 p-3">
                <p className="text-slate-500">Ricevuti</p>
                <p className="mt-1 font-semibold text-slate-100">{formatCount(entry.packets_received)} pkt</p>
                <p className="text-slate-400">{formatBytes(entry.bytes_received)}</p>
              </div>
            </div>
          </div>
        </section>
      </div>
    </div>
  )
}

export default function MACIPCorrelationView({ result, onHostClick }: MACIPCorrelationViewProps) {
  const [query, setQuery] = useState('')
  const [vendorFilter, setVendorFilter] = useState('all')
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  const entries = result.mac_correlations ?? []
  const filtered = useMemo(() => {
    const text = query.trim().toLowerCase()
    return entries.filter((entry) => {
      const external = externalForMac(result, entry)
      if (vendorFilter === 'known' && !external?.vendor) return false
      if (vendorFilter === 'unknown' && external?.vendor) return false
      if (!text) return true

      const haystack = [
        entry.mac,
        ...entry.ips,
        ...entry.src_ips,
        ...entry.dst_ips,
        ...entry.peer_macs,
        external?.vendor ?? '',
        external?.oui ?? '',
      ].join(' ').toLowerCase()
      return haystack.includes(text)
    })
  }, [entries, query, result, vendorFilter])

  const toggle = (mac: string) => {
    setExpanded((current) => {
      const next = new Set(current)
      if (next.has(mac)) next.delete(mac)
      else next.add(mac)
      return next
    })
  }

  const knownVendors = entries.filter((entry) => Boolean(externalForMac(result, entry)?.vendor)).length

  return (
    <div className="space-y-4">
      <div className="card">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-slate-200">MAC/IP</h2>
            <p className="mt-1 max-w-3xl text-xs text-slate-500">
              Correlazione tra indirizzi MAC visibili nel PCAP e indirizzi IP osservati, con vendor OUI dopo l'analisi esterna.
            </p>
          </div>
          <div className="text-right text-xs text-slate-500">
            <strong className="text-slate-200">{formatCount(entries.length)}</strong> MAC osservati
            <div>{formatCount(knownVendors)} vendor rilevati</div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="grid grid-cols-1 gap-2 md:grid-cols-[1fr_180px]">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Cerca MAC, IP, vendor, OUI o peer..."
              className="w-full rounded-lg border border-slate-700 bg-slate-900 py-2 pl-9 pr-3 text-sm text-slate-100 placeholder-slate-600"
            />
          </div>
          <div className="relative">
            <Filter className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
            <select
              value={vendorFilter}
              onChange={(event) => setVendorFilter(event.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-900 py-2 pl-9 pr-3 text-sm text-slate-200"
            >
              <option value="all">Tutti i vendor</option>
              <option value="known">Vendor rilevato</option>
              <option value="unknown">Vendor mancante</option>
            </select>
          </div>
        </div>
      </div>

      <div className="space-y-2">
        {filtered.slice(0, 500).map((entry) => {
          const external = externalForMac(result, entry)
          const isOpen = expanded.has(entry.mac)
          const totalBytes = entry.bytes_sent + entry.bytes_received
          const totalPackets = entry.packets_sent + entry.packets_received

          return (
            <section key={entry.mac} className="overflow-hidden rounded-lg border border-slate-700 bg-slate-800">
              <button
                type="button"
                onClick={() => toggle(entry.mac)}
                className="grid w-full grid-cols-[24px_minmax(0,1fr)] items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-slate-700/45 lg:grid-cols-[24px_minmax(230px,1fr)_minmax(180px,1fr)_150px_150px]"
              >
                {isOpen ? <ChevronDown className="h-4 w-4 text-slate-400" /> : <ChevronRight className="h-4 w-4 text-slate-400" />}
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <Cpu className="h-4 w-4 text-brand-300" />
                    <span className="font-mono text-sm font-semibold text-slate-100">{entry.mac}</span>
                    {external?.vendor && (
                      <span className="rounded bg-emerald-500/10 px-2 py-0.5 text-[11px] text-emerald-200">vendor</span>
                    )}
                  </div>
                  <p className="mt-1 truncate text-xs text-slate-500">{rowVendor(external)}</p>
                </div>
                <div className="min-w-0 text-xs text-slate-400">
                  <div className="truncate font-mono">{entry.ips.slice(0, 4).join(', ') || 'IP n/d'}</div>
                  <div className="truncate text-slate-500">{entry.ips.length} IP correlati · {entry.peer_macs.length} peer MAC</div>
                </div>
                <div className="text-xs text-slate-400">
                  <div>↑ {formatBytes(entry.bytes_sent)}</div>
                  <div>↓ {formatBytes(entry.bytes_received)}</div>
                </div>
                <div className="text-xs text-slate-500">
                  <div>{formatCount(totalPackets)} pkt</div>
                  <div>{formatBytes(totalBytes)} totali</div>
                </div>
              </button>
              {isOpen && <MACDetails entry={entry} external={external} onHostClick={onHostClick} />}
            </section>
          )
        })}

        {filtered.length === 0 && (
          <p className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-8 text-center text-sm text-slate-500">
            Nessuna correlazione MAC/IP corrisponde ai filtri.
          </p>
        )}
      </div>
    </div>
  )
}
