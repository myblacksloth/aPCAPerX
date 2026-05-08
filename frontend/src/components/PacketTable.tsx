import { useState, useMemo, useEffect } from 'react'
import { Search, ChevronLeft, ChevronRight, Eye } from 'lucide-react'
import type { PacketEntry } from '../types/analysis'
import { protocolColor } from '../utils/format'
import PacketDetailModal from './PacketDetailModal'

interface PacketTableProps {
  packets: PacketEntry[]
  onHostClick?: (ip: string) => void
}

const PAGE_SIZE = 50

export default function PacketTable({ packets, onHostClick }: PacketTableProps) {
  const [search,        setSearch]        = useState('')
  const [page,          setPage]          = useState(0)
  // indice nell'array `filtered` del pacchetto selezionato (null = modale chiuso)
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null)

  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim()
    if (!q) return packets
    return packets.filter(p =>
      p.src_ip?.toLowerCase().includes(q) ||
      p.dst_ip?.toLowerCase().includes(q) ||
      p.protocol.toLowerCase().includes(q) ||
      p.info.toLowerCase().includes(q) ||
      String(p.src_port).includes(q) ||
      String(p.dst_port).includes(q)
    )
  }, [packets, search])

  const handleSearch = (q: string) => {
    setSearch(q)
    setPage(0)
    setSelectedIndex(null)
  }

  useEffect(() => {
    // Quando cambia il filtro globale della dashboard, torna alla prima pagina.
    setPage(0)
    setSelectedIndex(null)
  }, [packets])

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE)
  const pageData   = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  // Indice globale (su `filtered`) dalla posizione nella pagina
  const openModal = (pageIdx: number) => {
    setSelectedIndex(page * PAGE_SIZE + pageIdx)
  }

  // Navigazione prev/next nel modale: se esce dalla pagina corrente, aggiorna la pagina
  const handleNavigate = (newIdx: number) => {
    setSelectedIndex(newIdx)
    const newPage = Math.floor(newIdx / PAGE_SIZE)
    if (newPage !== page) setPage(newPage)
  }

  return (
    <>
      <div className="card">
        {/* ── Header ───────────────────────────────────────────────────── */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <h2 className="text-base font-semibold text-slate-200">
            Lista pacchetti{' '}
            <span className="text-slate-500 text-sm font-normal">
              ({packets.length.toLocaleString('it-IT')})
            </span>
          </h2>

          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="text"
              placeholder="Filtra per IP, protocollo, info…"
              value={search}
              onChange={e => handleSearch(e.target.value)}
              className="pl-9 pr-4 py-1.5 bg-slate-700 border border-slate-600 rounded-lg
                         text-sm text-slate-200 placeholder-slate-500 w-64
                         focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500/30"
            />
          </div>
        </div>

        {/* ── Tabella ───────────────────────────────────────────────────── */}
        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="text-left text-slate-500 border-b border-slate-700">
                <th className="pb-2 font-medium pr-3 text-right">#</th>
                <th className="pb-2 font-medium pr-3">Orario</th>
                <th className="pb-2 font-medium pr-3">Sorgente</th>
                <th className="pb-2 font-medium pr-3">Destinazione</th>
                <th className="pb-2 font-medium pr-3">Protocollo</th>
                <th className="pb-2 font-medium pr-3 text-right">Len</th>
                <th className="pb-2 font-medium">Info</th>
                <th className="pb-2 font-medium w-7" />
              </tr>
            </thead>
            <tbody>
              {pageData.map((pkt, pageIdx) => {
                const globalIdx = page * PAGE_SIZE + pageIdx
                const isSelected = selectedIndex === globalIdx
                const color = protocolColor(pkt.protocol)

                return (
                  <tr
                    key={pkt.number}
                    onClick={() => openModal(pageIdx)}
                    className={`
                      border-b border-slate-700/30 cursor-pointer transition-colors group
                      ${isSelected
                        ? 'bg-brand-500/10 border-brand-500/30'
                        : 'hover:bg-slate-700/25'}
                    `}
                  >
                    <td className="py-1 pr-3 text-slate-600 text-right">{pkt.number}</td>

                    <td className="py-1 pr-3 text-slate-400">{pkt.timestamp}</td>

                    <td className="py-1 pr-3 text-slate-300">
                      {pkt.src_ip
                        ? (
                          <button
                            type="button"
                            onClick={(event) => {
                              // Rende l'IP cliccabile senza aprire l'inspector del pacchetto.
                              event.stopPropagation()
                              onHostClick?.(pkt.src_ip as string)
                            }}
                            className="font-mono text-slate-200 underline-offset-2 hover:text-brand-300 hover:underline"
                          >
                            {pkt.src_ip}{pkt.src_port ? ':' + pkt.src_port : ''}
                          </button>
                        )
                        : <span className="text-slate-600">—</span>}
                    </td>

                    <td className="py-1 pr-3 text-slate-300">
                      {pkt.dst_ip
                        ? (
                          <button
                            type="button"
                            onClick={(event) => {
                              // Rende l'IP cliccabile senza aprire l'inspector del pacchetto.
                              event.stopPropagation()
                              onHostClick?.(pkt.dst_ip as string)
                            }}
                            className="font-mono text-slate-200 underline-offset-2 hover:text-brand-300 hover:underline"
                          >
                            {pkt.dst_ip}{pkt.dst_port ? ':' + pkt.dst_port : ''}
                          </button>
                        )
                        : <span className="text-slate-600">—</span>}
                    </td>

                    <td className="py-1 pr-3">
                      <span
                        className="protocol-badge"
                        style={{ backgroundColor: color + '22', color }}
                      >
                        {pkt.protocol}
                      </span>
                    </td>

                    <td className="py-1 pr-3 text-right text-slate-400">{pkt.length}</td>

                    <td className="py-1 text-slate-400 max-w-xs truncate" title={pkt.info}>
                      {pkt.info}
                    </td>

                    {/* Icona inspector — visibile al hover o quando selezionato */}
                    <td className="py-1 text-right">
                      <Eye
                        className={`w-3.5 h-3.5 transition-opacity
                          ${isSelected ? 'opacity-100 text-brand-400' : 'opacity-0 group-hover:opacity-60 text-slate-400'}`}
                      />
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>

          {filtered.length === 0 && (
            <p className="text-slate-500 text-sm text-center py-8">
              Nessun pacchetto corrisponde alla ricerca "{search}"
            </p>
          )}
        </div>

        {/* Hint */}
        <p className="mt-2 text-[10px] text-slate-600 text-right">
          Clicca su una riga per ispezionare il pacchetto
        </p>

        {/* ── Paginazione ───────────────────────────────────────────────── */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between mt-3 pt-3 border-t border-slate-700">
            <span className="text-xs text-slate-500">
              {filtered.length.toLocaleString('it-IT')} pacchetti ·{' '}
              pagina {page + 1} di {totalPages}
            </span>

            <div className="flex gap-2">
              <button
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
                className="p-1.5 rounded-lg bg-slate-700 hover:bg-slate-600
                           disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronLeft className="w-4 h-4 text-slate-300" />
              </button>
              <button
                onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                disabled={page >= totalPages - 1}
                className="p-1.5 rounded-lg bg-slate-700 hover:bg-slate-600
                           disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronRight className="w-4 h-4 text-slate-300" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ── Modale inspector ─────────────────────────────────────────────── */}
      {selectedIndex !== null && filtered[selectedIndex] && (
        <PacketDetailModal
          packet={filtered[selectedIndex]}
          allPackets={filtered}
          currentIndex={selectedIndex}
          onNavigate={handleNavigate}
          onClose={() => setSelectedIndex(null)}
        />
      )}
    </>
  )
}
