/**
 * Componente per la lista dettagliata dei pacchetti.
 *
 * Mostra i primi 1000 pacchetti del file PCAP con:
 *   - Numero progressivo, orario, indirizzi IP sorgente/destinazione
 *   - Protocollo con badge colorato
 *   - Lunghezza in byte
 *   - Campo Info (stile Wireshark)
 *
 * Funzionalità interattive:
 *   - Ricerca testuale: filtra per IP, protocollo o contenuto del campo Info
 *   - Paginazione: 50 pacchetti per pagina per non rallentare il browser
 */
import { useState, useMemo } from 'react'
import { Search, ChevronLeft, ChevronRight } from 'lucide-react'
import type { PacketEntry } from '../types/analysis'
import { protocolColor } from '../utils/format'

interface PacketTableProps {
  packets: PacketEntry[]
}

// Numero di pacchetti mostrati per pagina
const PAGE_SIZE = 50

export default function PacketTable({ packets }: PacketTableProps) {
  // Testo inserito nella barra di ricerca
  const [search, setSearch] = useState('')

  // Pagina corrente (parte da 0)
  const [page, setPage] = useState(0)

  /**
   * Filtra i pacchetti in base al testo di ricerca.
   * La ricerca è case-insensitive e controlla IP, protocollo e info.
   * Usato useMemo per non ricalcolare ad ogni render se l'input non cambia.
   */
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

  // Resetta alla prima pagina quando l'utente modifica la ricerca
  const handleSearch = (q: string) => {
    setSearch(q)
    setPage(0)
  }

  // Calcola i dati della pagina corrente
  const totalPages = Math.ceil(filtered.length / PAGE_SIZE)
  const pageData   = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  return (
    <div className="card">
      {/* ── Header con titolo e barra di ricerca ─────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <h2 className="text-base font-semibold text-slate-200">
          Lista pacchetti{' '}
          <span className="text-slate-500 text-sm font-normal">
            (primi {packets.length.toLocaleString('it-IT')})
          </span>
        </h2>

        {/* Campo di ricerca */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="Filtra per IP, protocollo, info…"
            value={search}
            onChange={(e) => handleSearch(e.target.value)}
            className="pl-9 pr-4 py-1.5 bg-slate-700 border border-slate-600 rounded-lg
                       text-sm text-slate-200 placeholder-slate-500 w-64
                       focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500/30"
          />
        </div>
      </div>

      {/* ── Tabella pacchetti ─────────────────────────────────────────── */}
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
            </tr>
          </thead>
          <tbody>
            {pageData.map((pkt) => (
              <tr
                key={pkt.number}
                className="border-b border-slate-700/30 hover:bg-slate-700/20 transition-colors"
              >
                {/* Numero progressivo */}
                <td className="py-1 pr-3 text-slate-600 text-right">
                  {pkt.number}
                </td>

                {/* Timestamp HH:MM:SS.mmm */}
                <td className="py-1 pr-3 text-slate-400">
                  {pkt.timestamp}
                </td>

                {/* IP sorgente : porta */}
                <td className="py-1 pr-3 text-slate-300">
                  {pkt.src_ip
                    ? `${pkt.src_ip}${pkt.src_port ? ':' + pkt.src_port : ''}`
                    : <span className="text-slate-600">—</span>}
                </td>

                {/* IP destinazione : porta */}
                <td className="py-1 pr-3 text-slate-300">
                  {pkt.dst_ip
                    ? `${pkt.dst_ip}${pkt.dst_port ? ':' + pkt.dst_port : ''}`
                    : <span className="text-slate-600">—</span>}
                </td>

                {/* Badge protocollo con colore specifico */}
                <td className="py-1 pr-3">
                  <span
                    className="protocol-badge"
                    style={{
                      backgroundColor: protocolColor(pkt.protocol) + '22',
                      color: protocolColor(pkt.protocol),
                    }}
                  >
                    {pkt.protocol}
                  </span>
                </td>

                {/* Lunghezza in byte */}
                <td className="py-1 pr-3 text-right text-slate-400">
                  {pkt.length}
                </td>

                {/* Campo Info: tronca stringhe molto lunghe */}
                <td className="py-1 text-slate-400 max-w-xs truncate" title={pkt.info}>
                  {pkt.info}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {/* Messaggio quando la ricerca non produce risultati */}
        {filtered.length === 0 && (
          <p className="text-slate-500 text-sm text-center py-8">
            Nessun pacchetto corrisponde alla ricerca "{search}"
          </p>
        )}
      </div>

      {/* ── Barra di paginazione ────────────────────────────────────────── */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-4 pt-3 border-t border-slate-700">
          {/* Contatore risultati */}
          <span className="text-xs text-slate-500">
            {filtered.length.toLocaleString('it-IT')} pacchetti ·{' '}
            pagina {page + 1} di {totalPages}
          </span>

          {/* Bottoni di navigazione */}
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
  )
}
