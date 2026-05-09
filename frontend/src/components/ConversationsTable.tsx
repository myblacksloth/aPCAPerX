/**
 * Componente per la tabella delle conversazioni di rete.
 *
 * Una "conversazione" rappresenta tutti i packets scambiati tra
 * due IP addresses (in entrambe le direzioni). La tabella shows
 * le 20 conversazioni most attive ordinate per volume in byte.
 *
 * Features:
 *   - Ordinamento per colonna (click sull'intestazione)
 *   - Badge colorati per i protocolli
 *   - Barra visiva per il volume di data
 */
import { useState } from 'react'
import { ArrowUpDown } from 'lucide-react'
import type { Conversation } from '../types/analysis'
import { formatBytes, formatCount, protocolColor } from '../utils/format'

interface ConversationsTableProps {
  conversations: Conversation[]
}

// Colonne su cui is possibile ordinare la tabella
type SortKey = 'packets' | 'bytes'

export default function ConversationsTable({ conversations }: ConversationsTableProps) {
  // Colonna di ordinamento corrente e direzione (desc per default)
  const [sortKey, setSortKey] = useState<SortKey>('bytes')
  const [sortAsc, setSortAsc] = useState(false)

  /** Cambia il criterio di ordinamento o inverte la direzione se already selezionato */
  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortAsc(prev => !prev)
    } else {
      setSortKey(key)
      setSortAsc(false)
    }
  }

  // Crea una copia ordinata per non mutare il prop originale
  const sorted = [...conversations].sort((a, b) => {
    const diff = a[sortKey] - b[sortKey]
    return sortAsc ? diff : -diff
  })

  // Valore massimo in byte: usato per la barra di proporzione visiva
  const maxBytes = sorted[0]?.bytes ?? 1

  return (
    <div className="card">
      <h2 className="text-base font-semibold text-slate-200 mb-4">
        Conversazioni ({conversations.length})
      </h2>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-slate-500 border-b border-slate-700">
              <th className="pb-2 font-medium">IP Sorgente</th>
              <th className="pb-2 font-medium">IP Destinazione</th>
              <th className="pb-2 font-medium hidden md:table-cell">Protocols</th>

              {/* Intestazioni ordinabili */}
              {(['packets', 'bytes'] as SortKey[]).map(key => (
                <th key={key} className="pb-2 font-medium text-right">
                  <button
                    onClick={() => toggleSort(key)}
                    className="inline-flex items-center gap-1 hover:text-slate-300 transition-colors"
                  >
                    {key === 'packets' ? 'Packets' : 'Volume'}
                    <ArrowUpDown className="w-3 h-3" />
                  </button>
                </th>
              ))}

              <th className="pb-2 font-medium hidden lg:table-cell">Proporzione</th>
            </tr>
          </thead>

          <tbody>
            {sorted.map((conv, i) => (
              <tr key={i} className="border-b border-slate-700/50 hover:bg-slate-700/20">
                {/* Source IP (primo IP della coppia) */}
                <td className="py-2 font-mono text-xs text-slate-300">
                  {conv.src_ip}
                </td>

                {/* IP destinatario */}
                <td className="py-2 font-mono text-xs text-slate-300">
                  {conv.dst_ip}
                </td>

                {/* Badge for protocols observed in the conversation */}
                <td className="py-2 hidden md:table-cell">
                  <div className="flex flex-wrap gap-1">
                    {conv.protocols.map(p => (
                      <span
                        key={p}
                        className="protocol-badge"
                        style={{
                          backgroundColor: protocolColor(p) + '22',
                          color: protocolColor(p),
                        }}
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                </td>

                {/* Numero di packets */}
                <td className="py-2 text-right text-slate-300">
                  {formatCount(conv.packets)}
                </td>

                {/* Volume in byte */}
                <td className="py-2 text-right text-slate-300">
                  {formatBytes(conv.bytes)}
                </td>

                {/* Barra di proporzione visiva rispetto alla conversazione most grande */}
                <td className="py-2 hidden lg:table-cell pl-4">
                  <div className="w-full bg-slate-700 rounded-full h-1.5">
                    <div
                      className="h-1.5 rounded-full bg-brand-500"
                      style={{ width: `${(conv.bytes / maxBytes) * 100}%` }}
                    />
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {conversations.length === 0 && (
          <p className="text-slate-500 text-sm text-center py-8">
            No conversation found
          </p>
        )}
      </div>
    </div>
  )
}
