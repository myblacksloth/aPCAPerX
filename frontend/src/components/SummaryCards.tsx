/**
 * Componente per le card di riepilogo nella parte alta del dashboard.
 *
 * Mostra 6 metriche chiave in una griglia orizzontale:
 * pacchetti totali, byte totali, durata, media pacchetti/secondo,
 * dimensione media e numero di IP unici.
 */
import { Package, HardDrive, Clock, Zap, Ruler, Globe } from 'lucide-react'
import type { AnalysisResult } from '../types/analysis'
import { formatBytes, formatDuration, formatCount } from '../utils/format'

interface SummaryCardsProps {
  result: AnalysisResult
}

export default function SummaryCards({ result }: SummaryCardsProps) {
  const { summary } = result

  // Calcola il numero di IP unici combinando sorgenti e destinazioni
  const uniqueIPs = new Set([
    ...result.top_src_ips.map(e => e.ip),
    ...result.top_dst_ips.map(e => e.ip),
  ]).size

  // Definizione delle 6 card: icona, etichetta, valore formattato, sottotesto
  const cards = [
    {
      icon: Package,
      label: 'Pacchetti totali',
      value: formatCount(summary.total_packets),
      sub: `${summary.total_packets.toLocaleString('it-IT')} pacchetti`,
      color: 'text-brand-400',
      bg: 'bg-brand-500/10',
    },
    {
      icon: HardDrive,
      label: 'Volume totale',
      value: formatBytes(summary.total_bytes),
      sub: `${summary.total_bytes.toLocaleString('it-IT')} byte`,
      color: 'text-green-400',
      bg: 'bg-green-500/10',
    },
    {
      icon: Clock,
      label: 'Durata cattura',
      value: formatDuration(summary.duration_seconds),
      sub: summary.capture_start
        ? new Date(summary.capture_start).toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'medium' })
        : '—',
      color: 'text-yellow-400',
      bg: 'bg-yellow-500/10',
    },
    {
      icon: Zap,
      label: 'Pacchetti/secondo',
      value: summary.packets_per_second >= 1
        ? formatCount(Math.round(summary.packets_per_second))
        : summary.packets_per_second.toFixed(2),
      sub: 'tasso medio',
      color: 'text-orange-400',
      bg: 'bg-orange-500/10',
    },
    {
      icon: Ruler,
      label: 'Dim. media pacchetto',
      value: `${summary.avg_packet_size.toFixed(0)} B`,
      sub: formatBytes(summary.avg_packet_size),
      color: 'text-cyan-400',
      bg: 'bg-cyan-500/10',
    },
    {
      icon: Globe,
      label: 'IP unici (top 20)',
      value: formatCount(uniqueIPs),
      sub: `${uniqueIPs} indirizzi distinti`,
      color: 'text-pink-400',
      bg: 'bg-pink-500/10',
    },
  ]

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
      {cards.map(({ icon: Icon, label, value, sub, color, bg }) => (
        <div key={label} className="card flex flex-col gap-2">
          {/* Icona con sfondo colorato */}
          <div className={`w-8 h-8 ${bg} rounded-lg flex items-center justify-center`}>
            <Icon className={`w-4 h-4 ${color}`} />
          </div>
          {/* Valore principale in evidenza */}
          <div className={`text-xl font-bold ${color}`}>{value}</div>
          {/* Etichetta e sottotesto */}
          <div>
            <div className="text-xs font-medium text-slate-300">{label}</div>
            <div className="text-xs text-slate-500 truncate" title={sub}>{sub}</div>
          </div>
        </div>
      ))}
    </div>
  )
}
