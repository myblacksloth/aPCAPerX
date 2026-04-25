/**
 * Componente per la timeline del traffico di rete.
 *
 * Visualizza l'andamento del numero di pacchetti nel tempo tramite
 * un'area chart (AreaChart) di Recharts. L'asse X mostra l'orario
 * di cattura; l'asse Y mostra il numero di pacchetti per bucket temporale.
 *
 * La granularità del bucket dipende dalla durata totale della cattura
 * (calcolata dal backend) e può variare da 1 secondo a 10 minuti.
 */
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer,
} from 'recharts'
import type { AnalysisResult } from '../types/analysis'
import { formatCount } from '../utils/format'

interface TimelineChartProps {
  result: AnalysisResult
}

// Tooltip personalizzato per il grafico temporale
function TimelineTooltip({ active, payload, label }: {
  active?: boolean
  payload?: Array<{ value: number; payload: { bytes: number } }>
  label?: string
}) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-slate-700 border border-slate-600 rounded-lg p-3 text-sm shadow-xl">
      <p className="text-slate-400 text-xs mb-1">⏱ {label}</p>
      <p className="text-white font-semibold">
        {payload[0].value.toLocaleString('it-IT')} pacchetti
      </p>
    </div>
  )
}

export default function TimelineChart({ result }: TimelineChartProps) {
  const { timeline } = result

  // Calcola il picco massimo per mostrarlo come annotazione
  const maxPackets = Math.max(...timeline.map(t => t.packets), 0)
  const totalPoints = timeline.length

  return (
    <div className="card">
      {/* ── Header ──────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-base font-semibold text-slate-200">
          Timeline del traffico
        </h2>
        <div className="flex gap-4 text-xs text-slate-500">
          <span>{totalPoints} punti</span>
          <span>Picco: <strong className="text-brand-300">{formatCount(maxPackets)}</strong> pkt</span>
        </div>
      </div>

      {timeline.length > 1 ? (
        /* ── Area chart ─────────────────────────────────────────────── */
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={timeline} margin={{ left: 0, right: 10, top: 5, bottom: 0 }}>
            {/* Gradiente di riempimento sotto la curva */}
            <defs>
              <linearGradient id="trafficGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor="#6366f1" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#6366f1" stopOpacity={0.02} />
              </linearGradient>
            </defs>

            {/* Griglia di sfondo sottile */}
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />

            {/* Asse X: orario — se ci sono molti punti, mostra solo ogni N-esimo */}
            <XAxis
              dataKey="timestamp"
              tick={{ fill: '#64748b', fontSize: 10 }}
              axisLine={false}
              tickLine={false}
              interval={Math.max(0, Math.floor(totalPoints / 8) - 1)}
            />

            {/* Asse Y: numero pacchetti */}
            <YAxis
              tick={{ fill: '#64748b', fontSize: 10 }}
              axisLine={false}
              tickLine={false}
              tickFormatter={(v) => formatCount(v)}
              width={45}
            />

            <Tooltip content={<TimelineTooltip />} />

            {/* Area con gradiente e linea superiore */}
            <Area
              type="monotone"
              dataKey="packets"
              stroke="#6366f1"
              strokeWidth={2}
              fill="url(#trafficGradient)"
              dot={false}               /* nessun punto sui dati → grafico più pulito */
              activeDot={{ r: 4, fill: '#818cf8', strokeWidth: 0 }}
            />
          </AreaChart>
        </ResponsiveContainer>
      ) : (
        /* Messaggio per catture troppo brevi (un solo bucket) */
        <p className="text-slate-500 text-sm text-center py-8">
          Dati insufficienti per la timeline (cattura troppo breve)
        </p>
      )}
    </div>
  )
}
