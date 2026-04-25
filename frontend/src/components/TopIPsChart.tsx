/**
 * Componente per la visualizzazione degli indirizzi IP più attivi.
 *
 * Mostra due tab separati:
 *   - "Sorgenti" → IP che hanno inviato il maggior numero di pacchetti
 *   - "Destinazioni" → IP che hanno ricevuto il maggior numero di pacchetti
 *
 * Per ogni tab viene renderizzato un grafico a barre orizzontali (Recharts)
 * che permette di confrontare visivamente i volumi di traffico.
 */
import { useState } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Cell,
} from 'recharts'
import type { AnalysisResult } from '../types/analysis'
import { formatBytes, formatCount, CHART_COLORS } from '../utils/format'

interface TopIPsChartProps {
  result: AnalysisResult
}

// Tooltip personalizzato per le barre IP
function IPTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ value: number; payload: { bytes: number } }>; label?: string }) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-slate-700 border border-slate-600 rounded-lg p-3 text-sm shadow-xl">
      <p className="font-mono text-white mb-1 text-xs">{label}</p>
      <p className="text-slate-300">{payload[0].value.toLocaleString('it-IT')} pacchetti</p>
      <p className="text-slate-400">{formatBytes(payload[0].payload.bytes)}</p>
    </div>
  )
}

// Tick dell'asse Y personalizzato: mostra l'IP in font monospace
function IPTick({ x, y, payload }: { x?: number; y?: number; payload?: { value: string } }) {
  if (!x || !y || !payload) return null
  return (
    <text
      x={x}
      y={y}
      dy={4}
      textAnchor="end"
      className="fill-slate-400"
      style={{ fontSize: 10, fontFamily: 'monospace' }}
    >
      {/* Tronca gli IP molto lunghi (IPv6) */}
      {payload.value.length > 18 ? payload.value.slice(0, 16) + '…' : payload.value}
    </text>
  )
}

export default function TopIPsChart({ result }: TopIPsChartProps) {
  // Stato della tab attiva: 0 = sorgenti, 1 = destinazioni
  const [tab, setTab] = useState<0 | 1>(0)

  const tabs = [
    { label: 'IP Sorgenti',     data: result.top_src_ips.slice(0, 10) },
    { label: 'IP Destinazione', data: result.top_dst_ips.slice(0, 10) },
  ]

  // I dati correnti della tab selezionata
  const currentData = tabs[tab].data

  return (
    <div className="card">
      {/* ── Header con tab selector ──────────────────────────────────── */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-base font-semibold text-slate-200">Top IP</h2>
        <div className="flex bg-slate-700 rounded-lg p-0.5 gap-0.5">
          {tabs.map((t, i) => (
            <button
              key={t.label}
              onClick={() => setTab(i as 0 | 1)}
              className={[
                'px-3 py-1 text-xs rounded-md transition-colors',
                tab === i
                  ? 'bg-brand-500 text-white font-medium'
                  : 'text-slate-400 hover:text-slate-200',
              ].join(' ')}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* ── Grafico a barre orizzontali ───────────────────────────────── */}
      {currentData.length > 0 ? (
        <ResponsiveContainer width="100%" height={currentData.length * 32 + 20}>
          <BarChart
            data={currentData}
            layout="vertical"       /* barre orizzontali per leggere gli IP */
            margin={{ left: 10, right: 40, top: 0, bottom: 0 }}
          >
            {/* Asse Y: indirizzi IP (il valore categorico) */}
            <YAxis
              type="category"
              dataKey="ip"
              width={120}
              tick={<IPTick />}
              axisLine={false}
              tickLine={false}
            />
            {/* Asse X: numero di pacchetti (il valore numerico) */}
            <XAxis
              type="number"
              tick={{ fill: '#64748b', fontSize: 10 }}
              axisLine={false}
              tickLine={false}
              tickFormatter={(v) => formatCount(v)}
            />
            <Tooltip content={<IPTooltip />} cursor={{ fill: 'rgba(99,102,241,0.1)' }} />
            <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={20}>
              {/* Assegna un colore diverso a ogni barra */}
              {currentData.map((_, i) => (
                <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      ) : (
        <p className="text-slate-500 text-sm text-center py-8">
          Nessun indirizzo IP trovato in questa categoria
        </p>
      )}
    </div>
  )
}
